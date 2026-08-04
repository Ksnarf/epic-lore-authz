//! THE compat test. Per the design plan, this is the single highest-value
//! test in the project: it is the only thing that would catch a missing
//! `idp` claim (or a broken JWKS `alg`) in CI before a customer does. See
//! docs/protocol-notes.md and tasks.md Phase 0.
//!
//! Strategy: vendor lore-server's own claim structs VERBATIM (byte-for-byte
//! copy of the type definitions, MIT licensed, safe to vendor for test
//! purposes -- see the `lore_server_verbatim` module below) and jsonwebtoken
//! 9.3.1 (the exact version lore-server pins), then:
//!
//! 1. Mint a token with `lore_authz_server::minting::mint_authz_token` and
//!    prove it deserializes into the VENDORED `AuthorizationToken` with
//!    `resources: Some(..)` populated -- not the `None`-dropping fallback.
//! 2. Prove the missing-`idp` failure mode described in
//!    docs/protocol-notes.md #2 actually exists on the wire: a hand-built
//!    token missing `idp` fails the `AuthorizationToken` decode and
//!    silently succeeds as the fallback `JWTUserInfo` shape (which has no
//!    `resources` field to even be `None` on -- the information is just
//!    gone). Our own `mint_authz_token` cannot produce this: its
//!    `AuthzTokenInput::idp` parameter is a mandatory `String`, not an
//!    `Option`, so there is no call that both compiles and omits it.
//! 3. Prove our AuthN token deserializes cleanly into the vendored
//!    `JWTUserInfo` fallback shape too (sanity: the "identity only, no
//!    resources" token variant).
//! 4. Prove our served JWKS document parses into the exact
//!    `jsonwebtoken::jwk::JwkSet` type lore-server's `JwkServiceImpl`
//!    deserializes a JWKS response into, and that every key has both `kid`
//!    and `alg` -- the trap documented in
//!    crates/lore-authz-server/src/signing.rs and docs/protocol-notes.md #4.

use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::decode;
use jsonwebtoken::jwk::JwkSet;
use lore_authz_server::minting::AuthnTokenInput;
use lore_authz_server::minting::AuthzTokenInput;
use lore_authz_server::minting::mint_authn_token;
use lore_authz_server::minting::mint_authz_token;
use lore_authz_server::signing::SigningKeyStore;
use lore_server_verbatim::AuthorizationToken;
use lore_server_verbatim::JWTUserInfo;

/// Verbatim copy of the claim structs `lore-server` actually deserializes
/// tokens as, from `EpicGames/lore` at the pinned commit
/// `f205899adf24b13b2d28e5c08d9256ac99c69f0c`
/// (see `proto/vendor/UPSTREAM.md`), upstream path
/// `lore-server/src/auth/jwt.rs`, lines 21-79 at that commit. Copied
/// byte-for-byte (only doc comments trimmed); MIT licensed, safe to vendor
/// for test purposes. Do NOT "clean up" or "simplify" these -- their entire
/// value is being an independent, un-drifted copy of what upstream actually
/// does. If lore-server's real struct ever changes, this module is meant to
/// go stale and this test is meant to start failing, not to be edited to
/// match our own `AuthzClaims`/`AuthnClaims`.
mod lore_server_verbatim {
    // SPDX-FileCopyrightText: 2026 Epic Games, Inc.
    // SPDX-License-Identifier: MIT
    use serde::Deserialize;
    use serde::Serialize;
    use serde_with::OneOrMany;
    use serde_with::formats::PreferMany;
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
    pub struct JWTUserInfo {
        #[serde(rename = "sub")]
        pub user_id: String,
        #[serde(rename = "iss")]
        pub issuer: String,
        #[serde(rename = "iat")]
        pub issued_at: u64,
        #[serde_as(as = "OneOrMany<_, PreferMany>")]
        #[serde(rename = "aud")]
        pub audience: Vec<String>,
        pub env: String,
        pub name: String,
        pub preferred_username: String,
        pub is_service_account: Option<bool>,
        #[serde(rename = "exp")]
        pub expires: u64,
    }

    /// From Lore protos, but cannot derive deserialize on external type
    #[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
    pub struct ResourcePermission {
        pub resource_id: String,
        pub permission: Vec<String>,
    }

    #[serde_as]
    #[derive(Debug, Deserialize, Clone, Serialize, PartialEq, Default)]
    pub struct AuthorizationToken {
        #[serde(rename = "sub")]
        pub user_id: String,
        #[serde(rename = "iss")]
        pub issuer: String,
        #[serde(rename = "iat")]
        pub issued_at: u64,
        #[serde(rename = "exp")]
        pub expires: u64,
        #[serde_as(as = "OneOrMany<_, PreferMany>")]
        #[serde(rename = "aud")]
        pub audience: Vec<String>,
        pub env: String,
        pub name: String,
        pub preferred_username: String,
        pub resources: Option<Vec<ResourcePermission>>,
        pub groups: Option<Vec<String>>,
        pub is_service_account: Option<bool>,
        pub idp: String,
    }
}

const TEST_ISSUER: &str = "https://authz.example.com";
const TEST_AUDIENCE: &str = "lore.example.com";

fn test_store() -> SigningKeyStore {
    // Deliberately not a real file -- every run of this test gets a fresh
    // ephemeral in-memory dev key (see crates/lore-authz-server/src/
    // signing.rs). Nothing here ever touches disk or a real key source.
    SigningKeyStore::load("file:///epic-lore-authz-test-fixture-does-not-exist.der")
        .expect("ephemeral key generation must always succeed")
}

/// Builds the SAME `Validation` shape lore-server's `JwtVerifier::
/// verify_token_internal` builds (see lore-server/src/auth/jwt.rs at the
/// pinned commit): `Validation::new(alg)`, `set_issuer`, `set_audience`,
/// `validate_exp = true`.
fn lore_server_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[TEST_ISSUER]);
    validation.set_audience(&[TEST_AUDIENCE]);
    validation.validate_exp = true;
    validation
}

#[test]
fn minted_authz_token_deserializes_into_lores_authorizationtoken_with_resources_populated() {
    let store = test_store();
    let signed = mint_authz_token(
        store.active(),
        TEST_ISSUER,
        &[TEST_AUDIENCE.to_string()],
        "dev",
        3600,
        &AuthzTokenInput {
            user_id: "user-1".to_string(),
            name: "Test User".to_string(),
            preferred_username: "testuser".to_string(),
            is_service_account: false,
            idp: "dev-test-idp".to_string(),
            groups: Some(vec!["engineering".to_string()]),
            resources: vec![lore_authz_core::claims::ResourcePermission {
                resource_id: "urc-0194b726b34e72b0b45550b88a967076".to_string(),
                permission: vec!["read".to_string(), "write".to_string()],
            }],
        },
    )
    .expect("minting must succeed");

    let decoding_key = DecodingKey::from_jwk(&store.active().public_jwk)
        .expect("our own public JWK must decode back into a DecodingKey");
    let validation = lore_server_validation();

    let decoded = decode::<AuthorizationToken>(&signed.token, &decoding_key, &validation).expect(
        "a correctly-minted AuthZ token MUST deserialize as lore-server's AuthorizationToken",
    );

    assert_eq!(
        decoded.claims.idp, "dev-test-idp",
        "idp must survive intact"
    );
    let resources = decoded.claims.resources.expect(
        "resources must be Some, not silently dropped to None -- see docs/protocol-notes.md #2",
    );
    assert_eq!(resources.len(), 1);
    assert_eq!(
        resources[0].resource_id,
        "urc-0194b726b34e72b0b45550b88a967076"
    );
    assert_eq!(resources[0].permission, vec!["read", "write"]);
}

#[test]
fn minted_authn_token_deserializes_into_lores_jwtuserinfo_fallback_shape() {
    let store = test_store();
    let signed = mint_authn_token(
        store.active(),
        TEST_ISSUER,
        &[TEST_AUDIENCE.to_string()],
        "dev",
        36000,
        &AuthnTokenInput {
            user_id: "user-1".to_string(),
            name: "Test User".to_string(),
            preferred_username: "testuser".to_string(),
            is_service_account: false,
        },
    )
    .expect("minting must succeed");

    let decoding_key = DecodingKey::from_jwk(&store.active().public_jwk).unwrap();
    let decoded = decode::<JWTUserInfo>(&signed.token, &decoding_key, &lore_server_validation())
        .expect("AuthN token must deserialize as lore-server's JWTUserInfo fallback shape");
    assert_eq!(decoded.claims.user_id, "user-1");
}

/// THE negative case. Proves the missing-`idp` failure mode described in
/// docs/protocol-notes.md #2 is real, on the wire, using lore-server's own
/// vendored types -- not just asserted in a comment.
#[test]
fn token_missing_idp_fails_authorizationtoken_decode_but_silently_succeeds_as_jwtuserinfo() {
    let store = test_store();
    let signing_key = store.active();

    let now = jsonwebtoken::get_current_timestamp();
    // Hand-built claims JSON: every field AuthorizationToken requires
    // EXCEPT `idp`, which is intentionally omitted. This bypasses our own
    // `AuthzClaims`/minting path on purpose -- the whole point is to prove
    // what happens to a token that omits `idp`, which our real minting
    // function (AuthzTokenInput::idp is a mandatory String, not an Option)
    // has no way to construct.
    let claims_missing_idp = serde_json::json!({
        "sub": "user-1",
        "iss": TEST_ISSUER,
        "iat": now,
        "exp": now + 3600,
        "aud": [TEST_AUDIENCE],
        "env": "dev",
        "name": "Test User",
        "preferred_username": "testuser",
        "resources": [{"resource_id": "urc-abc", "permission": ["read"]}],
        "is_service_account": false,
        // "idp" deliberately absent.
    });

    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.kid = Some(signing_key.kid.clone());
    let token = jsonwebtoken::encode(&header, &claims_missing_idp, &signing_key.encoding_key)
        .expect("encoding a hand-built claim set must still succeed");

    let decoding_key = DecodingKey::from_jwk(&signing_key.public_jwk).unwrap();
    let validation = lore_server_validation();

    let as_authorization_token = decode::<AuthorizationToken>(&token, &decoding_key, &validation);
    assert!(
        as_authorization_token.is_err(),
        "a token missing `idp` must FAIL to decode as AuthorizationToken (idp is non-Option)"
    );

    let as_fallback = decode::<JWTUserInfo>(&token, &decoding_key, &validation)
        .expect(
            "lore-server's actual behavior (see verify_token_internal in lore-server/src/auth/jwt.rs): \
             when the AuthorizationToken decode fails, it falls back to JWTUserInfo, which has no \
             `idp` field to fail on -- this MUST still succeed, silently losing the `resources` claim",
        );
    assert_eq!(as_fallback.claims.user_id, "user-1");
    // JWTUserInfo has no `resources` field at all -- there is nothing to
    // assert is None; the type itself cannot express the claim we lost.
    // This is the "looks exactly like a permissions bug" trap from
    // docs/protocol-notes.md #2, reproduced end to end.
}

#[test]
fn served_jwks_parses_as_lore_servers_jwkset_type_with_kid_and_alg_on_every_key() {
    let store = test_store();
    let jwks_json = serde_json::to_string(&store.jwks()).expect("JWKS must serialize");

    // This is the exact type lore-server/src/auth/jwk.rs's `JwkServiceImpl::
    // fetch_new_keys` deserializes a JWKS HTTP response into.
    let parsed: JwkSet = serde_json::from_str(&jwks_json)
        .expect("our served JWKS document must parse as jsonwebtoken::jwk::JwkSet");

    assert!(!parsed.keys.is_empty());
    for key in &parsed.keys {
        // lore-server/src/auth/jwk.rs: `jwk.common.key_id.as_ref().ok_or(..)?`
        // and `jwk.common.key_algorithm.ok_or(..)?` -- missing either on
        // even ONE key fails loading the ENTIRE key set, not just this key.
        assert!(key.common.key_id.is_some(), "every JWKS key needs a kid");
        assert!(
            key.common.key_algorithm.is_some(),
            "every JWKS key needs an alg (lore-server hard-fails the whole \
             key set otherwise, per lore-server/src/auth/jwk.rs)"
        );
    }
}
