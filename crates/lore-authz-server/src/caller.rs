//! Resolves "who is calling" for `LookupUserPermissions` /
//! `CheckUserPermission` / `ExchangeUserTokenForMultiresourceToken` from an
//! incoming bearer token -- PHASE 1a/1b (see tasks.md). `caller_principal_id`
//! decodes ONLY the `sub` claim (the `Principal.id`, per
//! `lore_authz_core::model::Principal`'s doc comment) from whatever JWT this
//! service itself signed, using whichever of the two claim shapes
//! (`AuthzClaims` or `AuthnClaims`) happens to be present -- both carry `sub`
//! under the same rename, so on its own it cannot tell which shape it was
//! given (see `is_authz_shaped_token` below for the one caller that needs
//! to). This module has nothing to do with decoding lore-server's OWN claim
//! shapes; that is a completely separate concern covered by
//! `tests/lore_compat.rs` (see docs/protocol-notes.md).

use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::decode;
use serde::Deserialize;
use tonic::Status;
use uuid::Uuid;

use crate::secret::strip_bearer;
use crate::signing::SigningKeyStore;

#[derive(Deserialize)]
struct SubjectClaim {
    #[serde(rename = "sub")]
    subject: String,
}

/// Decodes the caller's `Principal.id` (the `sub` claim) out of a bearer
/// token this service itself signed. Fails closed with
/// `Status::unauthenticated` on anything: missing/empty token, bad
/// signature, expired, wrong issuer/audience, or a `sub` that does not parse
/// as a UUID. `signing_keys` currently holds exactly one active key (Phase
/// 0/1a, no rotation yet -- see docs/open-questions.md Q14), so this always
/// verifies against that one key regardless of the token's own `kid` header;
/// that assumption stops holding once key rotation lands.
pub fn caller_principal_id(
    raw_authorization: Option<&str>,
    signing_keys: &SigningKeyStore,
    issuer: &str,
    audience: &[String],
) -> Result<Uuid, Status> {
    let token = raw_authorization
        .and_then(strip_bearer)
        .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;

    // Deliberately coarse, matching crate::oidc's error design: the specific
    // reason (a jsonwebtoken error kind -- InvalidSignature, InvalidIssuer,
    // ExpiredSignature, ...) is logged, never returned. Returning it would
    // let a caller distinguish expired vs bad-signature vs wrong-audience
    // for free, which is a reconnaissance aid, not a debugging convenience
    // owed to an untrusted caller.
    let decoding_key = DecodingKey::from_jwk(&signing_keys.active().public_jwk).map_err(|err| {
        tracing::error!(error = %err, "decoding this service's own public JWK failed");
        Status::internal("internal error")
    })?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(audience);

    let claims = decode::<SubjectClaim>(token, &decoding_key, &validation)
        .map_err(|err| {
            tracing::debug!(error = %err, "bearer token failed signature/claim validation");
            Status::unauthenticated("invalid bearer token")
        })?
        .claims;

    Uuid::parse_str(&claims.subject)
        .map_err(|_| Status::unauthenticated("bearer token subject is not a valid principal id"))
}

/// Claims-shape probe for `ExchangeUserTokenForMultiresourceToken`'s own
/// use (see `grpc.rs` and docs/protocol-notes.md #8a): `idp` is present on
/// `lore_authz_core::claims::AuthzClaims` and absent from `AuthnClaims`, so
/// its presence tells the two shapes apart without needing a second decode
/// target per shape.
///
/// Returns `false` for anything that is not a validly-signed token this
/// service issued -- missing, garbage, expired, wrong issuer/audience, all
/// of it. That is deliberate: this function makes no trust decision of its
/// own, it only classifies a token that has ALREADY been (or is about to
/// be) verified by `caller_principal_id`. A caller that gets `false` here
/// still has to pass that real check before anything is granted.
pub fn is_authz_shaped_token(
    raw_authorization: Option<&str>,
    signing_keys: &SigningKeyStore,
    issuer: &str,
    audience: &[String],
) -> bool {
    #[derive(Deserialize)]
    struct ShapeClaim {
        #[serde(default)]
        idp: Option<String>,
    }

    let Some(token) = raw_authorization.and_then(strip_bearer) else {
        return false;
    };
    let Ok(decoding_key) = DecodingKey::from_jwk(&signing_keys.active().public_jwk) else {
        return false;
    };
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(audience);

    decode::<ShapeClaim>(token, &decoding_key, &validation)
        .map(|data| data.claims.idp.is_some())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use lore_authz_core::claims::ResourcePermission;

    use super::*;
    use crate::minting::AuthnTokenInput;
    use crate::minting::AuthzTokenInput;
    use crate::minting::mint_authn_token;
    use crate::minting::mint_authz_token;

    const ISSUER: &str = "https://authz.example.com";
    const AUDIENCE: &str = "lore.example.com";

    fn store() -> SigningKeyStore {
        SigningKeyStore::load("file:///epic-lore-authz-caller-test-fixture-does-not-exist.der")
            .unwrap()
    }

    #[test]
    fn recovers_principal_id_from_a_bearer_token_we_signed() {
        let store = store();
        let principal_id = Uuid::new_v4();
        let signed = mint_authz_token(
            store.active(),
            ISSUER,
            &[AUDIENCE.to_string()],
            "dev",
            3600,
            &AuthzTokenInput {
                user_id: principal_id.to_string(),
                name: "Test User".to_string(),
                preferred_username: "testuser".to_string(),
                is_service_account: false,
                idp: "dev-test-idp".to_string(),
                groups: None,
                resources: vec![ResourcePermission {
                    resource_id: "urc-abc".to_string(),
                    permission: vec!["read".to_string()],
                }],
            },
        )
        .unwrap();

        let bearer = format!("Bearer {}", signed.token);
        let resolved =
            caller_principal_id(Some(&bearer), &store, ISSUER, &[AUDIENCE.to_string()]).unwrap();
        assert_eq!(resolved, principal_id);
    }

    #[test]
    fn missing_authorization_denies() {
        let store = store();
        let err = caller_principal_id(None, &store, ISSUER, &[AUDIENCE.to_string()])
            .expect_err("no token must deny");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn empty_authorization_denies_same_as_missing() {
        let store = store();
        let err = caller_principal_id(Some(""), &store, ISSUER, &[AUDIENCE.to_string()])
            .expect_err("empty string must be treated as absent, and deny");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn garbage_token_denies() {
        let store = store();
        let err = caller_principal_id(
            Some("Bearer not-a-real-jwt"),
            &store,
            ISSUER,
            &[AUDIENCE.to_string()],
        )
        .expect_err("an unparseable token must deny");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "invalid bearer token");
    }

    /// A well-formed, correctly-signed token that fails validation for a
    /// SPECIFIC reason (here: wrong audience) must still surface a single
    /// generic message. Without this, the caller-visible error would
    /// distinguish "wrong audience" from "expired" from "bad signature" --
    /// each is a different jsonwebtoken `ErrorKind`, and its `Display` is
    /// exactly what an attacker probing for a working token would want for
    /// free.
    #[test]
    fn a_token_that_fails_claim_validation_denies_with_the_same_generic_message() {
        let store = store();
        let signed = mint_authz_token(
            store.active(),
            ISSUER,
            &["some-other-audience-entirely".to_string()],
            "dev",
            3600,
            &AuthzTokenInput {
                user_id: Uuid::new_v4().to_string(),
                name: "Test User".to_string(),
                preferred_username: "testuser".to_string(),
                is_service_account: false,
                idp: "dev-test-idp".to_string(),
                groups: None,
                resources: vec![],
            },
        )
        .unwrap();

        let bearer = format!("Bearer {}", signed.token);
        let err = caller_principal_id(Some(&bearer), &store, ISSUER, &[AUDIENCE.to_string()])
            .expect_err("a token signed for a different audience must deny");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            err.message(),
            "invalid bearer token",
            "the message must not name the specific validation failure (e.g. jsonwebtoken's \
             InvalidAudience), or a caller could distinguish failure reasons for free"
        );
    }

    #[test]
    fn an_authz_token_is_detected_as_authz_shaped() {
        let store = store();
        let signed = mint_authz_token(
            store.active(),
            ISSUER,
            &[AUDIENCE.to_string()],
            "dev",
            3600,
            &AuthzTokenInput {
                user_id: Uuid::new_v4().to_string(),
                name: "Test User".to_string(),
                preferred_username: "testuser".to_string(),
                is_service_account: false,
                idp: "dev-test-idp".to_string(),
                groups: None,
                resources: vec![],
            },
        )
        .unwrap();
        let bearer = format!("Bearer {}", signed.token);
        assert!(is_authz_shaped_token(
            Some(&bearer),
            &store,
            ISSUER,
            &[AUDIENCE.to_string()]
        ));
    }

    #[test]
    fn an_authn_token_is_not_authz_shaped() {
        let store = store();
        let signed = mint_authn_token(
            store.active(),
            ISSUER,
            &[AUDIENCE.to_string()],
            "dev",
            3600,
            &AuthnTokenInput {
                user_id: Uuid::new_v4().to_string(),
                name: "Test User".to_string(),
                preferred_username: "testuser".to_string(),
                is_service_account: false,
            },
        )
        .unwrap();
        let bearer = format!("Bearer {}", signed.token);
        assert!(!is_authz_shaped_token(
            Some(&bearer),
            &store,
            ISSUER,
            &[AUDIENCE.to_string()]
        ));
    }

    #[test]
    fn missing_or_garbage_tokens_are_not_authz_shaped() {
        let store = store();
        assert!(!is_authz_shaped_token(
            None,
            &store,
            ISSUER,
            &[AUDIENCE.to_string()]
        ));
        assert!(!is_authz_shaped_token(
            Some("Bearer not-a-real-jwt"),
            &store,
            ISSUER,
            &[AUDIENCE.to_string()]
        ));
    }
}
