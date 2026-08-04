//! Mints AuthN ("user") tokens and AuthZ tokens matching lore-server's claim
//! contract. See `docs/protocol-notes.md` section 2 and
//! `crates/lore-authz-core/src/claims.rs` for the claim shapes themselves;
//! this module only turns plain inputs into signed, encoded JWTs.
//!
//! Neither function here is wired into the gRPC handlers yet -- that RPC
//! wiring (`ExchangeUserTokenForMultiresourceToken` etc., still `Status::
//! unimplemented` in `crates/lore-authz-server/src/grpc.rs`) is a separate,
//! still-open tasks.md item. This module is the minting mechanism those
//! handlers will call once policy/session storage exists (Phase 0/1).
//!
//! ## The `idp` gap this module intentionally does NOT paper over
//! `AuthzTokenInput::idp` is a mandatory field here, matching lore-server's
//! `AuthorizationToken.idp: String` (non-`Option`; see
//! `crates/lore-authz-core/src/claims.rs` and docs/protocol-notes.md #2).
//! But lore's own AuthN fallback shape, `JWTUserInfo` (`lore-server/src/
//! auth/jwt.rs`), has NO `idp` field at all -- and neither does our
//! `AuthnClaims`. That means a real `ExchangeUserTokenForMultiresourceToken`
//! implementation cannot recover `idp` by decoding the caller's AuthN token;
//! it must look `idp` up some other way (e.g. from the `Principal` row the
//! `sub` claim identifies, via `idp_connection_id` -- see
//! `crates/lore-authz-core/src/model.rs`). This is a real design constraint
//! for whoever wires the RPC, not a documentation gap in the notes; it is
//! called out here, in `docs/protocol-notes.md`, and in
//! `docs/open-questions.md` explicitly so it cannot be missed.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use jsonwebtoken::Algorithm;
use jsonwebtoken::Header;
use jsonwebtoken::encode;
use lore_authz_core::claims::AuthnClaims;
use lore_authz_core::claims::AuthzClaims;
use lore_authz_core::claims::ResourcePermission;
use lore_authz_core::claims::SignedToken;

use crate::signing::SigningKey;

/// Everything needed to mint an AuthN ("user") token for one principal.
/// Identity only -- see docs/protocol-notes.md section 1. Where these values
/// come from (OIDC id_token claims, SAML assertion, a JIT-provisioned
/// `Principal` row, or -- in this Phase 0 scaffold -- a hardcoded dev test
/// user) is out of scope for this module.
#[derive(Debug, Clone)]
pub struct AuthnTokenInput {
    pub user_id: String,
    pub name: String,
    pub preferred_username: String,
    pub is_service_account: bool,
}

/// Everything needed to mint an AuthZ token. See the module-level doc
/// comment above for why `idp` cannot be recovered from an `AuthnClaims`
/// alone and must be supplied by the caller from some other source of
/// truth.
#[derive(Debug, Clone)]
pub struct AuthzTokenInput {
    pub user_id: String,
    pub name: String,
    pub preferred_username: String,
    pub is_service_account: bool,
    pub idp: String,
    pub groups: Option<Vec<String>>,
    /// Sizing rule (design plan section C, see
    /// `crates/lore-authz-core/src/model.rs::TokenMinter` doc comment):
    /// callers must pass ONLY the resource_ids actually being granted for
    /// this token (plus a `urc-*` entry for wildcard bindings), never every
    /// repository a principal can see.
    pub resources: Vec<ResourcePermission>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the UNIX epoch")
        .as_secs()
}

fn header_for(signing_key: &SigningKey) -> Header {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(signing_key.kid.clone());
    header
}

/// Builds the `SignedToken` returned to callers. `expires_at` is
/// milliseconds since the UNIX epoch -- this is `epic_urc.UserToken.
/// expires_at` on the wire, NOT the JWT's own `exp` claim (which is always
/// whole seconds per the JWT spec and per `jsonwebtoken`'s own
/// `validate_exp`). See docs/open-questions.md Q1 (SETTLED) for the
/// evidence these are two different units of the "same-looking" expiry:
/// `lore-transport/src/auth/ucs_auth.rs` assigns `token.expires_at` straight
/// into a field literally named `expires_ms` with no `* 1000` scaling, and
/// `lore-transport/src/connection.rs`'s own tests use millisecond-shaped
/// literals (e.g. `1_700_000_000_000`) for it.
fn signed_token(token: String, exp_secs: u64) -> SignedToken {
    SignedToken {
        token,
        expires_at: i64::try_from(exp_secs)
            .unwrap_or(i64::MAX / 1000)
            .saturating_mul(1000),
    }
}

/// Mints an AuthN token. Carries no `resources` claim -- see
/// docs/protocol-notes.md section 1.
pub fn mint_authn_token(
    signing_key: &SigningKey,
    issuer: &str,
    audience: &[String],
    token_env: &str,
    ttl_secs: u64,
    input: &AuthnTokenInput,
) -> Result<SignedToken, jsonwebtoken::errors::Error> {
    let issued_at = now_secs();
    let expires_at = issued_at + ttl_secs;

    let claims = AuthnClaims {
        user_id: input.user_id.clone(),
        issuer: issuer.to_string(),
        issued_at,
        audience: audience.to_vec(),
        env: token_env.to_string(),
        name: input.name.clone(),
        preferred_username: input.preferred_username.clone(),
        is_service_account: Some(input.is_service_account),
        expires_at,
    };

    let token = encode(&header_for(signing_key), &claims, &signing_key.encoding_key)?;
    Ok(signed_token(token, expires_at))
}

/// Mints an AuthZ token. `input.idp` being a mandatory `String` (not
/// `Option`) here is what makes it structurally impossible to call this
/// function and produce a token missing the `idp` claim -- see the
/// module-level doc comment, and the compat test
/// (`crates/lore-authz-server/tests/lore_compat.rs`) that proves the wire
/// consequence of ever getting that wrong.
pub fn mint_authz_token(
    signing_key: &SigningKey,
    issuer: &str,
    audience: &[String],
    token_env: &str,
    ttl_secs: u64,
    input: &AuthzTokenInput,
) -> Result<SignedToken, jsonwebtoken::errors::Error> {
    let issued_at = now_secs();
    let expires_at = issued_at + ttl_secs;

    let claims = AuthzClaims {
        user_id: input.user_id.clone(),
        issuer: issuer.to_string(),
        issued_at,
        expires_at,
        audience: audience.to_vec(),
        env: token_env.to_string(),
        name: input.name.clone(),
        preferred_username: input.preferred_username.clone(),
        resources: Some(input.resources.clone()),
        groups: input.groups.clone(),
        is_service_account: Some(input.is_service_account),
        idp: input.idp.clone(),
    };

    let token = encode(&header_for(signing_key), &claims, &signing_key.encoding_key)?;
    Ok(signed_token(token, expires_at))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use jsonwebtoken::Algorithm;
    use jsonwebtoken::DecodingKey;
    use jsonwebtoken::Validation;
    use jsonwebtoken::decode;

    use super::*;
    use crate::signing::SigningKeyStore;

    fn store() -> SigningKeyStore {
        SigningKeyStore::load("file:///does/not/exist.der").unwrap()
    }

    #[test]
    fn authz_token_round_trips_with_resources_and_idp() {
        let store = store();
        let signed = mint_authz_token(
            store.active(),
            "https://authz.example.com",
            &["lore.example.com".to_string()],
            "dev",
            3600,
            &AuthzTokenInput {
                user_id: "user-1".to_string(),
                name: "Test User".to_string(),
                preferred_username: "testuser".to_string(),
                is_service_account: false,
                idp: "dev-test-idp".to_string(),
                groups: None,
                resources: vec![ResourcePermission {
                    resource_id: "urc-0000000000000000000000000000000".to_string(),
                    permission: vec!["read".to_string()],
                }],
            },
        )
        .unwrap();

        let decoding_key = DecodingKey::from_jwk(&store.active().public_jwk).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&["https://authz.example.com"]);
        validation.set_audience(&["lore.example.com"]);
        let data = decode::<AuthzClaims>(&signed.token, &decoding_key, &validation).unwrap();
        assert_eq!(data.claims.idp, "dev-test-idp");
        assert!(data.claims.resources.is_some());

        // expires_at is milliseconds (see signed_token doc comment / Q1):
        // sanity bound it against a plausible millisecond range rather than
        // asserting an exact value (encoding happens a few ms after
        // `issued_at` is computed).
        assert!(signed.expires_at > 1_000_000_000_000);
    }

    #[test]
    fn authn_token_has_no_resources_field_at_all() {
        let store = store();
        let signed = mint_authn_token(
            store.active(),
            "https://authz.example.com",
            &["lore.example.com".to_string()],
            "dev",
            36000,
            &AuthnTokenInput {
                user_id: "user-1".to_string(),
                name: "Test User".to_string(),
                preferred_username: "testuser".to_string(),
                is_service_account: false,
            },
        )
        .unwrap();

        // AuthnClaims has no `resources` field at all (see claims.rs) --
        // confirm the encoded payload has no such key, matching lore's own
        // JWTUserInfo shape.
        let payload_b64 = signed.token.split('.').nth(1).unwrap();
        let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&payload_json).unwrap();
        assert!(value.get("resources").is_none());
        assert!(value.get("idp").is_none());
    }
}
