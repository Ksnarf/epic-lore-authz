//! Resolves "who is calling" for `LookupUserPermissions` /
//! `CheckUserPermission` from an incoming bearer token -- PHASE 1a (see
//! tasks.md). This deliberately does NOT touch `StartAuthSession` /
//! `GetAuthSession` / `ExchangeUserTokenForMultiresourceToken` (Phase 1b,
//! out of scope for this pass): it decodes ONLY the `sub` claim (the
//! `Principal.id`, per `lore_authz_core::model::Principal`'s doc comment)
//! from whatever JWT this service itself signed, using whichever of the two
//! claim shapes (`AuthzClaims` or `AuthnClaims`) happens to be present --
//! both carry `sub` under the same rename. This module has nothing to do
//! with decoding lore-server's OWN claim shapes; that is a completely
//! separate concern covered by `tests/lore_compat.rs` (see
//! docs/protocol-notes.md).

use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::decode;
use serde::Deserialize;
use tonic::Status;
use uuid::Uuid;

use crate::signing::SigningKeyStore;

#[derive(Deserialize)]
struct SubjectClaim {
    #[serde(rename = "sub")]
    subject: String,
}

/// Strips a leading `"Bearer "` prefix (matching the lore CLI's own
/// `set_auth_header` convention), and treats an empty string as "no token
/// present". Per the fork's `authnz/common.rs::
/// can_create_request_without_authorization` test, lore-server's own
/// `create_request_with_authorization` forwards a literal EMPTY string, not
/// a missing header, when it has nothing to forward on our behalf -- this
/// must be treated as absent, not as a malformed token.
fn strip_bearer(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.strip_prefix("Bearer ").unwrap_or(trimmed))
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

    let decoding_key = DecodingKey::from_jwk(&signing_keys.active().public_jwk)
        .map_err(|err| Status::internal(format!("decoding own public JWK: {err}")))?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(audience);

    let claims = decode::<SubjectClaim>(token, &decoding_key, &validation)
        .map_err(|err| Status::unauthenticated(format!("invalid bearer token: {err}")))?
        .claims;

    Uuid::parse_str(&claims.subject)
        .map_err(|_| Status::unauthenticated("bearer token subject is not a valid principal id"))
}

#[cfg(test)]
mod tests {
    use lore_authz_core::claims::ResourcePermission;

    use super::*;
    use crate::minting::AuthzTokenInput;
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
    }
}
