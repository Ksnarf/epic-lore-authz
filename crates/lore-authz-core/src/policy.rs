//! I/O-free trait boundaries. `lore-authz-server` provides real
//! implementations (Postgres-backed, IdP-backed, signing-key-backed); this
//! crate only defines the shape those implementations must satisfy.
//!
//! None of these traits are implemented in this scaffold. Every real
//! implementation lives in `lore-authz-server` and is stubbed with
//! `todo!()` there, each annotated with the delivery phase (see
//! design plan section E / this repo's tasks.md) that is expected to fill
//! it in.

use async_trait::async_trait;

use crate::AuthzError;
use crate::claims::AuthnClaims;
use crate::claims::SignedToken;
use crate::model::Principal;

/// Turns a principal (plus, for AuthZ tokens, the requested resource ids)
/// into a signed JWT. Implemented against real key storage + jsonwebtoken in
/// `lore-authz-server`.
///
/// SIZING RULE (design plan section C): `mint_authz_token` must mint ONLY
/// the requested resource_ids (plus `urc-*` if the principal holds a
/// wildcard binding). Never enumerate every repository a principal can see
/// into one token -- AuthZ tokens are sent as gRPC metadata on every repo
/// RPC and header size limits are real.
#[async_trait]
pub trait TokenMinter: Send + Sync {
    async fn mint_authn_token(&self, principal: &Principal) -> Result<SignedToken, AuthzError>;

    async fn mint_authz_token(
        &self,
        authn: &AuthnClaims,
        resource_ids: &[String],
    ) -> Result<SignedToken, AuthzError>;
}

/// Reads role_bindings (+ groups, + roles) and answers "what does this
/// principal see" for token minting and for `CheckUserPermission` /
/// `LookupUserPermissions`.
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Resource ids (already resolved to `urc-*` for wildcard bindings) the
    /// principal is allowed to receive in a minted AuthZ token, restricted
    /// to the subset of `requested_resource_ids` actually held.
    async fn resolve_resource_permissions(
        &self,
        principal: &Principal,
        requested_resource_ids: &[String],
    ) -> Result<Vec<crate::claims::ResourcePermission>, AuthzError>;
}

/// Resolves an external identity (OIDC id_token claims, SAML assertion, CI
/// OIDC federation token, API key) to a local `Principal`, JIT-provisioning
/// one if this is the first time the subject has been seen. See design plan
/// section A.3 for the three service-account paths this must eventually
/// support.
#[async_trait]
pub trait IdentityResolver: Send + Sync {
    async fn resolve_or_provision(&self, external_subject: &str) -> Result<Principal, AuthzError>;
}
