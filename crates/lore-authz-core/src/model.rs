//! Domain model, mirroring the Postgres data model in the design plan
//! (section C) at a level with no database annotations. `lore-authz-server`
//! is responsible for persistence (sqlx) and for mapping these types
//! to/from rows; that mapping is not implemented in this scaffold.

use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

/// A signing key. JWKS publishes `Pending` and `Active` keys (and briefly
/// `Retired` ones); only `Active` keys are used to sign new tokens. See
/// docs/protocol-notes.md on why the NEXT key must be published before it is
/// ever used to sign.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SigningKeyStatus {
    Pending,
    Active,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKey {
    pub kid: String,
    pub alg: String,
    pub status: SigningKeyStatus,
    pub not_before: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdpProtocol {
    Oidc,
    Saml,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpConnection {
    pub id: Uuid,
    pub name: String,
    pub protocol: IdpProtocol,
    pub enabled: bool,
    pub is_default: bool,
    /// OIDC issuer/client_id/client_secret_ref/scopes, or SAML
    /// entity_id/sso_url/certs/binding. Left as an opaque JSON blob at the
    /// domain layer; `lore-authz-server`'s idp integration owns the shape.
    pub config: serde_json::Value,
    pub email_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrincipalStatus {
    Active,
    Suspended,
    Deprovisioned,
}

/// A user OR a service account. Both live in one id space (see design plan
/// section C) so `GetUserInfo`/`GetUserId` work uniformly and `sub` in every
/// token is always a `Principal.id`.
///
/// `external_id` / `source` / `status` are populated starting PHASE 1a (see
/// tasks.md) so that SCIM provisioning (Phase 3) is purely additive later --
/// no migration is needed to add these columns retroactively. Nothing
/// populates `external_id` yet (no SCIM client exists); `source` defaults to
/// `"local"` for every principal created so far.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: Uuid,
    pub idp_connection_id: Option<Uuid>,
    pub subject: String,
    /// The identity's id in whatever external system `source` names (e.g. a
    /// SCIM `externalId`). `None` until a Phase 3 SCIM client sets it.
    pub external_id: Option<String>,
    /// Where this principal was provisioned from: `"local"` (Phase 1a
    /// manual/test provisioning), `"oidc"` (Phase 1b JIT), or `"scim"`
    /// (Phase 3). Advisory/audit only; nothing branches on it yet.
    pub source: String,
    pub email: Option<String>,
    pub display_name: String,
    pub preferred_username: String,
    pub is_service_account: bool,
    pub status: PrincipalStatus,
    /// The `idp` claim value to stamp on AuthZ tokens minted for this
    /// principal, recorded by whichever identity provider proved their
    /// identity (PHASE 1b).
    ///
    /// This field is how `ExchangeUserTokenForMultiresourceToken` answers
    /// docs/open-questions.md Q13: `idp` is MANDATORY on lore-server's
    /// `AuthorizationToken` shape and omitting it fails SILENTLY (the token
    /// decodes as the AuthN shape instead and `resources` becomes `None` --
    /// docs/protocol-notes.md #7b), but the AuthN token the exchange
    /// receives has no `idp` field to recover it from. So it is recovered
    /// from here instead.
    ///
    /// `None` for principals provisioned without an identity provider (the
    /// Phase 1a manual/test path); the token minter falls back to the
    /// configured `TOKEN_IDP` in that case, never to an empty or absent
    /// claim.
    pub idp: Option<String>,
}

/// Same `external_id` / `source` / `status` rationale as `Principal` above --
/// SCIM group provisioning (Phase 3) should be additive, not a migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub external_id: Option<String>,
    pub source: String,
    pub status: PrincipalStatus,
}

/// Populated by `RebacApi::CreateResource` / `DeleteResource`. `resource_id`
/// is `urc-{repository_id}` per lore-server convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub resource_id: String,
    pub resource_name: String,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Built-in roles: reader{read}, writer{read,write}, admin{read,write,admin}.
/// REMINDER: lore-server OSS does not enforce these strings; see
/// docs/protocol-notes.md. Advisory only until a server exists that reads
/// `permission`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrincipalType {
    User,
    Group,
    ServiceAccount,
}

/// The single table the token minter reads to build the `resources` claim,
/// and (PHASE 1a, see tasks.md) the table `LookupUserPermissions` /
/// `CheckUserPermission` read to answer "what can this principal see".
///
/// `resource_pattern` is always a literal string, never `None`: either a
/// specific `urc-{repository_id}` or the literal wildcard `urc-*`, which a
/// grant honors as matching ANY `urc-*` resource (see tasks.md "PHASE 1a" --
/// this replaced an earlier `Option<String>` sketch where `None` meant "all
/// repositories"; storing the literal wildcard string instead means a row
/// read straight out of this table is already in the exact shape
/// `ResourcePermission::matches_repository` checks against, with no `None`
/// special case to keep in sync).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleBinding {
    pub id: Uuid,
    pub role_id: Uuid,
    pub resource_pattern: String,
    pub principal_type: PrincipalType,
    pub principal_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthSessionStatus {
    Pending,
    Approved,
    Consumed,
    Expired,
    Failed,
}

/// The `StartAuthSession` / `GetAuthSession` state machine. `session_code`
/// must be single-use and >=128 bits of CSPRNG entropy; `client_state` is
/// compared by constant-time hash equality, never stored or compared in
/// plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_code: String,
    pub status: AuthSessionStatus,
    pub idp_connection_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}
