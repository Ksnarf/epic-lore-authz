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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: Uuid,
    pub idp_connection_id: Option<Uuid>,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: String,
    pub preferred_username: String,
    pub is_service_account: bool,
    pub status: PrincipalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
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

/// The single table the token minter reads to build the `resources` claim.
/// `resource_id: None` means "all repositories" (mints as `urc-*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleBinding {
    pub id: Uuid,
    pub role_id: Uuid,
    pub resource_id: Option<String>,
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
