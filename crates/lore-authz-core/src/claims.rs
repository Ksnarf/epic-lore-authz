//! JWT claim shapes matching what lore-server's JWT verifier actually
//! deserializes (lore-server/src/auth/jwt.rs at the pinned commit, see
//! docs/protocol-notes.md). These are OUR types, independently written to
//! match the observed contract -- they are not copied from lore-server's
//! source. Field names and `serde(rename)` values below MUST stay in sync
//! with lore-server or every minted token silently degrades to the
//! `AuthNClaims` fallback shape and loses the `resources` claim. See
//! docs/protocol-notes.md for the full explanation of that failure mode.
//!
//! TODO(phase 0): add a compat test that deserializes a token minted from
//! these structs using a VERBATIM copy of lore-server's `AuthorizationToken`
//! struct (MIT licensed, safe to vendor for test purposes). That is called
//! out in the design plan as the single highest-value test in the project.
//! Not included in this scaffold; tracked in tasks.md Phase 0.

use serde::Deserialize;
use serde::Serialize;
use serde_with::OneOrMany;
use serde_with::formats::PreferMany;
use serde_with::serde_as;

/// One entry in the `resources` claim of an AuthZ token.
///
/// lore-server's `verify_authorization` only ever checks whether one of
/// these matches the requested repository's resource_id (`urc-{repo_id}`)
/// or is the wildcard `urc-*`. It never reads `permission`. Do not market or
/// rely on per-permission enforcement server-side; see
/// docs/protocol-notes.md.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePermission {
    pub resource_id: String,
    /// Advisory only as far as the OSS lore-server is concerned. Populate it
    /// honestly anyway (read/write/admin) so a future server, or an
    /// operator reading raw tokens, sees a truthful vocabulary.
    pub permission: Vec<String>,
}

impl ResourcePermission {
    pub fn is_wildcard(&self) -> bool {
        self.resource_id == "urc-*"
    }

    pub fn matches_repository(&self, checked_resource_id: &str) -> bool {
        self.is_wildcard() || self.resource_id == checked_resource_id
    }
}

/// AuthZ token claims. Minted by `ExchangeUserTokenForMultiresourceToken`.
/// This is the "big" token: lore-server's `JwtInterceptor` validates it on
/// every repository RPC.
///
/// ALL non-Option fields here are mandatory for lore-server to decode a
/// token as this shape rather than falling back to `AuthNClaims`. In
/// particular: forgetting `idp` is the single highest-value bug to avoid --
/// see docs/protocol-notes.md.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthzClaims {
    #[serde(rename = "sub")]
    pub user_id: String,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "iat")]
    pub issued_at: u64,
    #[serde(rename = "exp")]
    pub expires_at: u64,
    /// MUST contain the lore-server root domain. See docs/protocol-notes.md
    /// ("aud is a list of root domains") -- this is not an opaque audience
    /// string, it is checked client-side against the remote's domain.
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(rename = "aud")]
    pub audience: Vec<String>,
    pub env: String,
    pub name: String,
    pub preferred_username: String,
    pub resources: Option<Vec<ResourcePermission>>,
    pub groups: Option<Vec<String>>,
    pub is_service_account: Option<bool>,
    /// REQUIRED. Omitting this does not fail loudly: lore-server falls back
    /// to decoding the token as `AuthNClaims`, silently drops `resources`,
    /// and every authorization check then fails with a misleading
    /// "not authorized" rather than a decode error. See
    /// docs/protocol-notes.md.
    pub idp: String,
}

/// AuthN token claims (called "user token" in the plan). Minted by
/// StartAuthSession/GetAuthSession, ExchangeExternalTokenForUserToken, or
/// ExchangeAPIKeyForUserToken. Identity only -- carries no `resources`.
/// This is also the shape lore-server falls back to decoding as when a
/// token is missing a field required by `AuthzClaims` (notably `idp`).
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthnClaims {
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
    pub expires_at: u64,
}

/// A signed, encoded JWT plus the metadata callers need without
/// re-decoding it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedToken {
    pub token: String,
    /// UNVERIFIED UNIT: seconds or milliseconds since epoch? See
    /// docs/open-questions.md Q1. Whatever unit is chosen MUST match what
    /// this same field means in `epic_urc::UserToken.expires_at` on the
    /// wire, and MUST be settled empirically (Phase 0) before this type is
    /// treated as authoritative.
    pub expires_at: i64,
}
