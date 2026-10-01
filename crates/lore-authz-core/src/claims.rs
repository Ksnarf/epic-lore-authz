//! JWT claim shapes matching what lore-server's JWT verifier actually
//! deserializes (lore-server/src/auth/jwt.rs at the pinned commit, see
//! docs/protocol-notes.md). These are OUR types, independently written to
//! match the observed contract -- they are not copied from lore-server's
//! source. Field names and `serde(rename)` values below MUST stay in sync
//! with lore-server or every minted token silently degrades to the
//! `AuthNClaims` fallback shape and loses the `resources` claim. See
//! docs/protocol-notes.md for the full explanation of that failure mode.
//!
//! The compat test called out in the design plan as the single
//! highest-value test in the project (a token minted from these structs
//! deserializing into a VERBATIM copy of lore-server's `AuthorizationToken`
//! with `resources` populated, plus the negative case for a missing `idp`)
//! lives at `crates/lore-authz-server/tests/lore_compat.rs`. See
//! `crates/lore-authz-server/src/minting.rs` for the functions that build
//! and sign these claims.

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
    /// IdP groups claim (Path A, see `docs/configuration.md`'s OIDC section
    /// and `crates/lore-authz-server/src/oidc.rs`'s `extract_groups`).
    /// `skip_serializing_if` so a token minted with no groups is
    /// byte-identical to one minted before this field existed -- an IdP that
    /// never emits the configured claim must not change the wire shape of
    /// every other token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    pub is_service_account: Option<bool>,
    #[serde(rename = "exp")]
    pub expires_at: u64,
}

/// A signed, encoded JWT plus the metadata callers need without
/// re-decoding it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedToken {
    pub token: String,
    /// SETTLED (docs/open-questions.md Q1): **milliseconds** since the UNIX
    /// epoch, matching `epic_urc::UserToken.expires_at` on the wire.
    ///
    /// This is NOT the same unit as the JWT's own `exp` claim inside
    /// `token` (`AuthzClaims::expires_at` / `AuthnClaims::expires_at`
    /// below), which is always whole seconds per the JWT spec and per
    /// `jsonwebtoken`'s own `validate_exp`. Two different fields, two
    /// different units, same English word "expires" -- do not conflate them
    /// when minting (see `crates/lore-authz-server/src/minting.rs`).
    ///
    /// Evidence (verified against `EpicGames/lore` at the pinned commit
    /// `f205899adf24b13b2d28e5c08d9256ac99c69f0c`):
    /// `lore-transport/src/auth/ucs_auth.rs` assigns the proto's
    /// `expires_at` straight into a field literally named `expires_ms` with
    /// no `* 1000` scaling (`expires_ms: token.expires_at.max(0) as u64`,
    /// three call sites); `lore-transport/src/types.rs` documents that
    /// `expires_ms` field as "Expiry as milliseconds since UNIX epoch"; and
    /// `lore-transport/src/connection.rs`'s own tests use
    /// millisecond-shaped literals for it (e.g. `1_700_000_000_000`, which
    /// is a plausible 2023 date in milliseconds but a nonsensical year-55919
    /// date in seconds). By contrast, `lore-credential/src/jwt.rs`
    /// (`user_info_from_token`) DOES multiply the JWT `exp` claim by 1000
    /// ("JWT has number of seconds since UNIX epoch ... we want
    /// milliseconds like all other timestamps in Lore") -- confirming the
    /// JWT `exp` claim itself is seconds, and that the proto-level
    /// `expires_at` is a separately-tracked millisecond value, not a
    /// re-statement of the JWT's `exp`.
    pub expires_at: i64,
}
