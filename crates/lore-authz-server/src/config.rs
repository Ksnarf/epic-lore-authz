//! Config surface for the epic-lore-authz binary. Every field here has a
//! corresponding entry in `.env.example` at the repo root -- keep the two in
//! sync. Nothing in this file is a stub: reading env vars is plumbing, not
//! business logic.

use std::env;
use std::net::SocketAddr;

// As of PHASE 1a (see tasks.md), main.rs wires grpc_listen_addr,
// http_listen_addr, signing_key_source, database_url, db_schema, jwt_issuer,
// and jwt_audience. token_env and the TTLs are consumed by
// crates/lore-authz-server/src/minting.rs's functions but not yet threaded
// into main.rs, since the gRPC handlers that would call them
// (ExchangeUserTokenForMultiresourceToken and friends) are still
// Status::unimplemented stubs -- see tasks.md Phase 1b. oidc_*/saml_* become
// load-bearing when Phase 1b/2 land. Not dead code in the design; just not
// all consumed yet.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres connection string. PHASE 1a (see tasks.md): required for
    /// `LookupUserPermissions`, `CheckUserPermission`, and
    /// `RebacApi::CreateResource`/`DeleteResource` to do anything but fail
    /// closed with `Status::failed_precondition` -- see `main.rs` and
    /// `crates/lore-authz-server/src/db/mod.rs`.
    pub database_url: String,
    /// This product owns exactly one schema inside whatever database it is
    /// pointed at (never `public`, never CREATE DATABASE, never superuser).
    /// See design plan section C.
    pub db_schema: String,

    /// Value placed in the `iss` claim of every minted token, and the value
    /// lore-server's `auth.jwt_issuer` must match.
    pub jwt_issuer: String,
    /// Root domain(s) placed in the `aud` claim. MUST include the lore
    /// server's own root domain -- see docs/protocol-notes.md, this is
    /// checked independently by the lore CLI and by lore-server. Comma
    /// separated in the env var.
    pub jwt_audience: Vec<String>,
    /// Value placed in the `env` claim of every minted token (e.g.
    /// "dev"/"staging"/"prod"). Per docs/protocol-notes.md section 2, this
    /// is required on BOTH the AuthZ and AuthN claim shapes -- omitting it
    /// fails both decode attempts loudly, unlike a missing `idp` (AuthZ
    /// shape only), which fails silently. See
    /// crates/lore-authz-server/src/minting.rs.
    pub token_env: String,
    /// Suggested default from the design plan (section A.3): short-lived,
    /// re-login on expiry rather than refresh (RefreshAuthSession is dead
    /// upstream).
    pub authn_token_ttl_secs: u64,
    pub authz_token_ttl_secs: u64,
    /// `idp` claim fallback for principals with no recorded identity
    /// provider. MUST NOT be empty: an AuthZ token with an absent or empty
    /// `idp` is accepted by lore-server and then silently stripped of its
    /// `resources` claim (docs/protocol-notes.md section 2), which surfaces
    /// as a permissions bug rather than a claims error. See
    /// `crate::login::LoginSettings::default_idp`.
    pub token_idp: String,

    /// How long a browser login session stays usable (PHASE 1b). Longer
    /// than the lore CLI's own hard 150-second polling budget on purpose --
    /// see `crate::login`'s module doc comment.
    pub auth_session_ttl_secs: u64,
    /// Origin this service is reachable at IN A BROWSER (scheme + host +
    /// optional port), used to build the `login_url` `StartAuthSession`
    /// hands the CLI. Empty means unset, and `StartAuthSession` then fails
    /// closed rather than issuing a login URL that goes nowhere.
    pub public_base_url: String,

    /// Where signing keys come from. Phase 0: `file://` pointing at an
    /// unencrypted PKCS#8 EC private key (PEM or raw DER; NOT a JWK -- see
    /// `crates/lore-authz-server/src/signing.rs`'s module doc for why a
    /// private-key JWK cannot be loaded through this project's pinned
    /// `jsonwebtoken` crate). If the file does not exist, an ephemeral dev
    /// key is generated in memory instead and a warning is logged. Phase 1:
    /// a real KMS/HSM-backed rotation flow. See docs/architecture.md.
    pub signing_key_source: String,
    /// Path this binary serves its own JWKS document on, for lore-server's
    /// `auth.jwk.endpoint` to point at.
    pub jwks_path: String,

    /// gRPC listener (UrcAuthApi + RebacApi). The lore CLI rewrites any
    /// scheme to https before dialing this (see docs/protocol-notes.md), so
    /// this must terminate TLS the CLI's native root store trusts in any
    /// real deployment, even though the bind address itself is scheme-less.
    pub grpc_listen_addr: SocketAddr,
    /// HTTP listener (JWKS, login, OIDC/SAML callbacks, health/metrics).
    pub http_listen_addr: SocketAddr,

    /// OIDC provider settings for the default/first-configured IdP
    /// connection. Real deployments configure IdP connections in the
    /// database (Phase 1); these env vars exist for a minimal single-tenant
    /// bring-up and local dev.
    pub oidc_issuer_url: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_url: Option<String>,

    /// SAML SP settings, same single-tenant bring-up caveat as OIDC above.
    /// Behind the `saml` cargo feature in Phase 2; see design plan section D.
    pub saml_sp_entity_id: Option<String>,
    pub saml_idp_metadata_url: Option<String>,

    /// Shared secret gating `RebacApi::CreateResource`/`DeleteResource` --
    /// see `crate::service_auth` for why this mechanism (not the user
    /// bearer-JWT path `crate::caller` uses) fits this hop, and
    /// `docs/open-questions.md` Q6/Q12 for the finding this closes.
    /// `None` (unset) means those two RPCs deny every caller: see
    /// `crate::service_auth::verify_rebac_caller`. This is a deliberate
    /// fail-closed default, not a missing feature.
    pub rebac_service_token: Option<String>,
}

fn env_var(key: &str) -> Result<String, anyhow::Error> {
    env::var(key).map_err(|_| anyhow::anyhow!("missing required env var: {key}"))
}

fn env_var_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_var_opt(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

impl Config {
    pub fn from_env() -> Result<Self, anyhow::Error> {
        let jwt_audience = env_var("JWT_AUDIENCE")?
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if jwt_audience.is_empty() {
            anyhow::bail!("JWT_AUDIENCE must contain at least one root domain");
        }

        // Refuse to start rather than mint tokens with an empty `idp`. That
        // failure is silent at lore-server (see the field's doc comment), so
        // it is exactly the kind of misconfiguration that must be caught at
        // startup and not in production traffic.
        let token_idp = env_var_or("TOKEN_IDP", "local");
        if token_idp.trim().is_empty() {
            anyhow::bail!(
                "TOKEN_IDP must not be empty -- an AuthZ token with an empty `idp` claim is \
                 accepted by lore-server and then silently loses its `resources` claim; see \
                 docs/protocol-notes.md section 2"
            );
        }

        Ok(Config {
            database_url: env_var_or("DATABASE_URL", ""),
            db_schema: env_var_or("DB_SCHEMA", "loreauth"),
            jwt_issuer: env_var("JWT_ISSUER")?,
            jwt_audience,
            token_env: env_var_or("TOKEN_ENV", "dev"),
            authn_token_ttl_secs: env_var_or("AUTHN_TOKEN_TTL_SECS", "36000").parse()?, // 10h
            authz_token_ttl_secs: env_var_or("AUTHZ_TOKEN_TTL_SECS", "3600").parse()?,  // 1h
            token_idp,
            auth_session_ttl_secs: env_var_or("AUTH_SESSION_TTL_SECS", "300").parse()?, // 5m
            public_base_url: env_var_or("PUBLIC_BASE_URL", "")
                .trim_end_matches('/')
                .to_string(),
            signing_key_source: env_var_or(
                "SIGNING_KEY_SOURCE",
                "file:///CHANGE_ME/signing-key.der",
            ),
            jwks_path: env_var_or("JWKS_PATH", "/.well-known/jwks.json"),
            grpc_listen_addr: env_var_or("GRPC_LISTEN_ADDR", "0.0.0.0:8443").parse()?,
            http_listen_addr: env_var_or("HTTP_LISTEN_ADDR", "0.0.0.0:8080").parse()?,
            oidc_issuer_url: env_var_opt("OIDC_ISSUER_URL"),
            oidc_client_id: env_var_opt("OIDC_CLIENT_ID"),
            oidc_client_secret: env_var_opt("OIDC_CLIENT_SECRET"),
            oidc_redirect_url: env_var_opt("OIDC_REDIRECT_URL"),
            saml_sp_entity_id: env_var_opt("SAML_SP_ENTITY_ID"),
            saml_idp_metadata_url: env_var_opt("SAML_IDP_METADATA_URL"),
            rebac_service_token: env_var_opt("REBAC_SERVICE_TOKEN"),
        })
    }
}
