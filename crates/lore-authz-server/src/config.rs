//! Config surface for the epic-lore-authz binary. Every field here has a
//! corresponding entry in `.env.example` at the repo root -- keep the two in
//! sync. Nothing in this file is a stub: reading env vars is plumbing, not
//! business logic.

use std::env;
use std::net::SocketAddr;

// Most fields are not read yet: this scaffold only wires grpc_listen_addr
// and http_listen_addr into main.rs. The rest become load-bearing as Phase 0
// / Phase 1 tasks in tasks.md land (token minting, signing keys, IdP). Not
// dead code in the design; just not consumed yet.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres connection string. Phase 0 runs entirely in memory and does
    /// not read this; it becomes load-bearing in Phase 1.
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
    /// Suggested default from the design plan (section A.3): short-lived,
    /// re-login on expiry rather than refresh (RefreshAuthSession is dead
    /// upstream).
    pub authn_token_ttl_secs: u64,
    pub authz_token_ttl_secs: u64,

    /// Where signing keys come from. Phase 0: a single key read from a file
    /// or env var. Phase 1: a real KMS/HSM-backed rotation flow. See
    /// docs/architecture.md.
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

        Ok(Config {
            database_url: env_var_or("DATABASE_URL", ""),
            db_schema: env_var_or("DB_SCHEMA", "loreauth"),
            jwt_issuer: env_var("JWT_ISSUER")?,
            jwt_audience,
            authn_token_ttl_secs: env_var_or("AUTHN_TOKEN_TTL_SECS", "36000").parse()?, // 10h
            authz_token_ttl_secs: env_var_or("AUTHZ_TOKEN_TTL_SECS", "3600").parse()?,  // 1h
            signing_key_source: env_var_or("SIGNING_KEY_SOURCE", "file:///CHANGE_ME.jwk"),
            jwks_path: env_var_or("JWKS_PATH", "/.well-known/jwks.json"),
            grpc_listen_addr: env_var_or("GRPC_LISTEN_ADDR", "0.0.0.0:8443").parse()?,
            http_listen_addr: env_var_or("HTTP_LISTEN_ADDR", "0.0.0.0:8080").parse()?,
            oidc_issuer_url: env_var_opt("OIDC_ISSUER_URL"),
            oidc_client_id: env_var_opt("OIDC_CLIENT_ID"),
            oidc_client_secret: env_var_opt("OIDC_CLIENT_SECRET"),
            oidc_redirect_url: env_var_opt("OIDC_REDIRECT_URL"),
            saml_sp_entity_id: env_var_opt("SAML_SP_ENTITY_ID"),
            saml_idp_metadata_url: env_var_opt("SAML_IDP_METADATA_URL"),
        })
    }
}
