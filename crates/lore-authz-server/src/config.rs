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
#[derive(Clone)]
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
    /// database (Phase 2+); these env vars exist for a minimal
    /// single-tenant bring-up and local dev.
    ///
    /// ALL FOUR are required together: a partially configured provider is
    /// treated as unconfigured and every browser login denies (see
    /// `crate::oidc::OidcProvider::new` and `main.rs`). `oidc_client_secret`
    /// comes from configuration only -- there is no default, and none is
    /// committed anywhere in this repository.
    pub oidc_issuer_url: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_url: Option<String>,
    /// Space-separated OIDC scopes. `openid` is added if absent (it is
    /// mandatory in an OIDC authorization request).
    pub oidc_scopes: String,
    /// Create a principal on first login for an identity that has none.
    /// Safe as a default because it creates an IDENTITY, never an
    /// AUTHORIZATION: a just-provisioned principal holds no role bindings,
    /// so its AuthZ token grants nothing. Set `false` for a closed
    /// deployment where every principal is pre-provisioned.
    pub oidc_jit_provisioning: bool,

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

    /// Shared secret gating the ENTIRE admin surface (`/admin/**` on the HTTP
    /// listener: the `/admin/v1` provisioning API and the `/admin/ui` panel)
    /// -- see `crate::admin` for the mechanism and `docs/configuration.md`
    /// for the deployment guidance.
    ///
    /// `None` (unset, or set to the empty string -- `env_var_opt` collapses
    /// the two) means every admin request is DENIED. That is the whole
    /// design: this surface can MINT AUTHORITY (create a principal, bind it
    /// to `urc-*` with the `admin` role), so an unconfigured gate that
    /// defaulted to open would be strictly worse than any bug this project
    /// has fixed. There is deliberately no bypass flag, no "dev mode", and
    /// no way to enable the routes without a token: see
    /// `crate::admin::auth::verify_admin_caller`.
    pub admin_api_token: Option<String>,
}

/// Hand-written so a `Config` can never carry a secret into a log line, a
/// panic message, or an `anyhow` context string. Every secret-valued field is
/// rendered as `Some("<redacted>")` / `None` -- the PRESENCE of a value is
/// operationally important (it is what decides whether a gate denies
/// everything) and is not itself sensitive; the value never is.
///
/// Nothing in this crate currently `{:?}`-prints a `Config`, and this exists
/// so that the day something does, it cannot leak. `config_debug_never_
/// reveals_a_secret_value` in this module's tests is the guard.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        /// Renders as `Some("<redacted>")` / `None`, never the value: the
        /// `Option` is kept (so `Debug` prints the presence) and only its
        /// CONTENT is replaced.
        fn redacted(value: &Option<String>) -> Option<&'static str> {
            value.as_ref().map(|_| "<redacted>")
        }

        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("db_schema", &self.db_schema)
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .field("token_env", &self.token_env)
            .field("authn_token_ttl_secs", &self.authn_token_ttl_secs)
            .field("authz_token_ttl_secs", &self.authz_token_ttl_secs)
            .field("token_idp", &self.token_idp)
            .field("auth_session_ttl_secs", &self.auth_session_ttl_secs)
            .field("public_base_url", &self.public_base_url)
            .field("signing_key_source", &self.signing_key_source)
            .field("jwks_path", &self.jwks_path)
            .field("grpc_listen_addr", &self.grpc_listen_addr)
            .field("http_listen_addr", &self.http_listen_addr)
            .field("oidc_issuer_url", &self.oidc_issuer_url)
            .field("oidc_client_id", &self.oidc_client_id)
            .field("oidc_client_secret", &redacted(&self.oidc_client_secret))
            .field("oidc_redirect_url", &self.oidc_redirect_url)
            .field("oidc_scopes", &self.oidc_scopes)
            .field("oidc_jit_provisioning", &self.oidc_jit_provisioning)
            .field("saml_sp_entity_id", &self.saml_sp_entity_id)
            .field("saml_idp_metadata_url", &self.saml_idp_metadata_url)
            .field("rebac_service_token", &redacted(&self.rebac_service_token))
            .field("admin_api_token", &redacted(&self.admin_api_token))
            .finish()
    }
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

/// Booleans are spelled the way an operator would reasonably spell them, and
/// anything else is a hard startup failure rather than a silent default --
/// `OIDC_JIT_PROVISIONING=flase` must not quietly mean `true`.
fn parse_bool_env(key: &str, default: bool) -> Result<bool, anyhow::Error> {
    match env_var_opt(key) {
        None => Ok(default),
        Some(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => {
                anyhow::bail!("{key} must be one of true/false/1/0/yes/no/on/off, got {other:?}")
            }
        },
    }
}

/// Scheme + host + optional port of a URL, with no trailing slash -- e.g.
/// `https://authz.example.com:8443/oidc/callback` -> `https://authz.example.com:8443`.
/// Returns `None` for anything that is not a parseable absolute URL.
fn origin_of(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    })
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

        // PUBLIC_BASE_URL falls back to the ORIGIN of OIDC_REDIRECT_URL,
        // because in every realistic deployment they are the same host: the
        // redirect URL IS a path on this service's public origin. Deriving
        // it removes a required setting whose only correct value is already
        // written down elsewhere, and a wrong value here produces a login
        // URL that goes nowhere.
        let oidc_redirect_url = env_var_opt("OIDC_REDIRECT_URL");
        let public_base_url = match env_var_opt("PUBLIC_BASE_URL") {
            Some(explicit) => explicit.trim_end_matches('/').to_string(),
            None => oidc_redirect_url
                .as_deref()
                .and_then(origin_of)
                .unwrap_or_default(),
        };

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
            public_base_url,
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
            oidc_redirect_url,
            oidc_scopes: env_var_or("OIDC_SCOPES", "openid profile email"),
            oidc_jit_provisioning: parse_bool_env("OIDC_JIT_PROVISIONING", true)?,
            saml_sp_entity_id: env_var_opt("SAML_SP_ENTITY_ID"),
            saml_idp_metadata_url: env_var_opt("SAML_IDP_METADATA_URL"),
            rebac_service_token: env_var_opt("REBAC_SERVICE_TOKEN"),
            // `env_var_opt` filters the empty string out to `None`, which is
            // exactly the fail-closed reading this gate needs: an operator
            // who writes `ADMIN_API_TOKEN=` in an env file has NOT configured
            // an admin surface, and must not get one that accepts an empty
            // bearer token. See `crate::admin::auth::verify_admin_caller`.
            admin_api_token: env_var_opt("ADMIN_API_TOKEN"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_is_derived_without_the_path_and_keeps_a_non_default_port() {
        assert_eq!(
            origin_of("https://authz.example.com/oidc/callback").as_deref(),
            Some("https://authz.example.com")
        );
        assert_eq!(
            origin_of("https://authz.example.com:8443/oidc/callback").as_deref(),
            Some("https://authz.example.com:8443")
        );
        assert_eq!(
            origin_of("http://127.0.0.1:18080/oidc/callback").as_deref(),
            Some("http://127.0.0.1:18080")
        );
        // Not a usable origin -- the caller falls back to "unconfigured",
        // which denies, rather than to a half-formed URL.
        assert_eq!(origin_of("not a url"), None);
        assert_eq!(origin_of("/oidc/callback"), None);
    }

    /// A typo in a boolean must fail loudly. `OIDC_JIT_PROVISIONING=flase`
    /// silently meaning `true` is exactly the kind of misconfiguration this
    /// setting exists to prevent.
    #[test]
    fn a_misspelled_boolean_is_a_startup_failure_not_a_silent_default() {
        // SAFETY: `set_var`/`remove_var` are unsafe in edition 2024 because
        // they race with other threads reading the environment. This test
        // uses a key no other test touches, and asserts on the parse result
        // rather than on any global config state.
        const KEY: &str = "LORE_AUTHZ_TEST_BOOL_PARSE";
        unsafe { env::remove_var(KEY) };
        assert!(parse_bool_env(KEY, true).unwrap());
        assert!(!parse_bool_env(KEY, false).unwrap());

        for (value, expected) in [
            ("true", true),
            ("TRUE", true),
            ("1", true),
            ("yes", true),
            ("on", true),
            ("false", false),
            ("0", false),
            ("no", false),
            ("off", false),
        ] {
            unsafe { env::set_var(KEY, value) };
            assert_eq!(parse_bool_env(KEY, !expected).unwrap(), expected);
        }

        unsafe { env::set_var(KEY, "flase") };
        assert!(parse_bool_env(KEY, true).is_err());
        unsafe { env::remove_var(KEY) };
    }

    /// Builds a `Config` by hand (not from the environment, so this test
    /// races with nothing) with a recognizable sentinel in every
    /// secret-valued field, and asserts the `Debug` rendering contains NONE
    /// of them. The admin token is the one that matters most: it can mint
    /// authority, so a `{:?}` of the config in a log line or a panic message
    /// would be a credential disclosure.
    #[test]
    fn config_debug_never_reveals_a_secret_value() {
        const SENTINEL: &str = "NEVER-LOG-THIS-VALUE";
        let config = Config {
            database_url: format!("postgres://user:{SENTINEL}@db.example.com/postgres"),
            db_schema: "loreauth".to_string(),
            jwt_issuer: "https://authz.example.com".to_string(),
            jwt_audience: vec!["lore.example.com".to_string()],
            token_env: "test".to_string(),
            authn_token_ttl_secs: 1,
            authz_token_ttl_secs: 1,
            token_idp: "local".to_string(),
            auth_session_ttl_secs: 1,
            public_base_url: "https://authz.example.com".to_string(),
            signing_key_source: "file:///does-not-exist.der".to_string(),
            jwks_path: "/.well-known/jwks.json".to_string(),
            grpc_listen_addr: "127.0.0.1:8443".parse().unwrap(),
            http_listen_addr: "127.0.0.1:8080".parse().unwrap(),
            oidc_issuer_url: Some("https://idp.example.com".to_string()),
            oidc_client_id: Some("client".to_string()),
            oidc_client_secret: Some(SENTINEL.to_string()),
            oidc_redirect_url: Some("https://authz.example.com/oidc/callback".to_string()),
            oidc_scopes: "openid".to_string(),
            oidc_jit_provisioning: true,
            saml_sp_entity_id: None,
            saml_idp_metadata_url: None,
            rebac_service_token: Some(SENTINEL.to_string()),
            admin_api_token: Some(SENTINEL.to_string()),
        };

        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "a secret leaked into Config's Debug rendering: {rendered}"
        );
        // The PRESENCE of each secret is still visible, because "is this
        // gate configured at all" is the operationally important fact and is
        // not itself sensitive.
        assert!(rendered.contains("admin_api_token: Some(\"<redacted>\")"));
        assert!(rendered.contains("rebac_service_token: Some(\"<redacted>\")"));
        assert!(rendered.contains("oidc_client_secret: Some(\"<redacted>\")"));

        let unset = Config {
            admin_api_token: None,
            rebac_service_token: None,
            oidc_client_secret: None,
            ..config
        };
        let rendered = format!("{unset:?}");
        assert!(rendered.contains("admin_api_token: None"));
        assert!(!rendered.contains(SENTINEL));
    }
}
