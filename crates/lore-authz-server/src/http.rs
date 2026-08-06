//! HTTP surface: JWKS, the browser login flow, the OIDC callback, health.
//! Routes match the component diagram in docs/architecture.md. Handlers
//! beyond JWKS, health, and the PHASE 1b login flow are stubs returning 501
//! with a comment naming the delivery phase; see tasks.md.
//!
//! ## This is the BROWSER half of the login
//! `GET /login/{login_code}` and `GET /oidc/callback` are the two routes the
//! operator's browser touches. Neither is authenticated -- they cannot be,
//! since the whole point is to establish who the operator is -- so both are
//! written to be safe when hit by anyone, in any order, with any values:
//!
//! - Every failure renders the SAME page. Unknown login code, expired
//!   session, replayed callback, unrecognized `state`, and a validation
//!   failure at the identity provider are deliberately indistinguishable,
//!   so neither route can be used to probe which session codes are live.
//! - No secret ever appears in a response body, a redirect target other
//!   than the identity provider's own authorization endpoint, or a log line.
//! - Nothing here mints a token. The browser's only power is to move a
//!   session from `pending` to `authenticated`; the token is issued to the
//!   CLI, over gRPC, against a secret the browser never sees.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Html;
use axum::response::IntoResponse;
use axum::response::Redirect;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;

use crate::db::Db;
use crate::oidc::OidcProvider;
use crate::oidc_login;
use crate::oidc_login::CallbackOutcome;
use crate::oidc_login::LoginPageOutcome;
use crate::oidc_login::OidcLoginSettings;
use crate::signing::SigningKeyStore;

/// Shared state for the HTTP listener. `Arc` because axum clones state per
/// request; `SigningKeyStore` holds no interior mutability (single key for
/// the process lifetime -- see signing.rs), so a plain `Arc` is enough.
#[derive(Clone)]
pub struct AppState {
    pub signing_keys: Arc<SigningKeyStore>,
    /// `None` when `DATABASE_URL` is not configured. The login routes deny
    /// in that case: login sessions live in the database precisely so they
    /// survive a load balancer, and an in-memory fallback would be a silent
    /// correctness regression rather than a graceful degrade.
    pub db: Option<Arc<Db>>,
    /// `None` when OIDC is not configured (or is only partly configured --
    /// see `OidcProvider::new`). The login routes deny. There is no code
    /// path where an unconfigured provider produces a completed login.
    pub oidc: Option<Arc<OidcProvider>>,
    pub oidc_login: OidcLoginSettings,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        // lore-server fetches this. Real JWKS document built from the
        // currently active signing key (Phase 0/1b: exactly one key; key
        // rotation is still Phase 1, see docs/architecture.md).
        .route("/.well-known/jwks.json", get(jwks))
        // PHASE 1b: the browser entry point for a pending StartAuthSession.
        // Redirects to the configured identity provider.
        .route("/login/{login_code}", get(login_page))
        .route("/login/done", get(login_done))
        // PHASE 1b: OIDC authorization-code callback.
        .route("/oidc/callback", get(oidc_callback))
        // Phase 2: SAML 2.0 assertion consumer service + SP metadata.
        .route("/saml/acs", post(unimplemented))
        .route("/saml/metadata", get(unimplemented))
        // Phase 2: admin REST API.
        .route("/admin/v1/{*rest}", get(unimplemented))
        // Phase 3: SCIM 2.0.
        .route("/scim/v2/{*rest}", get(unimplemented))
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        // Phase 3: Prometheus metrics. Real health/readiness are trivial
        // enough to implement now (see healthz below); metrics wiring is
        // deferred with the rest of operational hardening.
        .route("/metrics", get(unimplemented))
        .with_state(state)
}

// Trivial liveness/readiness probe. Safe to implement for real: it carries
// no domain logic, unlike everything else in this file.
async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Real JWKS document, built from the active signing key. Every key carries
/// BOTH `kid` and `alg` (see `crates/lore-authz-server/src/signing.rs`'s
/// module doc for the cited lore-server source line that makes this
/// mandatory: a JWKS response missing `alg` on even one key fails loading
/// the entire key set, not just that key). Uses `signing::SigningKeyStore
/// ::jwks()` directly -- the exact same function the compat test in
/// `crates/lore-authz-server/tests/lore_compat.rs` exercises -- so there is
/// one source of truth for this document's shape, not a copy that could
/// drift from what is actually tested.
async fn jwks(State(state): State<AppState>) -> Json<JwkSet> {
    Json(state.signing_keys.jwks())
}

/// Minimal, self-contained HTML. No external stylesheet, no script, no
/// image: this page is rendered mid-login by a browser that may have no
/// network path to anything but this service, and a login page that pulls
/// third-party assets is a login page that leaks the URL it was rendered at.
fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <title>{title}</title></head>\
         <body style=\"font-family:system-ui,sans-serif;margin:4rem auto;max-width:32rem;\
         line-height:1.5\"><h1 style=\"font-size:1.25rem\">{title}</h1><p>{body}</p></body></html>"
    ))
}

/// The one response every invalid login-flow request gets. Identical text,
/// identical status, whatever actually went wrong -- see this module's doc
/// comment.
fn invalid_login_page() -> Response {
    (
        StatusCode::BAD_REQUEST,
        page(
            "This login link is no longer valid",
            "It may have expired, already been used, or never existed. Start a new login from \
             the command line and use the fresh link it gives you.",
        ),
    )
        .into_response()
}

/// Distinguished from `invalid_login_page` on purpose: this one is an
/// OPERATOR problem (the identity provider is unreachable or misconfigured),
/// and telling a user to keep retrying a broken provider is worse than
/// telling them it is broken. It reveals nothing about any session.
fn provider_unavailable_page() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        page(
            "The identity provider is unavailable",
            "This service could not reach the configured identity provider. This is a server-side \
             problem, not something you can fix by retrying. Please contact your administrator.",
        ),
    )
        .into_response()
}

/// Returned when the login flow is not configured at all. Deliberately does
/// NOT resemble a success, and deliberately does not say which of the two
/// (database, identity provider) is missing.
fn login_not_configured_page() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        page(
            "Login is not configured",
            "This authorization service has no login flow configured. This is a server-side \
             configuration problem; please contact your administrator.",
        ),
    )
        .into_response()
}

/// PHASE 1b. The browser follows the `login_url` `StartAuthSession` handed
/// the CLI, and is redirected to the identity provider's authorization
/// endpoint carrying this session's `state`, `nonce` and PKCE challenge.
///
/// `login_code` is a DIFFERENT secret from the `session_code` the CLI polls
/// with (see `migrations/0002_auth_sessions.sql`), so this URL appearing in
/// browser history, a chat message, or a screenshot does not let its holder
/// collect the resulting token.
async fn login_page(State(state): State<AppState>, Path(login_code): Path<String>) -> Response {
    let (Some(db), Some(provider)) = (state.db.as_ref(), state.oidc.as_ref()) else {
        return login_not_configured_page();
    };

    match oidc_login::authorize_redirect(db, provider, &login_code).await {
        Ok(LoginPageOutcome::Redirect(url)) => Redirect::to(&url).into_response(),
        Ok(LoginPageOutcome::Invalid) => invalid_login_page(),
        Ok(LoginPageOutcome::ProviderUnavailable) => provider_unavailable_page(),
        Err(err) => {
            // A Status here is an internal failure (a database error), not a
            // user error. Log the code only; the message may name internals.
            tracing::warn!(code = ?err.code(), "login page failed");
            provider_unavailable_page()
        }
    }
}

async fn login_done() -> Response {
    (
        StatusCode::OK,
        page(
            "You are signed in",
            "You may close this tab and return to your terminal.",
        ),
    )
        .into_response()
}

/// The query parameters an OIDC provider redirects back with: either
/// `code` + `state` on success, or `error` (+ optional `error_description`)
/// on failure, per RFC 6749 sections 4.1.2 and 4.1.2.1.
#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// PHASE 1b. The identity provider redirects the browser here.
///
/// Everything that decides whether this completes a login happens in
/// `crate::oidc_login::complete_callback`: `state` must resolve to a pending,
/// unexpired session; the code exchange must succeed with that session's own
/// PKCE verifier; the ID token's signature, `iss`, `aud`, `exp` and `nonce`
/// must all check out; and the identity must resolve to an ACTIVE principal.
/// This handler only turns the outcome into a page.
async fn oidc_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let (Some(db), Some(provider)) = (state.db.as_ref(), state.oidc.as_ref()) else {
        return login_not_configured_page();
    };

    // The provider told us the user declined, or that something went wrong
    // on its side. `error` is a fixed RFC 6749 code, not free text, but it
    // is still attacker-influenceable input arriving in a URL -- log it as a
    // structured field, never interpolate it into the page.
    if let Some(error) = query.error.as_deref() {
        tracing::warn!(oidc_error = %error, "identity provider returned an error to the callback");
        return invalid_login_page();
    }

    let (Some(code), Some(session_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return invalid_login_page();
    };

    match oidc_login::complete_callback(db, provider, &state.oidc_login, code, session_state).await
    {
        Ok(CallbackOutcome::Completed) => login_done().await,
        Ok(CallbackOutcome::Invalid) => invalid_login_page(),
        Ok(CallbackOutcome::ProviderUnavailable) => provider_unavailable_page(),
        Err(err) => {
            tracing::warn!(code = ?err.code(), "OIDC callback failed");
            provider_unavailable_page()
        }
    }
}

async fn unimplemented() -> (StatusCode, &'static str) {
    (
        StatusCode::NOT_IMPLEMENTED,
        "not implemented in this scaffold - see tasks.md for the owning phase",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use uuid::Uuid;

    use super::*;
    use crate::login;
    use crate::login::LoginSettings;
    use crate::oidc::OidcConfig;
    use crate::signing::SigningKeyStore;

    fn signing_keys() -> Arc<SigningKeyStore> {
        Arc::new(
            SigningKeyStore::load("file:///epic-lore-authz-http-test-fixture-does-not-exist.der")
                .unwrap(),
        )
    }

    fn unconfigured_state() -> AppState {
        AppState {
            signing_keys: signing_keys(),
            db: None,
            oidc: None,
            oidc_login: OidcLoginSettings::default(),
        }
    }

    /// Security review finding: both browser routes' "login is not
    /// configured" denial (`db` or `oidc` unset) was `[code-says]` -- read
    /// but never actually executed by a test. Both fail toward denial
    /// (503), never toward anything resembling success, and the underlying
    /// logic is already covered at the unit/gRPC level (see tasks.md); this
    /// is the smoke test over the HTTP surface itself.
    #[tokio::test]
    async fn login_page_denies_when_not_configured() {
        let response = login_page(
            State(unconfigured_state()),
            Path("any-login-code".to_string()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn oidc_callback_denies_when_not_configured() {
        let response = oidc_callback(
            State(unconfigured_state()),
            Query(CallbackQuery {
                code: Some("any-code".to_string()),
                state: Some("any-state".to_string()),
                error: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A fresh, throwaway SQLite database -- no Docker/Postgres/Dex needed
    /// for this file's tests, unlike `tests/oidc_flow.rs`.
    async fn fresh_sqlite_db() -> Db {
        let path = std::env::temp_dir().join(format!(
            "epic-lore-authz-http-test-{}.sqlite3",
            Uuid::new_v4()
        ));
        let database_url = format!("sqlite://{}", path.display());
        Db::connect(&database_url, "loreauth")
            .await
            .expect("connect + migrate a fresh throwaway sqlite file")
    }

    /// Security review finding: the `ProviderUnavailable` page (502) was
    /// `[code-says]` -- the test IdP is always up, so nothing ever drove
    /// this branch for real. Here the identity provider genuinely is
    /// unreachable (port 0 never accepts a connection), so this exercises
    /// the REAL path: `login_page` -> `oidc_login::authorize_redirect` ->
    /// `OidcProvider::authorization_url` -> `discovery()` actually failing.
    /// Asserts the response is `provider_unavailable_page` (502), never a
    /// success and never indistinguishable from `invalid_login_page` (400).
    #[tokio::test]
    async fn login_page_renders_provider_unavailable_when_the_idp_is_unreachable() {
        let db = fresh_sqlite_db().await;
        let provider = OidcProvider::new(OidcConfig {
            issuer: "http://127.0.0.1:0".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            redirect_url: "https://authz.example.com/oidc/callback".to_string(),
            scopes: "openid".to_string(),
        })
        .unwrap();

        let settings = LoginSettings {
            public_base_url: "https://authz.example.com".to_string(),
            ..LoginSettings::default()
        };
        let started = login::start_session(
            &db,
            &settings,
            "client-state",
            "the-oidc-state".to_string(),
            "the-oidc-nonce".to_string(),
            "the-pkce-verifier".to_string(),
        )
        .await
        .expect("start a pending login session");
        let login_code = started
            .login_url
            .rsplit('/')
            .next()
            .expect("login_url must end with the login_code")
            .to_string();

        let state = AppState {
            signing_keys: signing_keys(),
            db: Some(Arc::new(db)),
            oidc: Some(Arc::new(provider)),
            oidc_login: OidcLoginSettings::default(),
        };

        let response = login_page(State(state), Path(login_code)).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "an unreachable identity provider must render provider_unavailable_page, not a \
             success and not invalid_login_page"
        );
    }

    /// Same real-unreachable-provider shape, through the OTHER browser
    /// route: the identity provider redirects back with a code, but the
    /// token-endpoint exchange itself cannot reach the provider. Built with
    /// `login::start_session` directly (rather than `oidc_login::start`) so
    /// the `oidc_state` this test presents back is known upfront.
    #[tokio::test]
    async fn oidc_callback_renders_provider_unavailable_when_the_idp_is_unreachable() {
        let db = fresh_sqlite_db().await;
        let provider = OidcProvider::new(OidcConfig {
            issuer: "http://127.0.0.1:0".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            redirect_url: "https://authz.example.com/oidc/callback".to_string(),
            scopes: "openid".to_string(),
        })
        .unwrap();

        let settings = LoginSettings {
            public_base_url: "https://authz.example.com".to_string(),
            ..LoginSettings::default()
        };
        login::start_session(
            &db,
            &settings,
            "client-state",
            "the-oidc-state".to_string(),
            "the-oidc-nonce".to_string(),
            "the-pkce-verifier".to_string(),
        )
        .await
        .expect("start a pending login session");

        let state = AppState {
            signing_keys: signing_keys(),
            db: Some(Arc::new(db)),
            oidc: Some(Arc::new(provider)),
            oidc_login: OidcLoginSettings::default(),
        };

        let response = oidc_callback(
            State(state),
            Query(CallbackQuery {
                code: Some("some-authorization-code".to_string()),
                state: Some("the-oidc-state".to_string()),
                error: None,
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "an unreachable identity provider must render provider_unavailable_page"
        );
    }
}
