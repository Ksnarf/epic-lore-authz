//! The OIDC login flow, driven against a REAL OpenID Connect provider
//! running in a container (PHASE 1b, see tasks.md).
//!
//! ## Why a real identity provider
//! This project has already been burned by mocked tests passing while the
//! real integration was broken (see `docs/protocol-notes.md` and the compat
//! test philosophy in `tests/lore_compat.rs`). So the login leg gets the
//! same treatment as the authorization leg: a real provider, serving a real
//! discovery document, signing real RS256 ID tokens with a real key from a
//! real JWKS endpoint, enforcing real PKCE and real one-time authorization
//! codes. Nothing in this file mocks an HTTP response.
//!
//! Nothing here is provider-SPECIFIC either. Every endpoint is discovered
//! from `/.well-known/openid-configuration`, exactly as it would be against
//! any other IdP -- see `crates/lore-authz-server/src/oidc.rs`'s
//! "provider-agnostic on purpose" note and `docker/dex/config.yaml`.
//!
//! ## Running these
//! `docker compose -f docker-compose.test.yml run --rm --build tests`
//! provides everything. Outside that, set `TEST_OIDC_ISSUER`,
//! `TEST_OIDC_CLIENT_ID`, `TEST_OIDC_CLIENT_SECRET`,
//! `TEST_OIDC_REDIRECT_URL` (and `TEST_DATABASE_URL` for the Postgres half).
//! If they are unset, these tests PANIC with a message saying so -- fail
//! loudly, never skip silently into a green result that proved nothing.
//!
//! ## Two fidelities, on purpose
//! - `full_login_flow_end_to_end_through_the_real_http_server` runs the
//!   maximum-fidelity version: this service's REAL axum router bound to a
//!   real socket, and an HTTP client that follows every redirect exactly as
//!   a browser would -- our `/login/{code}` route, the provider's authorize
//!   endpoint, the provider's redirect back to our `/oidc/callback` route,
//!   and the resulting page. It holds a process-wide lock because the
//!   redirect URI (and therefore the port) is registered with the provider
//!   and cannot be ephemeral.
//! - Every other session-level case stops at the provider's redirect,
//!   captures the real authorization code, and calls
//!   `oidc_login::complete_callback` -- the exact function the HTTP handler
//!   calls, with the exact inputs it would receive. Same code path, no port
//!   contention, and they run in parallel.
//!
//! ## Storage cases run against BOTH backends
//! Anything touching a login session is parameterized over `Backend` and
//! called twice, matching the rule `tests/authz_suite/mod.rs` establishes.

use std::sync::Arc;

use lore_authz_proto::UrcAuthApi as _;
use lore_authz_proto::epic_urc;
use lore_authz_server::db::Db;
use lore_authz_server::db::principals;
use lore_authz_server::db::sessions;
use lore_authz_server::grpc::AuthApiService;
use lore_authz_server::http;
use lore_authz_server::http::AppState;
use lore_authz_server::login::LoginSettings;
use lore_authz_server::oidc::OidcConfig;
use lore_authz_server::oidc::OidcProvider;
use lore_authz_server::oidc_login;
use lore_authz_server::oidc_login::CallbackOutcome;
use lore_authz_server::oidc_login::OidcLoginSettings;
use lore_authz_server::oidc_login::PRINCIPAL_SOURCE_OIDC;
use lore_authz_server::secret::random_url_safe_token;
use lore_authz_server::secret::sha256_b64url;
use lore_authz_server::signing::SigningKeyStore;
use tonic::Request;
use uuid::Uuid;

const ISSUER: &str = "https://authz.example.com";
const TOKEN_ENV: &str = "test";
const DEFAULT_IDP: &str = "test-default-idp";

#[derive(Debug, Clone, Copy)]
enum Backend {
    Postgres,
    Sqlite,
}

fn env_or_panic(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        panic!(
            "{key} must be set to run the OIDC login-flow tests against a REAL identity \
             provider. `docker compose -f docker-compose.test.yml run --rm --build tests` sets \
             every one of them; see this file's module doc comment. These are real integration \
             tests -- there is no mock fallback and no silent skip."
        )
    })
}

fn audience() -> Vec<String> {
    vec!["lore.example.com".to_string()]
}

/// The browser-facing origin of THIS service during the test, derived from
/// the redirect URL registered with the provider -- the same derivation
/// `Config::from_env` performs when `PUBLIC_BASE_URL` is unset.
fn public_base_url() -> String {
    let redirect = env_or_panic("TEST_OIDC_REDIRECT_URL");
    let url = reqwest::Url::parse(&redirect).expect("TEST_OIDC_REDIRECT_URL must be a URL");
    match url.port() {
        Some(port) => format!("{}://{}:{port}", url.scheme(), url.host_str().unwrap()),
        None => format!("{}://{}", url.scheme(), url.host_str().unwrap()),
    }
}

fn provider() -> Arc<OidcProvider> {
    Arc::new(
        OidcProvider::new(OidcConfig {
            issuer: env_or_panic("TEST_OIDC_ISSUER"),
            client_id: env_or_panic("TEST_OIDC_CLIENT_ID"),
            client_secret: env_or_panic("TEST_OIDC_CLIENT_SECRET"),
            redirect_url: env_or_panic("TEST_OIDC_REDIRECT_URL"),
            scopes: "openid profile email".to_string(),
        })
        .expect("a fully configured test provider"),
    )
}

async fn fresh_db(backend: Backend) -> Db {
    match backend {
        Backend::Postgres => {
            let url = std::env::var("TEST_DATABASE_URL").expect(
                "TEST_DATABASE_URL must point at a real, reachable Postgres instance -- see \
                 docker-compose.test.yml",
            );
            let schema = format!("test_{}", Uuid::new_v4().simple());
            Db::connect(&url, &schema)
                .await
                .expect("connect + migrate a fresh throwaway Postgres schema")
        }
        Backend::Sqlite => {
            let path = std::env::temp_dir()
                .join(format!("epic-lore-authz-oidc-{}.sqlite3", Uuid::new_v4()));
            Db::connect(&format!("sqlite://{}", path.display()), "loreauth")
                .await
                .expect("connect + migrate a fresh throwaway sqlite file")
        }
    }
}

struct Harness {
    db: Arc<Db>,
    auth_service: AuthApiService,
    provider: Arc<OidcProvider>,
    login_settings: OidcLoginSettings,
    state: AppState,
}

impl Harness {
    async fn new(backend: Backend) -> Self {
        Self::with_jit(backend, true).await
    }

    async fn with_jit(backend: Backend, jit_provisioning: bool) -> Self {
        let db = Arc::new(fresh_db(backend).await);
        let signing_keys = Arc::new(
            SigningKeyStore::load("file:///epic-lore-authz-oidc-test-fixture-does-not-exist.der")
                .expect("ephemeral signing key for test"),
        );
        let provider = provider();
        let login = LoginSettings {
            token_env: TOKEN_ENV.to_string(),
            authn_token_ttl_secs: 36_000,
            authz_token_ttl_secs: 3_600,
            session_ttl_secs: 300,
            public_base_url: public_base_url(),
            default_idp: DEFAULT_IDP.to_string(),
        };
        let login_settings = OidcLoginSettings { jit_provisioning };
        Self {
            auth_service: AuthApiService {
                db: Some(db.clone()),
                signing_keys: signing_keys.clone(),
                jwt_issuer: ISSUER.to_string(),
                jwt_audience: audience(),
                login,
                oidc: Some(provider.clone()),
            },
            state: AppState {
                signing_keys,
                db: Some(db.clone()),
                oidc: Some(provider.clone()),
                oidc_login: login_settings.clone(),
                // This suite exercises the login flow, not the admin
                // surface. `None` means every /admin route on the router it
                // binds denies -- the fail-closed default, asserted directly
                // in `tests/authz_suite/mod.rs`.
                admin_api_token: None,
            },
            db,
            provider,
            login_settings,
        }
    }

    /// The real `StartAuthSession` RPC -- not a shortcut into the storage
    /// layer.
    async fn start(&self, client_state: &str) -> epic_urc::StartAuthSessionResponse {
        self.auth_service
            .start_auth_session(Request::new(epic_urc::StartAuthSessionRequest {
                client_state: client_state.to_string(),
            }))
            .await
            .expect("start_auth_session")
            .into_inner()
    }

    async fn poll(&self, session_code: &str, client_state: &str) -> Option<epic_urc::UserToken> {
        self.auth_service
            .get_auth_session(Request::new(epic_urc::GetAuthSessionRequest {
                session_code: session_code.to_string(),
                client_state: client_state.to_string(),
            }))
            .await
            .expect("get_auth_session")
            .into_inner()
            .user_token
    }

    /// Reads the session's OIDC transients. Only a TEST does this: it is
    /// how a case can drive the provider leg with a deliberately wrong nonce
    /// or an unknown state while keeping everything else real.
    async fn session_transients(&self, login_url: &str) -> sessions::SessionRow {
        let login_code = login_url.rsplit('/').next().expect("a login code");
        sessions::find_by_login_code_hash(&self.db, &sha256_b64url(login_code))
            .await
            .expect("session lookup")
            .expect("the session StartAuthSession just created")
    }
}

/// An HTTP client that behaves like a browser up to the point where the
/// provider redirects back to this service, then STOPS -- so the test can
/// read the authorization code and `state` off the redirect target instead
/// of letting a listener consume them.
fn client_stopping_at_the_redirect_uri() -> reqwest::Client {
    let redirect_host = reqwest::Url::parse(&env_or_panic("TEST_OIDC_REDIRECT_URL"))
        .expect("TEST_OIDC_REDIRECT_URL must be a URL")
        .host_str()
        .expect("a host")
        .to_string();
    reqwest::Client::builder()
        // The provider sets a cookie between its own authorize and callback
        // legs, exactly as it would for a real browser.
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.url().host_str() == Some(redirect_host.as_str()) {
                attempt.stop()
            } else if attempt.previous().len() > 10 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .expect("test http client")
}

/// Drives the provider's authorization endpoint for real and returns the
/// `(code, state)` it redirects back with.
///
/// `state`, `nonce` and `code_verifier` are parameters so a test can supply
/// a session's real values (the honest path) or deliberately wrong ones (the
/// attack paths) while everything on the provider's side stays real.
async fn authorization_code_from_the_real_provider(
    state: &str,
    nonce: &str,
    code_verifier: &str,
) -> (String, String) {
    // Built through the same code that builds it in production, so a bug in
    // the authorization request itself is caught here rather than papered
    // over by a hand-written URL.
    let url = provider()
        .authorization_url(state, nonce, code_verifier)
        .await
        .expect("authorization URL from a real discovery document");

    let response = client_stopping_at_the_redirect_uri()
        .get(&url)
        .send()
        .await
        .expect("the identity provider's authorize endpoint");

    // `Policy::stop` yields the redirect response itself, un-followed.
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| response.url().to_string());
    let redirected =
        reqwest::Url::parse(&location).expect("the provider's redirect target must be a URL");

    let mut code = None;
    let mut returned_state = None;
    for (key, value) in redirected.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.to_string()),
            "state" => returned_state = Some(value.to_string()),
            _ => {}
        }
    }
    (
        code.expect("the identity provider must return an authorization code"),
        returned_state.expect("the identity provider must echo the state back"),
    )
}

/// Redeems a real authorization code at the provider's real token endpoint
/// and returns the raw ID token, so the signature-level tests below have a
/// genuine provider-signed token to work with (and to tamper with).
async fn real_id_token(nonce: &str) -> String {
    let state = random_url_safe_token().unwrap();
    let verifier = random_url_safe_token().unwrap();
    let (code, _) = authorization_code_from_the_real_provider(&state, nonce, &verifier).await;

    let discovery: serde_json::Value = reqwest::get(format!(
        "{}/.well-known/openid-configuration",
        env_or_panic("TEST_OIDC_ISSUER").trim_end_matches('/')
    ))
    .await
    .expect("discovery")
    .json()
    .await
    .expect("discovery json");
    let token_endpoint = discovery["token_endpoint"]
        .as_str()
        .expect("token_endpoint");

    let response: serde_json::Value = reqwest::Client::new()
        .post(token_endpoint)
        .basic_auth(
            env_or_panic("TEST_OIDC_CLIENT_ID"),
            Some(env_or_panic("TEST_OIDC_CLIENT_SECRET")),
        )
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", &env_or_panic("TEST_OIDC_REDIRECT_URL")),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .expect("token endpoint")
        .json()
        .await
        .expect("token response json");

    response["id_token"]
        .as_str()
        .expect("the provider must return an id_token")
        .to_string()
}

// --- The maximum-fidelity case ------------------------------------------

/// The redirect URI is registered with the provider, so its port is fixed
/// and only one test at a time may bind it.
static REDIRECT_PORT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn full_login_flow_end_to_end(backend: Backend) {
    let _guard = REDIRECT_PORT_LOCK.lock().await;
    let h = Harness::new(backend).await;

    let bind_addr = {
        let url = reqwest::Url::parse(&env_or_panic("TEST_OIDC_REDIRECT_URL")).unwrap();
        format!("{}:{}", url.host_str().unwrap(), url.port().unwrap_or(80))
    };
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("binding the registered redirect URI's port");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let router = http::router(h.state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let client_state = Uuid::new_v4().to_string();
    let started = h.start(&client_state).await;

    // The CLI would not have a token yet.
    assert!(h.poll(&started.session_code, &client_state).await.is_none());
    assert!(started.login_url.starts_with(&public_base_url()));
    assert!(
        !started.login_url.contains(&started.session_code),
        "the polling secret must never appear in the browser login URL"
    );

    // THE BROWSER LEG, for real: one request that follows every redirect --
    // our /login route, the provider's authorize endpoint, the provider's
    // redirect back to our /oidc/callback route, and the page it renders.
    let browser = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("browser-like client");
    let response = browser
        .get(&started.login_url)
        .send()
        .await
        .expect("the browser login leg");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "the browser login leg must end on a success page, got {status}: {body}"
    );
    assert!(
        body.contains("signed in"),
        "expected the 'you are signed in' page, got: {body}"
    );

    // The CLI's next poll now gets a real AuthN token.
    let token = h
        .poll(&started.session_code, &client_state)
        .await
        .expect("a completed login must issue a token on the next poll");
    assert!(!token.user_token.is_empty());
    assert!(token.expires_at > 1_000_000_000_000, "milliseconds");
    let user_id = Uuid::parse_str(&token.user_id).expect("user_id must be a principal id");

    // JIT provisioning created exactly one principal, from the provider's
    // `sub`, with the issuer recorded as its `idp`, and NO grants.
    let principal = principals::find_active_principal(&h.db, user_id)
        .await
        .expect("principal lookup")
        .expect("the JIT-provisioned principal");
    assert_eq!(principal.source, PRINCIPAL_SOURCE_OIDC);
    assert_eq!(principal.idp.as_deref(), Some(h.provider.issuer()));
    assert!(!principal.subject.is_empty());

    // And the AuthZ exchange, using that AuthN token exactly as the CLI
    // would -- the last hop of the whole flow.
    let mut exchange = Request::new(epic_urc::ExchangeUserTokenForMultiresourceTokenRequest {
        resource_id: vec!["urc-anything".to_string()],
    });
    exchange.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.user_token).parse().unwrap(),
    );
    let authz = h
        .auth_service
        .exchange_user_token_for_multiresource_token(exchange)
        .await
        .expect("exchange")
        .into_inner()
        .token
        .expect("an AuthZ token");

    let key = jsonwebtoken::DecodingKey::from_jwk(&h.auth_service.signing_keys.active().public_jwk)
        .unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&audience());
    let claims = jsonwebtoken::decode::<lore_authz_core::claims::AuthzClaims>(
        &authz.user_token,
        &key,
        &validation,
    )
    .expect("the AuthZ token must verify")
    .claims;

    // The two claims that decide whether lore accepts this token at all.
    assert_eq!(
        claims.idp,
        h.provider.issuer(),
        "`idp` must name the identity provider that actually authenticated this user"
    );
    assert_eq!(claims.env, TOKEN_ENV);
    // A freshly JIT-provisioned principal holds no grants, so the token
    // authorizes nothing -- provisioning creates an identity, never access.
    assert_eq!(
        claims.resources.expect("resources must be present").len(),
        0
    );

    let _ = shutdown_tx.send(());
    let _ = server.await;
}

#[tokio::test]
async fn full_login_flow_end_to_end_through_the_real_http_server_postgres() {
    full_login_flow_end_to_end(Backend::Postgres).await
}

#[tokio::test]
async fn full_login_flow_end_to_end_through_the_real_http_server_sqlite() {
    full_login_flow_end_to_end(Backend::Sqlite).await
}

// --- Callback validation, driven with real provider responses ------------

async fn callback_with_an_unknown_state_is_rejected(backend: Backend) {
    let h = Harness::new(backend).await;
    let client_state = Uuid::new_v4().to_string();
    let started = h.start(&client_state).await;

    // A real authorization code from the real provider, but obtained under
    // a `state` this service never issued -- the login-CSRF shape.
    let attacker_state = random_url_safe_token().unwrap();
    let (code, echoed_state) = authorization_code_from_the_real_provider(
        &attacker_state,
        &random_url_safe_token().unwrap(),
        &random_url_safe_token().unwrap(),
    )
    .await;
    assert_eq!(echoed_state, attacker_state);

    let outcome =
        oidc_login::complete_callback(&h.db, &h.provider, &h.login_settings, &code, &echoed_state)
            .await
            .expect("the callback must not error on a hostile input");
    assert!(
        matches!(outcome, CallbackOutcome::Invalid),
        "an unrecognized state must never complete a login, got {outcome:?}"
    );

    // The real session is untouched and still pending.
    assert!(h.poll(&started.session_code, &client_state).await.is_none());
}

#[tokio::test]
async fn callback_with_an_unknown_state_is_rejected_postgres() {
    callback_with_an_unknown_state_is_rejected(Backend::Postgres).await
}

#[tokio::test]
async fn callback_with_an_unknown_state_is_rejected_sqlite() {
    callback_with_an_unknown_state_is_rejected(Backend::Sqlite).await
}

async fn callback_with_a_mismatched_nonce_is_rejected(backend: Backend) {
    let h = Harness::new(backend).await;
    let client_state = Uuid::new_v4().to_string();
    let started = h.start(&client_state).await;
    let session = h.session_transients(&started.login_url).await;

    // Everything real and correct EXCEPT the nonce: the session's own
    // `state` and PKCE verifier are used, so the code exchange itself
    // succeeds and the ID token is genuinely signed by the provider. Only
    // the replay-protection check can catch this.
    let (code, echoed_state) = authorization_code_from_the_real_provider(
        &session.oidc_state,
        "a-nonce-this-session-never-issued",
        &session.pkce_verifier,
    )
    .await;
    assert_eq!(echoed_state, session.oidc_state);

    let outcome =
        oidc_login::complete_callback(&h.db, &h.provider, &h.login_settings, &code, &echoed_state)
            .await
            .expect("the callback must not error on a hostile input");
    assert!(
        matches!(outcome, CallbackOutcome::Invalid),
        "a mismatched nonce must never complete a login, got {outcome:?}"
    );
    assert!(h.poll(&started.session_code, &client_state).await.is_none());
}

#[tokio::test]
async fn callback_with_a_mismatched_nonce_is_rejected_postgres() {
    callback_with_a_mismatched_nonce_is_rejected(Backend::Postgres).await
}

#[tokio::test]
async fn callback_with_a_mismatched_nonce_is_rejected_sqlite() {
    callback_with_a_mismatched_nonce_is_rejected(Backend::Sqlite).await
}

async fn a_replayed_callback_cannot_complete_a_session_twice(backend: Backend) {
    let h = Harness::new(backend).await;
    let client_state = Uuid::new_v4().to_string();
    let started = h.start(&client_state).await;
    let session = h.session_transients(&started.login_url).await;

    let (code, echoed_state) = authorization_code_from_the_real_provider(
        &session.oidc_state,
        &session.oidc_nonce,
        &session.pkce_verifier,
    )
    .await;

    let first =
        oidc_login::complete_callback(&h.db, &h.provider, &h.login_settings, &code, &echoed_state)
            .await
            .expect("callback");
    assert!(matches!(first, CallbackOutcome::Completed));

    // The identical callback again. The session is no longer pending, so
    // this must not complete anything -- and it must not error either, since
    // a duplicated browser request is ordinary, not hostile.
    let second =
        oidc_login::complete_callback(&h.db, &h.provider, &h.login_settings, &code, &echoed_state)
            .await
            .expect("callback");
    assert!(
        matches!(second, CallbackOutcome::Invalid),
        "a replayed callback must not re-complete a session, got {second:?}"
    );

    // And the login itself still works exactly once.
    assert!(h.poll(&started.session_code, &client_state).await.is_some());
    assert!(h.poll(&started.session_code, &client_state).await.is_none());
}

#[tokio::test]
async fn a_replayed_callback_cannot_complete_a_session_twice_postgres() {
    a_replayed_callback_cannot_complete_a_session_twice(Backend::Postgres).await
}

#[tokio::test]
async fn a_replayed_callback_cannot_complete_a_session_twice_sqlite() {
    a_replayed_callback_cannot_complete_a_session_twice(Backend::Sqlite).await
}

/// With JIT provisioning off, an identity the provider vouches for but that
/// has no principal here must NOT be able to log in, and must not leave a
/// principal row behind.
async fn jit_disabled_denies_an_unknown_identity(backend: Backend) {
    let h = Harness::with_jit(backend, false).await;
    let client_state = Uuid::new_v4().to_string();
    let started = h.start(&client_state).await;
    let session = h.session_transients(&started.login_url).await;

    let (code, echoed_state) = authorization_code_from_the_real_provider(
        &session.oidc_state,
        &session.oidc_nonce,
        &session.pkce_verifier,
    )
    .await;

    let outcome =
        oidc_login::complete_callback(&h.db, &h.provider, &h.login_settings, &code, &echoed_state)
            .await
            .expect("callback");
    assert!(
        matches!(outcome, CallbackOutcome::Invalid),
        "an unprovisioned identity must be denied when JIT is off, got {outcome:?}"
    );
    assert!(h.poll(&started.session_code, &client_state).await.is_none());
}

#[tokio::test]
async fn jit_disabled_denies_an_unknown_identity_postgres() {
    jit_disabled_denies_an_unknown_identity(Backend::Postgres).await
}

#[tokio::test]
async fn jit_disabled_denies_an_unknown_identity_sqlite() {
    jit_disabled_denies_an_unknown_identity(Backend::Sqlite).await
}

/// A second login for the same identity must reuse the SAME principal, not
/// create a parallel one -- otherwise every login would silently orphan the
/// grants an operator attached to the previous row.
async fn a_second_login_reuses_the_same_principal(backend: Backend) {
    let h = Harness::new(backend).await;

    let mut ids = Vec::new();
    for _ in 0..2 {
        let client_state = Uuid::new_v4().to_string();
        let started = h.start(&client_state).await;
        let session = h.session_transients(&started.login_url).await;
        let (code, echoed_state) = authorization_code_from_the_real_provider(
            &session.oidc_state,
            &session.oidc_nonce,
            &session.pkce_verifier,
        )
        .await;
        let outcome = oidc_login::complete_callback(
            &h.db,
            &h.provider,
            &h.login_settings,
            &code,
            &echoed_state,
        )
        .await
        .expect("callback");
        assert!(matches!(outcome, CallbackOutcome::Completed));
        let token = h
            .poll(&started.session_code, &client_state)
            .await
            .expect("token");
        ids.push(token.user_id);
    }

    assert_eq!(
        ids[0], ids[1],
        "the same identity provider subject must always resolve to the same principal"
    );
}

#[tokio::test]
async fn a_second_login_reuses_the_same_principal_postgres() {
    a_second_login_reuses_the_same_principal(Backend::Postgres).await
}

#[tokio::test]
async fn a_second_login_reuses_the_same_principal_sqlite() {
    a_second_login_reuses_the_same_principal(Backend::Sqlite).await
}

// --- ID token verification, against a REAL provider-signed token ---------
//
// These need no database: they are about the token, not the session.

/// The positive control for the three negatives below: a genuine,
/// provider-signed ID token with the right nonce IS accepted. Without this,
/// a verifier that rejected everything would pass all of them.
#[tokio::test]
async fn a_real_provider_signed_id_token_is_accepted() {
    let nonce = random_url_safe_token().unwrap();
    let id_token = real_id_token(&nonce).await;
    let identity = provider()
        .verify_id_token(&id_token, &nonce)
        .await
        .expect("a genuine ID token with the right nonce must verify");
    assert!(
        !identity.subject.is_empty(),
        "a verified identity must carry the provider's subject"
    );
}

/// A REAL provider-signed token with ONE byte flipped in its signature. This
/// is the case that proves signature verification is actually happening
/// rather than being implied by the happy path.
#[tokio::test]
async fn an_id_token_with_a_tampered_signature_is_rejected() {
    let nonce = random_url_safe_token().unwrap();
    let id_token = real_id_token(&nonce).await;

    let (body, signature) = id_token.rsplit_once('.').expect("a JWT has three parts");
    // Flip one character of the base64url signature to a different, still
    // valid base64url character -- so the token still PARSES and only the
    // signature check can reject it.
    let mut sig: Vec<char> = signature.chars().collect();
    let last = sig.len() - 1;
    sig[last] = if sig[last] == 'A' { 'B' } else { 'A' };
    let tampered = format!("{body}.{}", sig.into_iter().collect::<String>());
    assert_ne!(tampered, id_token);

    assert!(
        provider().verify_id_token(&tampered, &nonce).await.is_err(),
        "a token whose signature does not verify must be rejected"
    );
}

/// A well-formed token, correct issuer and audience, correct nonce, signed
/// by a key the provider does not publish. The `kid` lookup must fail rather
/// than any part of the token's contents being trusted.
#[tokio::test]
async fn an_id_token_signed_by_a_key_the_provider_does_not_publish_is_rejected() {
    let nonce = random_url_safe_token().unwrap();
    let keys = SigningKeyStore::load("file:///epic-lore-authz-oidc-forgery-key-does-not-exist.der")
        .expect("an ephemeral key that is definitely not the provider's");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = serde_json::json!({
        "iss": env_or_panic("TEST_OIDC_ISSUER"),
        "aud": env_or_panic("TEST_OIDC_CLIENT_ID"),
        "sub": "a-subject-the-attacker-chose",
        "exp": now + 3600,
        "iat": now,
        "nonce": nonce,
        "email": "attacker@example.com",
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(keys.active().kid.clone());
    let forged = jsonwebtoken::encode(&header, &claims, &keys.active().encoding_key)
        .expect("forging a token is easy; having it accepted must not be");

    assert!(
        provider().verify_id_token(&forged, &nonce).await.is_err(),
        "a token signed by a key the provider does not publish must be rejected"
    );
}

/// The replay guard, at the token level: a genuine token whose nonce is not
/// the one bound to this login must be refused even though everything else
/// about it is valid.
#[tokio::test]
async fn a_real_id_token_with_the_wrong_nonce_is_rejected() {
    let nonce = random_url_safe_token().unwrap();
    let id_token = real_id_token(&nonce).await;

    assert!(
        provider()
            .verify_id_token(&id_token, "a-different-nonce")
            .await
            .is_err(),
        "an ID token whose nonce was not bound to this session must be rejected"
    );
    // And the empty-expectation case, which must not be treated as "nothing
    // to compare".
    assert!(provider().verify_id_token(&id_token, "").await.is_err());
}
