//! epic-lore-authz: the sidecar binary. Runs a gRPC listener (UrcAuthApi +
//! RebacApi) and an HTTP listener (JWKS, login, OIDC/SAML callbacks, health)
//! in the same process. See docs/architecture.md for the full component
//! diagram and docs/protocol-notes.md before touching anything claim- or
//! JWKS-shaped.
//!
//! SCAFFOLD NOTE: every gRPC RPC and most HTTP handlers beyond
//! health/readiness/JWKS still return "not implemented" -- see tasks.md for
//! the phased plan that fills these in (`ExchangeUserTokenForMultiresourceToken`
//! and friends). The signing key and JWKS document are real as of this
//! pass; see `lore_authz_server::signing`.

use std::sync::Arc;

use anyhow::Context;
use lore_authz_proto::RebacApiServer;
use lore_authz_proto::UrcAuthApiServer;
use lore_authz_server::config::Config;
use lore_authz_server::db::Db;
use lore_authz_server::grpc::AuthApiService;
use lore_authz_server::grpc::RebacApiService;
use lore_authz_server::http;
use lore_authz_server::http::AppState;
use lore_authz_server::oidc::OidcConfig;
use lore_authz_server::oidc::OidcProvider;
use lore_authz_server::oidc_login::OidcLoginSettings;
use lore_authz_server::signing::SigningKeyStore;
use tower_http::trace::DefaultMakeSpan;
use tower_http::trace::DefaultOnRequest;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing::info;
use tracing::warn;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env().context("loading configuration from environment")?;

    let signing_keys = Arc::new(
        SigningKeyStore::load(&config.signing_key_source).context("loading SIGNING_KEY_SOURCE")?,
    );
    info!(
        kid = %signing_keys.active().kid,
        alg = "ES256",
        "signing key ready (see startup log above for whether this is the \
         configured key or a generated ephemeral dev key)"
    );

    // PHASE 1a (see tasks.md): LookupUserPermissions, CheckUserPermission,
    // and RebacApi::CreateResource/DeleteResource are database-backed,
    // against either Postgres (multi-replica, required behind a load
    // balancer) or SQLite (dev/single-instance ONLY -- its single-writer
    // lock makes it wrong behind a load balancer), selected at runtime from
    // DATABASE_URL's scheme -- see lore_authz_server::db's module doc
    // comment and docs/configuration.md. If DATABASE_URL is not configured,
    // those four RPCs fail closed with Status::failed_precondition (see
    // AuthApiService::require_db / RebacApiService::require_db in grpc.rs)
    // rather than the process refusing to start -- HealthCheck, JWKS, and
    // the still-stubbed Phase 1b RPCs have no database dependency at all. A
    // DATABASE_URL that IS set but unreachable, or a DB_SCHEMA that fails
    // validation (Postgres only), is a startup failure (bail), not a silent
    // degrade: a misconfigured value an operator believes is live must not
    // fail quietly.
    let db = if config.database_url.is_empty() {
        warn!(
            "DATABASE_URL is not set: LookupUserPermissions, CheckUserPermission, and RebacApi \
             will fail closed with FailedPrecondition until it is configured -- see \
             docs/configuration.md"
        );
        None
    } else {
        let db = Db::connect(&config.database_url, &config.db_schema)
            .await
            .context(
                "connecting to the database / applying migrations (DATABASE_URL, DB_SCHEMA)",
            )?;
        info!(
            backend = db.backend_name(),
            schema = %db.schema(),
            "connected to the database and applied migrations"
        );
        Some(Arc::new(db))
    };

    // Security review remediation (see tasks.md, docs/open-questions.md
    // Q6): RebacApi::CreateResource/DeleteResource fail closed with
    // Status::unauthenticated on every call when REBAC_SERVICE_TOKEN is not
    // set, exactly like the DATABASE_URL warning above -- an operator who
    // has not configured this should see it in the startup log, not
    // discover it as a silent "everything is denied" surprise (or, worse,
    // never discover the ALTERNATIVE: an unconfigured gate that defaults to
    // allow).
    if config.rebac_service_token.is_none() {
        warn!(
            "REBAC_SERVICE_TOKEN is not set: RebacApi::CreateResource/DeleteResource will deny \
             every caller with Unauthenticated until it is configured -- see \
             docs/configuration.md"
        );
    }

    // The admin surface (/admin/v1 + /admin/ui on the HTTP listener) is
    // gated on ADMIN_API_TOKEN and fails closed: unset means every admin
    // request is denied with 401. Logged either way, because "the admin
    // surface denies everything" and "the admin surface is live" are both
    // facts an operator must be able to read out of the startup log rather
    // than discover by probing. The token itself is never logged, and
    // `Config`'s Debug impl redacts it (see config.rs).
    let admin_api_token = config.admin_api_token.clone().map(Arc::new);
    match admin_api_token {
        Some(_) => info!(
            "admin surface ENABLED at /admin/v1 (JSON API) and /admin/ui (panel) on the HTTP \
             listener, gated on ADMIN_API_TOKEN -- restrict the /admin path at your reverse \
             proxy as well, see docs/configuration.md"
        ),
        None => warn!(
            "ADMIN_API_TOKEN is not set: every /admin request will be DENIED with 401 until it \
             is configured. Provisioning principals, groups and grants is impossible without \
             it -- see docs/configuration.md"
        ),
    }

    // PHASE 1b (see tasks.md): token/session knobs for the login and
    // exchange RPCs. `public_base_url` being empty is a real, denied state,
    // not a benign default -- StartAuthSession refuses to issue a login URL
    // it cannot construct, so say so at startup rather than at the first
    // login attempt.
    let login_settings = lore_authz_server::login::LoginSettings {
        token_env: config.token_env.clone(),
        authn_token_ttl_secs: config.authn_token_ttl_secs,
        authz_token_ttl_secs: config.authz_token_ttl_secs,
        session_ttl_secs: config.auth_session_ttl_secs,
        public_base_url: config.public_base_url.clone(),
        default_idp: config.token_idp.clone(),
    };
    if login_settings.public_base_url.is_empty() {
        warn!(
            "PUBLIC_BASE_URL is not set (and no origin could be derived from OIDC_REDIRECT_URL): \
             StartAuthSession will deny with FailedPrecondition because it cannot build a browser \
             login URL -- see docs/configuration.md"
        );
    }

    // PHASE 1b: the identity provider. ALL FOUR settings are required
    // together -- a partially configured provider is treated as
    // unconfigured, and an unconfigured provider makes StartAuthSession and
    // both browser login routes DENY. There is deliberately no degraded mode
    // in which a login half-works.
    //
    // A provider that IS configured but unreachable is NOT a startup
    // failure: discovery is lazy and cached, so an IdP that is briefly down
    // (or that comes up after this process) costs a failed login, not a
    // crash loop. That is the opposite trade-off from DATABASE_URL above,
    // and deliberately so: this service is the thing lore-server itself
    // blocks on at ITS boot (see docs/protocol-notes.md section 4).
    let oidc = match (
        config.oidc_issuer_url.as_deref(),
        config.oidc_client_id.as_deref(),
        config.oidc_client_secret.as_deref(),
        config.oidc_redirect_url.as_deref(),
    ) {
        (Some(issuer), Some(client_id), Some(client_secret), Some(redirect_url)) => {
            let provider = OidcProvider::new(OidcConfig {
                issuer: issuer.to_string(),
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                redirect_url: redirect_url.to_string(),
                scopes: config.oidc_scopes.clone(),
            })
            .context("building the OIDC provider (OIDC_* settings)")?;
            info!(
                issuer,
                jit_provisioning = config.oidc_jit_provisioning,
                "OIDC identity provider configured (discovery happens lazily on first login)"
            );
            Some(Arc::new(provider))
        }
        _ => {
            warn!(
                "OIDC is not fully configured (OIDC_ISSUER_URL, OIDC_CLIENT_ID, \
                 OIDC_CLIENT_SECRET and OIDC_REDIRECT_URL are all required together): \
                 StartAuthSession and the browser login routes will DENY every request until \
                 they are -- see docs/configuration.md"
            );
            None
        }
    };
    let oidc_login_settings = OidcLoginSettings {
        jit_provisioning: config.oidc_jit_provisioning,
    };

    info!(
        grpc = %config.grpc_listen_addr,
        http = %config.http_listen_addr,
        "epic-lore-authz starting (Phase 1a: LookupUserPermissions/CheckUserPermission/RebacApi \
         are real; see tasks.md for what remains stubbed)"
    );

    // Log every inbound gRPC call (method path on the span's `uri` field) at
    // INFO. This is dev/test instrumentation, not policy: it makes the
    // sidecar's own logs correlatable with lore-server's during integration
    // testing. Failing-closed stubs are unaffected -- this only observes
    // traffic.
    let grpc_server = tonic::transport::Server::builder()
        .layer(
            TraceLayer::new_for_grpc()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO)),
        )
        .add_service(UrcAuthApiServer::new(AuthApiService {
            db: db.clone(),
            signing_keys: signing_keys.clone(),
            jwt_issuer: config.jwt_issuer.clone(),
            jwt_audience: config.jwt_audience.clone(),
            login: login_settings.clone(),
            oidc: oidc.clone(),
        }))
        .add_service(RebacApiServer::new(RebacApiService {
            db: db.clone(),
            rebac_service_token: config.rebac_service_token.clone(),
        }))
        .serve(config.grpc_listen_addr);

    let app_state = AppState {
        signing_keys,
        db: db.clone(),
        oidc,
        oidc_login: oidc_login_settings,
        admin_api_token,
    };
    let http_server = async {
        let listener = tokio::net::TcpListener::bind(config.http_listen_addr).await?;
        axum::serve(listener, http::router(app_state)).await
    };

    tokio::select! {
        result = grpc_server => result.context("grpc server exited")?,
        result = http_server => result.context("http server exited")?,
    }

    Ok(())
}
