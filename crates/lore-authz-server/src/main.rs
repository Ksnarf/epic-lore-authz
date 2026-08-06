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
        }))
        .add_service(RebacApiServer::new(RebacApiService {
            db: db.clone(),
            rebac_service_token: config.rebac_service_token.clone(),
        }))
        .serve(config.grpc_listen_addr);

    let app_state = AppState { signing_keys };
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
