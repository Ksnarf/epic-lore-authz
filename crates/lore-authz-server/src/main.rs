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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env().context("loading configuration from environment")?;

    let signing_keys =
        SigningKeyStore::load(&config.signing_key_source).context("loading SIGNING_KEY_SOURCE")?;
    info!(
        kid = %signing_keys.active().kid,
        alg = "ES256",
        "signing key ready (see startup log above for whether this is the \
         configured key or a generated ephemeral dev key)"
    );

    info!(
        grpc = %config.grpc_listen_addr,
        http = %config.http_listen_addr,
        "epic-lore-authz starting (scaffold: most RPCs are not yet implemented, see tasks.md)"
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
        .add_service(UrcAuthApiServer::new(AuthApiService))
        .add_service(RebacApiServer::new(RebacApiService))
        .serve(config.grpc_listen_addr);

    let app_state = AppState {
        signing_keys: Arc::new(signing_keys),
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
