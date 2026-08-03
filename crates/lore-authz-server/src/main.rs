//! epic-lore-authz: the sidecar binary. Runs a gRPC listener (UrcAuthApi +
//! RebacApi) and an HTTP listener (JWKS, login, OIDC/SAML callbacks, health)
//! in the same process. See docs/architecture.md for the full component
//! diagram and docs/protocol-notes.md before touching anything claim- or
//! JWKS-shaped.
//!
//! SCAFFOLD NOTE: every RPC and HTTP handler beyond health/readiness/JWKS-
//! shape currently returns "not implemented". This binary starts and serves
//! traffic; it does not yet authenticate anyone. See tasks.md for the
//! phased plan that fills these in.

mod config;
mod grpc;
mod http;

use anyhow::Context;
use lore_authz_proto::RebacApiServer;
use lore_authz_proto::UrcAuthApiServer;
use tracing::info;

use crate::config::Config;
use crate::grpc::AuthApiService;
use crate::grpc::RebacApiService;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env().context("loading configuration from environment")?;

    info!(
        grpc = %config.grpc_listen_addr,
        http = %config.http_listen_addr,
        "epic-lore-authz starting (scaffold: RPCs are not yet implemented)"
    );

    let grpc_server = tonic::transport::Server::builder()
        .add_service(UrcAuthApiServer::new(AuthApiService))
        .add_service(RebacApiServer::new(RebacApiService))
        .serve(config.grpc_listen_addr);

    let http_server = async {
        let listener = tokio::net::TcpListener::bind(config.http_listen_addr).await?;
        axum::serve(listener, http::router()).await
    };

    tokio::select! {
        result = grpc_server => result.context("grpc server exited")?,
        result = http_server => result.context("http server exited")?,
    }

    Ok(())
}
