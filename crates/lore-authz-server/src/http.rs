//! HTTP surface: JWKS, browser login flow, OIDC/SAML callbacks, health.
//! Routes match the component diagram in docs/architecture.md. Every
//! handler beyond health/readiness/JWKS is a stub returning 501 with a
//! comment naming the delivery phase; see tasks.md.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::routing::post;
use jsonwebtoken::jwk::JwkSet;
use serde_json::Value;
use serde_json::json;

use crate::signing::SigningKeyStore;

/// Shared state for the HTTP listener. `Arc` because axum clones state per
/// request; `SigningKeyStore` itself holds no interior mutability in Phase 0
/// (single key for the process lifetime -- see signing.rs), so a plain
/// `Arc` is enough.
#[derive(Clone)]
pub struct AppState {
    pub signing_keys: Arc<SigningKeyStore>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        // lore-server fetches this. Real JWKS document built from the
        // currently active signing key (Phase 0: exactly one key; Phase 1
        // adds Pending/Active/Retired rotation, see docs/architecture.md).
        .route("/.well-known/jwks.json", get(jwks))
        // Browser entry point for a pending StartAuthSession. Phase 0:
        // render a stub "Approve as <test user>" page, no real IdP yet.
        .route("/login/{session_code}", get(login_page))
        .route("/login/done", get(login_done))
        // Phase 1: OIDC authorization code callback.
        .route("/oidc/callback", get(unimplemented))
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

async fn login_page(Path(_session_code): Path<String>) -> (StatusCode, &'static str) {
    (
        StatusCode::NOT_IMPLEMENTED,
        "login_page: Phase 0 (see tasks.md) - stub IdP selector / single 'Approve as test user' button",
    )
}

async fn login_done() -> (StatusCode, &'static str) {
    (
        StatusCode::NOT_IMPLEMENTED,
        "login_done: Phase 0 (see tasks.md) - 'you may close this tab' page",
    )
}

async fn unimplemented() -> (StatusCode, &'static str) {
    (
        StatusCode::NOT_IMPLEMENTED,
        "not implemented in this scaffold - see tasks.md for the owning phase",
    )
}
