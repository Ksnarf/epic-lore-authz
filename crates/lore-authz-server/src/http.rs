//! HTTP surface: JWKS, browser login flow, OIDC/SAML callbacks, health.
//! Routes match the component diagram in docs/architecture.md. Every
//! handler beyond health/readiness is a stub returning 501 with a comment
//! naming the delivery phase; see tasks.md.

use axum::Json;
use axum::Router;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::get;
use axum::routing::post;
use serde_json::Value;
use serde_json::json;

pub fn router() -> Router {
    Router::new()
        // lore-server fetches this. Phase 0: return the real JWKS document
        // built from whatever signing keys are currently Pending/Active.
        // Stubbed here as an empty key set -- NOT a valid JWKS for any real
        // verifier, placeholder shape only.
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
}

// Trivial liveness/readiness probe. Safe to implement for real: it carries
// no domain logic, unlike everything else in this file.
async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

// Placeholder JWKS document. A real implementation reads Pending + Active
// (+ recently Retired) signing keys from storage and serializes each as a
// JWK with BOTH `kid` and `alg` set -- omitting `alg` on even one key fails
// the ENTIRE key set load on the lore-server side. See docs/protocol-notes.md.
async fn jwks() -> Json<Value> {
    // TODO(phase 0): read real keys. Empty key set is a placeholder shape,
    // not a functioning JWKS.
    Json(json!({ "keys": [] }))
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
