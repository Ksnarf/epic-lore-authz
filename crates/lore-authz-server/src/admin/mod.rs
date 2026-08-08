//! The admin surface: everything an operator needs to provision identities
//! and grants WITHOUT a database client.
//!
//! ## The gap this closes
//!
//! Before this module existed, every RPC in this product read
//! `principals` / `groups` / `group_members` / `role_bindings`, and nothing
//! could WRITE them. `RebacApi::CreateResource` (called by lore-server)
//! populated `resources`, and the OIDC login leg could JIT-provision a
//! principal -- but a JIT-provisioned principal holds no grants, so the only
//! way to make any of this useful was to insert `role_bindings` rows by hand
//! with `psql` or the `sqlite3` CLI. A product whose sole provisioning
//! interface is "connect to the database as a privileged user and write SQL"
//! is not deployable, and hands every operator a credential far stronger than
//! the task requires.
//!
//! ## Two front ends, ONE set of operations
//!
//! - `api` -- a JSON API under `/admin/v1`, for scripting and automation.
//! - `panel` -- a server-rendered HTML panel at `/admin/ui`, for a human.
//!   No SPA, no JavaScript, no build step: it ships inside the existing
//!   binary because it is `format!`-ed HTML in a Rust function.
//!
//! Both are thin transport wrappers over `ops`, which holds every validation
//! rule and every database call. Neither front end may contain logic the
//! other does not, and neither talks to `crate::db` directly -- so "the panel
//! allows something the API rejects" is not a bug that can be written here.
//!
//! ## Every route is gated, and the gate fails closed
//!
//! See `auth` for the mechanism and the reasoning. In one line:
//! `ADMIN_API_TOKEN` must be configured AND presented as
//! `authorization: Bearer <value>`, or the request is denied -- including
//! when the setting is unset or empty, which denies EVERYTHING rather than
//! defaulting to open.
//!
//! ## Why the whole surface lives under one path prefix
//!
//! `/admin/**` and nothing else, kept clearly apart from the public
//! `/.well-known/jwks.json`, `/login/*` and `/oidc/callback` routes, so a
//! reverse proxy can restrict this surface by path alone (deny `/admin`, or
//! require mTLS/an IP allowlist on it) without an allowlist that has to be
//! kept in step with this file. The bearer token is this service's own gate,
//! not a substitute for that network-level control: see
//! `docs/configuration.md`.
//!
//! ## What is deliberately NOT here
//!
//! - No role CRUD. The three advisory roles (`reader`, `writer`, `admin`)
//!   are seeded by both migration sets and are read-only (`GET
//!   /admin/v1/roles`). Their permission strings are advisory anyway -- the
//!   upstream lore-server does not enforce them (see `docs/protocol-notes.md`)
//!   -- so inventing more of them would create the impression of a
//!   fine-grained model this product does not implement.
//! - No hard delete of a principal or a group, and no `deprovisioned` status.
//!   Suspension is reversible and auditable; a `DELETE` that cascades
//!   `group_members` and `role_bindings` out of existence is neither.
//! - No pagination. Every list endpoint is bounded by `LIST_LIMIT` and says
//!   whether it truncated, which is honest about the limit rather than
//!   pretending to a page cursor it does not have. See tasks.md for the rest
//!   of what this surface does not do.

use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;

use crate::http::AppState;

pub mod api;
pub mod auth;
pub mod ops;
pub mod panel;

/// Hard cap on every admin list response.
///
/// Not pagination: a bounded response plus an explicit `truncated` flag, so a
/// deployment with more principals than this cannot turn a list call into an
/// unbounded query, and an operator can SEE that they are not looking at
/// everything. Filtering/pagination is left for whoever needs it (see
/// tasks.md); silently returning a partial list would be the one unacceptable
/// option.
pub const LIST_LIMIT: i64 = 500;

/// Every failure the admin surface can produce, mapped to exactly one status
/// code each. Deliberately coarse.
///
/// `Internal` NEVER carries the underlying error to the caller: a database
/// error's text names tables, columns and constraints, and this is a
/// provisioning API, not a debugging console. The detail is logged by the
/// `ops` function that produced it.
#[derive(Debug)]
pub enum AdminError {
    /// Operator input this surface refuses: a malformed uuid, an unknown
    /// `principal_kind`, an unsupported resource pattern, an empty name.
    /// The message names the offending FIELD and may quote the operator's own
    /// value back (it came from them, so it discloses nothing they do not
    /// have), never anything from configuration.
    Invalid(String),
    /// The named entity does not exist.
    NotFound(String),
    /// The entity already exists (a duplicate group name, a resource id
    /// already registered). Reported rather than swallowed: an operator must
    /// not believe they created something they did not.
    Conflict(String),
    /// `DATABASE_URL` is not configured, so there is nothing to provision
    /// into. Fails the same way the gRPC handlers do in that situation
    /// (`FailedPrecondition` there, 503 here) rather than pretending an empty
    /// list is the truth.
    DatabaseUnconfigured,
    /// A real database failure. Logged where it happened, generic here.
    Internal,
}

impl AdminError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            AdminError::Invalid(_) => StatusCode::BAD_REQUEST,
            AdminError::NotFound(_) => StatusCode::NOT_FOUND,
            AdminError::Conflict(_) => StatusCode::CONFLICT,
            AdminError::DatabaseUnconfigured => StatusCode::SERVICE_UNAVAILABLE,
            AdminError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Caller-facing text. Safe to render into an HTML page or a JSON body:
    /// it contains only this crate's own literals plus values the caller
    /// itself supplied.
    pub fn message(&self) -> String {
        match self {
            AdminError::Invalid(detail)
            | AdminError::NotFound(detail)
            | AdminError::Conflict(detail) => detail.clone(),
            AdminError::DatabaseUnconfigured => {
                "this service has no DATABASE_URL configured, so there is nothing to provision \
                 -- see docs/configuration.md"
                    .to_string()
            }
            AdminError::Internal => "internal error".to_string(),
        }
    }

    /// Maps a `sqlx` error, logging the detail and returning the generic
    /// variant. One function so no call site can accidentally let a database
    /// error's text reach a caller.
    pub fn from_db(context: &'static str, err: sqlx::Error) -> Self {
        tracing::warn!(error = %err, context, "admin database operation failed");
        AdminError::Internal
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        (
            self.status_code(),
            axum::Json(serde_json::json!({ "error": self.message() })),
        )
            .into_response()
    }
}

/// The admin router, mounted by `crate::http::router` at `/admin`.
///
/// `state` is passed in so the gate can be applied with
/// `axum::middleware::from_fn_with_state`; `Router::layer` (rather than
/// `route_layer`) is used deliberately, so the middleware also covers the
/// fallback below and an unauthenticated caller sees the same 401 for a path
/// that does not exist as for one that does.
pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        // --- JSON provisioning API (scripting/automation) ----------------
        .route(
            "/v1/principals",
            get(api::list_principals).post(api::create_principal),
        )
        .route("/v1/principals/{id}", get(api::get_principal))
        .route(
            "/v1/principals/{id}/status",
            post(api::set_principal_status),
        )
        .route("/v1/groups", get(api::list_groups).post(api::create_group))
        .route(
            "/v1/groups/{id}/members",
            get(api::list_group_members).post(api::add_group_member),
        )
        .route(
            "/v1/groups/{id}/members/{principal_id}",
            axum::routing::delete(api::remove_group_member),
        )
        .route(
            "/v1/resources",
            get(api::list_resources).post(api::create_resource),
        )
        .route(
            "/v1/resources/{resource_id}",
            axum::routing::delete(api::delete_resource),
        )
        .route("/v1/roles", get(api::list_roles))
        .route("/v1/grants", get(api::list_grants).post(api::create_grant))
        .route("/v1/grants/{id}", axum::routing::delete(api::delete_grant))
        // --- server-rendered HTML panel (a human with a browser) ---------
        .route("/ui", get(panel::panel))
        .route("/ui/principals", post(panel::create_principal))
        .route("/ui/principals/status", post(panel::set_principal_status))
        .route("/ui/groups", post(panel::create_group))
        .route("/ui/groups/members/add", post(panel::add_group_member))
        .route(
            "/ui/groups/members/remove",
            post(panel::remove_group_member),
        )
        .route("/ui/resources", post(panel::create_resource))
        .route("/ui/resources/delete", post(panel::delete_resource))
        .route("/ui/grants", post(panel::create_grant))
        .route("/ui/grants/delete", post(panel::delete_grant))
        .fallback(not_found)
        .layer(axum::middleware::from_fn_with_state(
            state,
            auth::require_admin,
        ))
}

/// Unknown `/admin/**` path. Reached only by an ALREADY-AUTHENTICATED caller,
/// because the gate is applied with `Router::layer` above.
async fn not_found() -> Response {
    AdminError::NotFound("no such admin route -- see docs/configuration.md".to_string())
        .into_response()
}
