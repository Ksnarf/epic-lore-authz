//! The JSON half of the admin surface (`/admin/v1/...`), for scripting and
//! automation. Every handler is a thin wrapper: extract, call
//! `crate::admin::ops`, serialize. No validation and no database access
//! happens here -- see `ops`' module doc comment for why that separation is
//! load-bearing rather than tidy.
//!
//! ## Wire shapes are declared here, not derived from domain types
//!
//! `lore_authz_core::model::Principal` is `Serialize`, and using it directly
//! would be shorter. It is deliberately not used: its `status` field is a
//! Rust enum that serializes as `"Active"`, while the value this API ACCEPTS
//! on `POST /admin/v1/principals/{id}/status`, and the value the database
//! stores, is `"active"`. An API whose output cannot be fed back into its own
//! input is a bug generator, so the view types below pin the lowercase form
//! that matches the database, and they change only when someone changes them
//! on purpose.

use axum::Json;
use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use lore_authz_core::model::Principal;
use lore_authz_core::model::PrincipalStatus;
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

use crate::admin::AdminError;
use crate::admin::ops;
use crate::admin::ops::Listing;
use crate::admin::ops::NewGrantInput;
use crate::admin::ops::NewPrincipalInput;
use crate::db::groups::GroupSummary;
use crate::db::permissions::GrantSummary;
use crate::db::permissions::RoleSummary;
use crate::db::resources::ResourceSummary;
use crate::http::AppState;

/// `{ "items": [...], "truncated": bool }` for every list endpoint. Uniform
/// on purpose: a caller writing a script against one list endpoint should not
/// discover that another returns a bare array. `truncated` is what makes
/// `crate::admin::LIST_LIMIT` honest rather than silent.
#[derive(Serialize)]
struct ListResponse<T> {
    items: Vec<T>,
    truncated: bool,
}

impl<T, U: From<T>> From<Listing<T>> for ListResponse<U> {
    fn from(listing: Listing<T>) -> Self {
        ListResponse {
            items: listing.items.into_iter().map(U::from).collect(),
            truncated: listing.truncated,
        }
    }
}

#[derive(Serialize)]
pub struct PrincipalView {
    id: Uuid,
    subject: String,
    external_id: Option<String>,
    source: String,
    email: Option<String>,
    display_name: String,
    preferred_username: String,
    is_service_account: bool,
    /// Lowercase, matching the database and this API's own input -- see the
    /// module doc comment.
    status: &'static str,
    idp: Option<String>,
}

impl From<Principal> for PrincipalView {
    fn from(principal: Principal) -> Self {
        PrincipalView {
            id: principal.id,
            subject: principal.subject,
            external_id: principal.external_id,
            source: principal.source,
            email: principal.email,
            display_name: principal.display_name,
            preferred_username: principal.preferred_username,
            is_service_account: principal.is_service_account,
            status: status_str(&principal.status),
            idp: principal.idp,
        }
    }
}

/// The database's own spelling of a status. Used by both front ends, so the
/// panel and the API cannot disagree about what a suspended principal looks
/// like.
pub fn status_str(status: &PrincipalStatus) -> &'static str {
    match status {
        PrincipalStatus::Active => "active",
        PrincipalStatus::Suspended => "suspended",
        PrincipalStatus::Deprovisioned => "deprovisioned",
    }
}

#[derive(Serialize)]
pub struct GroupView {
    id: Uuid,
    name: String,
    description: Option<String>,
    source: String,
    status: String,
}

impl From<GroupSummary> for GroupView {
    fn from(group: GroupSummary) -> Self {
        GroupView {
            id: group.id,
            name: group.name,
            description: group.description,
            source: group.source,
            status: group.status,
        }
    }
}

#[derive(Serialize)]
pub struct MemberView {
    principal_id: Uuid,
    display_name: String,
}

impl From<(Uuid, String)> for MemberView {
    fn from((principal_id, display_name): (Uuid, String)) -> Self {
        MemberView {
            principal_id,
            display_name,
        }
    }
}

#[derive(Serialize)]
pub struct ResourceView {
    resource_id: String,
    resource_name: String,
    /// Soft-deleted rows are listed, flagged, never hidden -- see
    /// `db::resources::list_resources`.
    deleted: bool,
}

impl From<ResourceSummary> for ResourceView {
    fn from(resource: ResourceSummary) -> Self {
        ResourceView {
            resource_id: resource.resource_id,
            resource_name: resource.resource_name,
            deleted: resource.deleted,
        }
    }
}

#[derive(Serialize)]
pub struct RoleView {
    id: Uuid,
    name: String,
    permissions: Vec<String>,
}

impl From<RoleSummary> for RoleView {
    fn from(role: RoleSummary) -> Self {
        RoleView {
            id: role.id,
            name: role.name,
            permissions: role.permissions,
        }
    }
}

#[derive(Serialize)]
pub struct GrantView {
    id: Uuid,
    role_id: Uuid,
    role_name: String,
    resource_pattern: String,
    principal_kind: String,
    principal_id: Uuid,
}

impl From<GrantSummary> for GrantView {
    fn from(grant: GrantSummary) -> Self {
        GrantView {
            id: grant.id,
            role_id: grant.role_id,
            role_name: grant.role_name,
            resource_pattern: grant.resource_pattern,
            principal_kind: grant.principal_kind,
            principal_id: grant.principal_id,
        }
    }
}

// --- principals ----------------------------------------------------------

pub async fn list_principals(State(state): State<AppState>) -> Result<Response, AdminError> {
    let listing = ops::list_principals(state.db.as_deref()).await?;
    Ok(Json(ListResponse::<PrincipalView>::from(listing)).into_response())
}

pub async fn get_principal(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AdminError> {
    let id = ops::parse_uuid("principal id", &id)?;
    let principal = ops::get_principal(state.db.as_deref(), id).await?;
    Ok(Json(PrincipalView::from(principal)).into_response())
}

#[derive(Deserialize)]
pub struct CreatePrincipalRequest {
    display_name: String,
    preferred_username: Option<String>,
    email: Option<String>,
    external_id: Option<String>,
    source: Option<String>,
    subject: Option<String>,
    #[serde(default)]
    is_service_account: bool,
    idp: Option<String>,
}

pub async fn create_principal(
    State(state): State<AppState>,
    Json(body): Json<CreatePrincipalRequest>,
) -> Result<Response, AdminError> {
    let principal = ops::create_principal(
        state.db.as_deref(),
        NewPrincipalInput {
            display_name: body.display_name,
            preferred_username: body.preferred_username,
            email: body.email,
            external_id: body.external_id,
            source: body.source,
            subject: body.subject,
            is_service_account: body.is_service_account,
            idp: body.idp,
        },
    )
    .await?;
    Ok((StatusCode::CREATED, Json(PrincipalView::from(principal))).into_response())
}

#[derive(Deserialize)]
pub struct SetStatusRequest {
    status: String,
}

pub async fn set_principal_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SetStatusRequest>,
) -> Result<Response, AdminError> {
    let id = ops::parse_uuid("principal id", &id)?;
    let principal = ops::set_principal_status(state.db.as_deref(), id, &body.status).await?;
    Ok(Json(PrincipalView::from(principal)).into_response())
}

// --- groups --------------------------------------------------------------

pub async fn list_groups(State(state): State<AppState>) -> Result<Response, AdminError> {
    let listing = ops::list_groups(state.db.as_deref()).await?;
    Ok(Json(ListResponse::<GroupView>::from(listing)).into_response())
}

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    name: String,
    description: Option<String>,
}

pub async fn create_group(
    State(state): State<AppState>,
    Json(body): Json<CreateGroupRequest>,
) -> Result<Response, AdminError> {
    let group =
        ops::create_group(state.db.as_deref(), &body.name, body.description.as_deref()).await?;
    Ok((StatusCode::CREATED, Json(GroupView::from(group))).into_response())
}

pub async fn list_group_members(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AdminError> {
    let id = ops::parse_uuid("group id", &id)?;
    let listing = ops::list_group_members(state.db.as_deref(), id).await?;
    Ok(Json(ListResponse::<MemberView>::from(listing)).into_response())
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    principal_id: String,
}

pub async fn add_group_member(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<AddMemberRequest>,
) -> Result<Response, AdminError> {
    let group_id = ops::parse_uuid("group id", &id)?;
    let principal_id = ops::parse_uuid("principal_id", &body.principal_id)?;
    ops::add_group_member(state.db.as_deref(), group_id, principal_id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn remove_group_member(
    State(state): State<AppState>,
    Path((id, principal_id)): Path<(String, String)>,
) -> Result<Response, AdminError> {
    let group_id = ops::parse_uuid("group id", &id)?;
    let principal_id = ops::parse_uuid("principal id", &principal_id)?;
    ops::remove_group_member(state.db.as_deref(), group_id, principal_id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// --- resources -----------------------------------------------------------

pub async fn list_resources(State(state): State<AppState>) -> Result<Response, AdminError> {
    let listing = ops::list_resources(state.db.as_deref()).await?;
    Ok(Json(ListResponse::<ResourceView>::from(listing)).into_response())
}

#[derive(Deserialize)]
pub struct CreateResourceRequest {
    resource_id: String,
    resource_name: Option<String>,
}

pub async fn create_resource(
    State(state): State<AppState>,
    Json(body): Json<CreateResourceRequest>,
) -> Result<Response, AdminError> {
    let resource = ops::create_resource(
        state.db.as_deref(),
        &body.resource_id,
        body.resource_name.as_deref(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(ResourceView::from(resource))).into_response())
}

pub async fn delete_resource(
    State(state): State<AppState>,
    Path(resource_id): Path<String>,
) -> Result<Response, AdminError> {
    ops::delete_resource(state.db.as_deref(), &resource_id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// --- roles and grants ----------------------------------------------------

pub async fn list_roles(State(state): State<AppState>) -> Result<Response, AdminError> {
    let roles = ops::list_roles(state.db.as_deref()).await?;
    // Not a `ListResponse`: the roles are seeded by migration, there are
    // exactly three, and no limit applies -- claiming a `truncated` field
    // here would be noise pretending to be a contract.
    Ok(Json(roles.into_iter().map(RoleView::from).collect::<Vec<_>>()).into_response())
}

pub async fn list_grants(State(state): State<AppState>) -> Result<Response, AdminError> {
    let listing = ops::list_grants(state.db.as_deref()).await?;
    Ok(Json(ListResponse::<GrantView>::from(listing)).into_response())
}

#[derive(Deserialize)]
pub struct CreateGrantRequest {
    /// A role NAME (`"reader"`) or its uuid -- see `ops::NewGrantInput`.
    role: String,
    /// `"urc-*"` or a specific `"urc-<id>"`.
    resource_pattern: String,
    principal_kind: String,
    principal_id: String,
}

pub async fn create_grant(
    State(state): State<AppState>,
    Json(body): Json<CreateGrantRequest>,
) -> Result<Response, AdminError> {
    let principal_id = ops::parse_uuid("principal_id", &body.principal_id)?;
    let (grant, created) = ops::create_grant(
        state.db.as_deref(),
        NewGrantInput {
            role: body.role,
            resource_pattern: body.resource_pattern,
            principal_kind: body.principal_kind,
            principal_id,
        },
    )
    .await?;

    // 201 for a new binding, 200 for one that already existed. Both are
    // successes -- re-granting is not an error -- but an operator scripting
    // this can tell the two apart without diffing a list.
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(GrantView::from(grant))).into_response())
}

pub async fn delete_grant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AdminError> {
    let id = ops::parse_uuid("grant id", &id)?;
    ops::delete_grant(state.db.as_deref(), id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
