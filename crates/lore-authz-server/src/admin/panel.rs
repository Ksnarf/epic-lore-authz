//! The HTML half of the admin surface (`/admin/ui`): a server-rendered
//! operator panel, in the same binary, with no JavaScript, no stylesheet, no
//! image, no font, and no build step of any kind. It is `format!`-ed HTML in
//! a Rust function, for the same reason the login pages in `crate::http` are:
//! a page an operator opens to manage authorization must not depend on
//! fetching anything from anywhere.
//!
//! ## How an operator reaches it, honestly
//!
//! Every route here is behind the same bearer-token gate as the JSON API (see
//! `crate::admin::auth`) -- there is no cookie, no session, and no
//! second, weaker way in. A browser cannot attach an `Authorization` header
//! to an address-bar navigation on its own, so this panel is reached through
//! whatever already fronts `/admin` in the deployment: a reverse proxy that
//! injects the header (the same proxy that should be restricting this path by
//! IP or mTLS anyway), or any client that can set a header. See
//! `docs/configuration.md` for a worked example.
//!
//! That is a deliberate trade, stated rather than papered over: the
//! alternative -- a login form that puts the admin token in a cookie or a
//! hidden field -- would add a second credential path into a surface that can
//! mint authority, to save an operator one line of proxy configuration.
//!
//! ## POST-then-redirect on success, re-render on failure
//!
//! A successful form POST answers `303 See Other` back to `/admin/ui?msg=...`
//! where `msg` is one of a FIXED set of codes (`NOTICES`); an unrecognized
//! code renders nothing at all. Nothing an operator (or anyone else) types is
//! ever reflected out of a query string into the page. Refreshing after a
//! success therefore re-runs a GET, not the create.
//!
//! A FAILED POST re-renders the panel in place, carrying the error's own
//! message and status code, because the operator needs the detail and there
//! is nothing to re-submit accidentally: it failed.
//!
//! ## Escaping
//!
//! Every value interpolated into this page goes through `esc`, including
//! values that "cannot" contain markup. `panel_escapes_operator_controlled_
//! text` in `tests/authz_suite/mod.rs` creates a principal whose display name
//! is a `<script>` tag through the real API and asserts the rendered page
//! carries it escaped -- an admin panel that executed script from a
//! provisioning field would hand the admin token to whoever set that field,
//! since the panel is opened by exactly the person who holds it.

use axum::Form;
use axum::extract::Query;
use axum::extract::State;
use axum::response::Html;
use axum::response::IntoResponse;
use axum::response::Redirect;
use axum::response::Response;
use serde::Deserialize;
use uuid::Uuid;

use crate::admin::AdminError;
use crate::admin::ops;
use crate::admin::ops::NewGrantInput;
use crate::admin::ops::NewPrincipalInput;
use crate::admin::ops::SETTABLE_STATUSES;
use crate::db::permissions::PRINCIPAL_KINDS;
use crate::db::permissions::WILDCARD_RESOURCE_PATTERN;
use crate::http::AppState;

/// The complete set of success notices. A `msg` query value not in this table
/// renders nothing -- this is a lookup, never a reflection, so the query
/// string cannot become an injection vector or a phishing surface.
const NOTICES: [(&str, &str); 10] = [
    ("principal-created", "Principal created."),
    ("status-updated", "Principal status updated."),
    ("group-created", "Group created."),
    ("member-added", "Member added to group."),
    ("member-removed", "Member removed from group."),
    ("resource-created", "Resource registered."),
    ("resource-deleted", "Resource deleted (soft delete)."),
    ("grant-created", "Grant created."),
    (
        "grant-exists",
        "That grant already existed; nothing changed.",
    ),
    ("grant-deleted", "Grant revoked."),
];

/// HTML-escapes text for an element body or a double-quoted attribute value.
/// Both contexts are covered by the same five replacements, and every
/// interpolation in this module is one of those two contexts -- there is no
/// unquoted-attribute, `<script>`, `<style>`, or URL context anywhere in the
/// page, which is what makes a single escaper sufficient here.
fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[derive(Deserialize)]
pub struct PanelQuery {
    msg: Option<String>,
}

pub async fn panel(State(state): State<AppState>, Query(query): Query<PanelQuery>) -> Response {
    let notice = query.msg.as_deref().and_then(|code| {
        NOTICES
            .iter()
            .find(|(known, _)| *known == code)
            .map(|(_, text)| *text)
    });
    render(&state, notice.map(Banner::Ok)).await
}

/// The one banner slot at the top of the page.
enum Banner {
    Ok(&'static str),
    Err(String),
}

/// Renders the whole panel. Takes `&AppState` rather than the extractor so
/// the failure path of every form handler can call it directly.
///
/// If the page itself cannot be built (no `DATABASE_URL`, or the database is
/// unreachable) it renders THAT error, with that error's status code, rather
/// than an empty page -- a panel showing no principals because the database
/// is down must not look like a deployment with no principals.
async fn render(state: &AppState, banner: Option<Banner>) -> Response {
    match build_body(state, &banner).await {
        Ok(body) => (axum::http::StatusCode::OK, Html(page(&body))).into_response(),
        Err(err) => (
            err.status_code(),
            Html(page(&format!(
                "<p class=\"err\">{}</p>",
                esc(&err.message())
            ))),
        )
            .into_response(),
    }
}

/// Renders after a FAILED operation, preserving the error's own status code
/// (400/404/409/503) rather than flattening every failure to one status, and
/// still showing current state below the banner so the operator can see what
/// actually exists.
async fn render_error(state: &AppState, err: AdminError) -> Response {
    let code = err.status_code();
    let message = err.message();
    let body = match build_body(state, &Some(Banner::Err(message.clone()))).await {
        Ok(body) => body,
        // The operation failed AND the page cannot be rebuilt: report the
        // original failure, which is the one the operator asked about.
        Err(_) => format!("<p class=\"err\">{}</p>", esc(&message)),
    };
    (code, Html(page(&body))).into_response()
}

fn page(body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <title>epic-lore-authz admin</title><style>{CSS}</style></head>\
         <body><h1>epic-lore-authz admin</h1>{body}</body></html>"
    )
}

/// Deliberately small. This panel is meant to be usable, not pretty (see
/// tasks.md); every rule here earns its place by making a dense table
/// readable.
const CSS: &str = "body{font-family:system-ui,sans-serif;margin:1.5rem;line-height:1.4;\
color:#111;background:#fff}\
h1{font-size:1.3rem}h2{font-size:1.05rem;margin-top:2rem;border-bottom:1px solid #ccc;\
padding-bottom:.2rem}\
table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.85rem}\
th,td{border:1px solid #ccc;padding:.3rem .4rem;text-align:left;vertical-align:top}\
th{background:#f2f2f2}\
form.inline{display:inline}\
form.create{margin:.5rem 0;padding:.6rem;border:1px solid #ccc;background:#fafafa}\
form.create label{display:inline-block;margin:.15rem .6rem .15rem 0;font-size:.85rem}\
input,select{font:inherit;font-size:.85rem;padding:.15rem}\
button{font:inherit;font-size:.8rem;padding:.15rem .4rem;cursor:pointer}\
p.ok{background:#e6f4ea;border:1px solid #34a853;padding:.5rem}\
p.err{background:#fce8e6;border:1px solid #d93025;padding:.5rem}\
p.note{color:#555;font-size:.85rem}\
code{background:#f2f2f2;padding:0 .2rem}";

/// Builds every section. One function so the success path and the failure
/// path render the identical page (a failed create must still show the
/// current state, not a stripped-down error page).
async fn build_body(state: &AppState, banner: &Option<Banner>) -> Result<String, AdminError> {
    let db = state.db.as_deref();

    let principals = ops::list_principals(db).await?;
    let groups = ops::list_groups(db).await?;
    let resources = ops::list_resources(db).await?;
    let roles = ops::list_roles(db).await?;
    let grants = ops::list_grants(db).await?;

    let mut out = String::new();
    match banner {
        Some(Banner::Ok(text)) => out.push_str(&format!("<p class=\"ok\">{}</p>", esc(text))),
        Some(Banner::Err(text)) => out.push_str(&format!("<p class=\"err\">{}</p>", esc(text))),
        None => {}
    }
    out.push_str(
        "<p class=\"note\">Every request to this page and every form below is authenticated \
         with the <code>ADMIN_API_TOKEN</code> bearer header. Creating a principal or a group \
         grants nothing on its own: access exists only where a grant names it.</p>",
    );

    // --- principals ------------------------------------------------------
    out.push_str("<h2>Principals</h2>");
    out.push_str(&truncation_note(principals.truncated));
    out.push_str(
        "<table><tr><th>id</th><th>display name</th><th>username</th><th>email</th>\
         <th>source</th><th>external id</th><th>subject</th><th>service account</th>\
         <th>status</th><th>idp</th><th></th></tr>",
    );
    for principal in &principals.items {
        let status = crate::admin::api::status_str(&principal.status);
        // The two settable statuses come from `ops`, so the panel's toggle
        // cannot offer a value the operation would then refuse. Any status
        // that is not "active" (including a legacy `deprovisioned` row, which
        // this surface cannot SET but must still be able to reactivate)
        // offers "Activate".
        let (action, label) = if status == SETTABLE_STATUSES[0] {
            (SETTABLE_STATUSES[1], "Suspend")
        } else {
            (SETTABLE_STATUSES[0], "Activate")
        };
        out.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{display_name}</td><td>{username}</td>\
             <td>{email}</td><td>{source}</td><td>{external_id}</td><td>{subject}</td>\
             <td>{service}</td><td>{status}</td><td>{idp}</td>\
             <td><form class=\"inline\" method=\"post\" action=\"/admin/ui/principals/status\">\
             <input type=\"hidden\" name=\"principal_id\" value=\"{id}\">\
             <input type=\"hidden\" name=\"status\" value=\"{action}\">\
             <button type=\"submit\">{label}</button></form></td></tr>",
            id = esc(&principal.id.to_string()),
            display_name = esc(&principal.display_name),
            username = esc(&principal.preferred_username),
            email = esc(principal.email.as_deref().unwrap_or("")),
            source = esc(&principal.source),
            external_id = esc(principal.external_id.as_deref().unwrap_or("")),
            subject = esc(&principal.subject),
            service = if principal.is_service_account {
                "yes"
            } else {
                "no"
            },
            status = esc(status),
            idp = esc(principal.idp.as_deref().unwrap_or("")),
            action = esc(action),
            label = esc(label),
        ));
    }
    out.push_str("</table>");
    out.push_str(
        "<form class=\"create\" method=\"post\" action=\"/admin/ui/principals\">\
         <label>display name <input name=\"display_name\" required></label>\
         <label>username <input name=\"preferred_username\"></label>\
         <label>email <input name=\"email\"></label>\
         <label>source <input name=\"source\" placeholder=\"local\"></label>\
         <label>external id <input name=\"external_id\"></label>\
         <label>subject <input name=\"subject\"></label>\
         <label>idp <input name=\"idp\"></label>\
         <label>service account <input type=\"checkbox\" name=\"is_service_account\" \
         value=\"true\"></label>\
         <button type=\"submit\">Create principal</button></form>\
         <p class=\"note\">Leave <code>source</code>, <code>external id</code> and \
         <code>subject</code> blank for an ordinary local principal. Set them to pre-provision \
         an identity your identity provider (or a later SCIM sync) will assert.</p>",
    );

    // --- groups ----------------------------------------------------------
    out.push_str("<h2>Groups</h2>");
    out.push_str(&truncation_note(groups.truncated));
    out.push_str("<table><tr><th>id</th><th>name</th><th>description</th><th>status</th><th>members</th></tr>");
    for group in &groups.items {
        let members = ops::list_group_members(db, group.id).await?;
        let mut rendered_members = String::new();
        for (principal_id, display_name) in &members.items {
            rendered_members.push_str(&format!(
                "<div>{name} <code>{pid}</code> \
                 <form class=\"inline\" method=\"post\" \
                 action=\"/admin/ui/groups/members/remove\">\
                 <input type=\"hidden\" name=\"group_id\" value=\"{gid}\">\
                 <input type=\"hidden\" name=\"principal_id\" value=\"{pid}\">\
                 <button type=\"submit\">Remove</button></form></div>",
                name = esc(display_name),
                pid = esc(&principal_id.to_string()),
                gid = esc(&group.id.to_string()),
            ));
        }
        out.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{name}</td><td>{description}</td>\
             <td>{status}</td><td>{members}</td></tr>",
            id = esc(&group.id.to_string()),
            name = esc(&group.name),
            description = esc(group.description.as_deref().unwrap_or("")),
            status = esc(&group.status),
            members = rendered_members,
        ));
    }
    out.push_str("</table>");
    out.push_str(
        "<form class=\"create\" method=\"post\" action=\"/admin/ui/groups\">\
         <label>name <input name=\"name\" required></label>\
         <label>description <input name=\"description\"></label>\
         <button type=\"submit\">Create group</button></form>",
    );
    out.push_str(&format!(
        "<form class=\"create\" method=\"post\" action=\"/admin/ui/groups/members/add\">\
         <label>group {}</label>\
         <label>principal {}</label>\
         <button type=\"submit\">Add member</button></form>",
        select(
            "group_id",
            groups
                .items
                .iter()
                .map(|group| (group.id.to_string(), group.name.clone()))
        ),
        select(
            "principal_id",
            principals
                .items
                .iter()
                .map(|principal| (principal.id.to_string(), principal.display_name.clone()))
        ),
    ));

    // --- resources -------------------------------------------------------
    out.push_str("<h2>Resources</h2>");
    out.push_str(&truncation_note(resources.truncated));
    out.push_str("<table><tr><th>resource id</th><th>name</th><th>deleted</th><th></th></tr>");
    for resource in &resources.items {
        let action = if resource.deleted {
            String::new()
        } else {
            format!(
                "<form class=\"inline\" method=\"post\" action=\"/admin/ui/resources/delete\">\
                 <input type=\"hidden\" name=\"resource_id\" value=\"{id}\">\
                 <button type=\"submit\">Delete</button></form>",
                id = esc(&resource.resource_id),
            )
        };
        out.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{name}</td><td>{deleted}</td><td>{action}</td></tr>",
            id = esc(&resource.resource_id),
            name = esc(&resource.resource_name),
            deleted = if resource.deleted { "yes" } else { "no" },
        ));
    }
    out.push_str("</table>");
    out.push_str(
        "<form class=\"create\" method=\"post\" action=\"/admin/ui/resources\">\
         <label>resource id <input name=\"resource_id\" placeholder=\"urc-...\" required></label>\
         <label>name <input name=\"resource_name\"></label>\
         <button type=\"submit\">Register resource</button></form>\
         <p class=\"note\">lore-server registers a repository's resource itself when the \
         repository is created. Register one here only for a repository that predates this \
         service, or to repair a missing row.</p>",
    );

    // --- roles -----------------------------------------------------------
    out.push_str("<h2>Roles</h2>");
    out.push_str("<table><tr><th>id</th><th>name</th><th>permissions</th></tr>");
    for role in &roles {
        out.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{name}</td><td>{permissions}</td></tr>",
            id = esc(&role.id.to_string()),
            name = esc(&role.name),
            permissions = esc(&role.permissions.join(", ")),
        ));
    }
    out.push_str("</table>");
    out.push_str(
        "<p class=\"note\">Roles are seeded by migration and are read-only here: this product \
         has no role CRUD. The permission strings are advisory -- lore-server itself checks \
         membership of the token's resource list, not the permission string.</p>",
    );

    // --- grants ----------------------------------------------------------
    out.push_str("<h2>Grants</h2>");
    out.push_str(&truncation_note(grants.truncated));
    out.push_str(
        "<table><tr><th>id</th><th>role</th><th>resource pattern</th><th>principal kind</th>\
         <th>principal</th><th></th></tr>",
    );
    for grant in &grants.items {
        out.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{role}</td><td><code>{pattern}</code></td>\
             <td>{kind}</td><td><code>{principal}</code></td>\
             <td><form class=\"inline\" method=\"post\" action=\"/admin/ui/grants/delete\">\
             <input type=\"hidden\" name=\"grant_id\" value=\"{id}\">\
             <button type=\"submit\">Revoke</button></form></td></tr>",
            id = esc(&grant.id.to_string()),
            role = esc(&grant.role_name),
            pattern = esc(&grant.resource_pattern),
            kind = esc(&grant.principal_kind),
            principal = esc(&grant.principal_id.to_string()),
        ));
    }
    out.push_str("</table>");
    out.push_str(&format!(
        "<form class=\"create\" method=\"post\" action=\"/admin/ui/grants\">\
         <label>role {role}</label>\
         <label>resource pattern <input name=\"resource_pattern\" value=\"{wildcard}\" \
         required></label>\
         <label>principal kind {kind}</label>\
         <label>principal id <input name=\"principal_id\" required></label>\
         <button type=\"submit\">Create grant</button></form>\
         <p class=\"note\">The resource pattern is either the literal wildcard \
         <code>{wildcard}</code> (every registered resource) or one specific \
         <code>urc-&lt;id&gt;</code>. Nothing else is a pattern: <code>urc-abc*</code> would be \
         stored as a resource id that can never match, so it is refused. The principal id must \
         be a principal above (for <code>user</code>/<code>service_account</code>) or a group \
         above (for <code>group</code>).</p>",
        role = select(
            "role",
            roles
                .iter()
                .map(|role| (role.name.clone(), role.name.clone()))
        ),
        kind = select(
            "principal_kind",
            PRINCIPAL_KINDS
                .iter()
                .map(|kind| ((*kind).to_string(), (*kind).to_string()))
        ),
        wildcard = esc(WILDCARD_RESOURCE_PATTERN),
    ));

    Ok(out)
}

fn truncation_note(truncated: bool) -> String {
    if truncated {
        format!(
            "<p class=\"note\">Showing the first {} rows only -- this list is truncated.</p>",
            crate::admin::LIST_LIMIT
        )
    } else {
        String::new()
    }
}

/// A `<select>` from `(value, label)` pairs, both escaped.
fn select(name: &str, options: impl Iterator<Item = (String, String)>) -> String {
    let mut out = format!("<select name=\"{}\">", esc(name));
    for (value, label) in options {
        out.push_str(&format!(
            "<option value=\"{}\">{}</option>",
            esc(&value),
            esc(&label)
        ));
    }
    out.push_str("</select>");
    out
}

fn ok(code: &str) -> Response {
    Redirect::to(&format!("/admin/ui?msg={code}")).into_response()
}

// --- form handlers -------------------------------------------------------
// Each is: parse, call `ops`, redirect on success, re-render with the error
// on failure. No logic here that the JSON API does not also go through.

#[derive(Deserialize)]
pub struct CreatePrincipalForm {
    display_name: String,
    preferred_username: Option<String>,
    email: Option<String>,
    external_id: Option<String>,
    source: Option<String>,
    subject: Option<String>,
    /// An unchecked HTML checkbox is not submitted at all, so presence (not
    /// value) is what "checked" means here.
    is_service_account: Option<String>,
    idp: Option<String>,
}

pub async fn create_principal(
    State(state): State<AppState>,
    Form(form): Form<CreatePrincipalForm>,
) -> Response {
    let input = NewPrincipalInput {
        display_name: form.display_name,
        preferred_username: form.preferred_username,
        email: form.email,
        external_id: form.external_id,
        source: form.source,
        subject: form.subject,
        is_service_account: form.is_service_account.is_some(),
        idp: form.idp,
    };
    match ops::create_principal(state.db.as_deref(), input).await {
        Ok(_) => ok("principal-created"),
        Err(err) => render_error(&state, err).await,
    }
}

#[derive(Deserialize)]
pub struct SetStatusForm {
    principal_id: String,
    status: String,
}

pub async fn set_principal_status(
    State(state): State<AppState>,
    Form(form): Form<SetStatusForm>,
) -> Response {
    let result = match ops::parse_uuid("principal_id", &form.principal_id) {
        Ok(id) => ops::set_principal_status(state.db.as_deref(), id, &form.status).await,
        Err(err) => Err(err),
    };
    match result {
        Ok(_) => ok("status-updated"),
        Err(err) => render_error(&state, err).await,
    }
}

#[derive(Deserialize)]
pub struct CreateGroupForm {
    name: String,
    description: Option<String>,
}

pub async fn create_group(
    State(state): State<AppState>,
    Form(form): Form<CreateGroupForm>,
) -> Response {
    match ops::create_group(state.db.as_deref(), &form.name, form.description.as_deref()).await {
        Ok(_) => ok("group-created"),
        Err(err) => render_error(&state, err).await,
    }
}

#[derive(Deserialize)]
pub struct MemberForm {
    group_id: String,
    principal_id: String,
}

impl MemberForm {
    fn ids(&self) -> Result<(Uuid, Uuid), AdminError> {
        Ok((
            ops::parse_uuid("group_id", &self.group_id)?,
            ops::parse_uuid("principal_id", &self.principal_id)?,
        ))
    }
}

pub async fn add_group_member(
    State(state): State<AppState>,
    Form(form): Form<MemberForm>,
) -> Response {
    let result = match form.ids() {
        Ok((group_id, principal_id)) => {
            ops::add_group_member(state.db.as_deref(), group_id, principal_id).await
        }
        Err(err) => Err(err),
    };
    match result {
        Ok(()) => ok("member-added"),
        Err(err) => render_error(&state, err).await,
    }
}

pub async fn remove_group_member(
    State(state): State<AppState>,
    Form(form): Form<MemberForm>,
) -> Response {
    let result = match form.ids() {
        Ok((group_id, principal_id)) => {
            ops::remove_group_member(state.db.as_deref(), group_id, principal_id).await
        }
        Err(err) => Err(err),
    };
    match result {
        Ok(()) => ok("member-removed"),
        Err(err) => render_error(&state, err).await,
    }
}

#[derive(Deserialize)]
pub struct CreateResourceForm {
    resource_id: String,
    resource_name: Option<String>,
}

pub async fn create_resource(
    State(state): State<AppState>,
    Form(form): Form<CreateResourceForm>,
) -> Response {
    match ops::create_resource(
        state.db.as_deref(),
        &form.resource_id,
        form.resource_name.as_deref(),
    )
    .await
    {
        Ok(_) => ok("resource-created"),
        Err(err) => render_error(&state, err).await,
    }
}

#[derive(Deserialize)]
pub struct DeleteResourceForm {
    resource_id: String,
}

pub async fn delete_resource(
    State(state): State<AppState>,
    Form(form): Form<DeleteResourceForm>,
) -> Response {
    match ops::delete_resource(state.db.as_deref(), &form.resource_id).await {
        Ok(()) => ok("resource-deleted"),
        Err(err) => render_error(&state, err).await,
    }
}

#[derive(Deserialize)]
pub struct CreateGrantForm {
    role: String,
    resource_pattern: String,
    principal_kind: String,
    principal_id: String,
}

pub async fn create_grant(
    State(state): State<AppState>,
    Form(form): Form<CreateGrantForm>,
) -> Response {
    let result = match ops::parse_uuid("principal_id", &form.principal_id) {
        Ok(principal_id) => {
            ops::create_grant(
                state.db.as_deref(),
                NewGrantInput {
                    role: form.role,
                    resource_pattern: form.resource_pattern,
                    principal_kind: form.principal_kind,
                    principal_id,
                },
            )
            .await
        }
        Err(err) => Err(err),
    };
    match result {
        Ok((_, true)) => ok("grant-created"),
        Ok((_, false)) => ok("grant-exists"),
        Err(err) => render_error(&state, err).await,
    }
}

#[derive(Deserialize)]
pub struct DeleteGrantForm {
    grant_id: String,
}

pub async fn delete_grant(
    State(state): State<AppState>,
    Form(form): Form<DeleteGrantForm>,
) -> Response {
    let result = match ops::parse_uuid("grant_id", &form.grant_id) {
        Ok(id) => ops::delete_grant(state.db.as_deref(), id).await,
        Err(err) => Err(err),
    };
    match result {
        Ok(()) => ok("grant-deleted"),
        Err(err) => render_error(&state, err).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The escaper is the panel's only defence against a provisioning field
    /// becoming script in the browser of the one person holding the admin
    /// token. Tested directly here; tested end to end through the real HTTP
    /// server, against both database backends, in `tests/authz_suite/mod.rs`.
    #[test]
    fn esc_neutralizes_every_character_that_could_break_out() {
        assert_eq!(
            esc("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
        assert_eq!(esc("a\" onmouseover=\"b"), "a&quot; onmouseover=&quot;b");
        assert_eq!(esc("a & b"), "a &amp; b");
        assert_eq!(esc("plain"), "plain");
    }

    /// A notice code is looked up in a fixed table and never reflected, so an
    /// unknown one produces no banner at all.
    #[test]
    fn only_known_notice_codes_render_anything() {
        let known = NOTICES
            .iter()
            .find(|(code, _)| *code == "grant-created")
            .map(|(_, text)| *text);
        assert_eq!(known, Some("Grant created."));
        assert!(
            NOTICES
                .iter()
                .all(|(code, _)| *code != "<script>alert(1)</script>")
        );
    }
}
