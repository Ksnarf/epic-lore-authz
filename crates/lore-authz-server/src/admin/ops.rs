//! Every admin operation, exactly once: validation, then the database call.
//!
//! Both front ends (`crate::admin::api`, `crate::admin::panel`) call these
//! functions and do nothing else of consequence. That is the point -- an
//! admin surface with two entry points and two copies of "may this be
//! granted?" is an admin surface where one copy is weaker, and the weaker one
//! is the one that gets used.
//!
//! ## The validation that actually matters
//!
//! Most of the checks below reject malformed input. Three of them prevent
//! grants that would be silently WRONG rather than merely malformed, which is
//! worse, because the operator would believe the access they granted exists:
//!
//! 1. `principal_kind` must agree with the principal's own
//!    `is_service_account`. `db::permissions::resolve_resource_permissions`
//!    derives the kind it matches on from the PRINCIPAL ROW, so a binding
//!    recorded as `user` against a service account (or the reverse) matches
//!    nothing, ever, while looking perfectly correct in a listing.
//! 2. `resource_pattern` must be either the exact wildcard sentinel `urc-*`
//!    or a well-formed `urc-<id>`. The policy engine treats ONLY the exact
//!    literal `urc-*` as a wildcard and everything else as an exact string
//!    match, so a plausible-looking `urc-abc*` is not a prefix pattern -- it
//!    is a binding to a resource id that cannot exist.
//! 3. The principal or group being granted to must EXIST.
//!    `role_bindings.principal_id` is polymorphic and therefore cannot carry
//!    a foreign key (see `migrations/0001_identities_resources_grants.sql`,
//!    which says in as many words that this is "validated at the application
//!    layer"). This is that layer.
//!
//! None of the three can be enforced by a database constraint, which is
//! precisely why they are tested against a real database on both backends
//! (see `tests/authz_suite/mod.rs`).

use lore_authz_core::model::Principal;
use uuid::Uuid;

use crate::admin::AdminError;
use crate::admin::LIST_LIMIT;
use crate::db::Db;
use crate::db::groups;
use crate::db::groups::GroupSummary;
use crate::db::permissions;
use crate::db::permissions::CreateGrantOutcome;
use crate::db::permissions::GrantSummary;
use crate::db::permissions::PRINCIPAL_KINDS;
use crate::db::permissions::RoleSummary;
use crate::db::permissions::WILDCARD_RESOURCE_PATTERN;
use crate::db::principals;
use crate::db::principals::InsertPrincipalOutcome;
use crate::db::principals::NewPrincipal;
use crate::db::resources;
use crate::db::resources::ResourceSummary;

/// The two statuses this surface may set. `deprovisioned` (which the schema
/// also allows) is deliberately not offered: nothing in this product treats
/// it differently from `suspended` yet, so exposing it would invite an
/// operator to encode a distinction the authorization path does not make.
pub const SETTABLE_STATUSES: [&str; 2] = ["active", "suspended"];

/// Upper bound on every operator-supplied free-text field. Not a security
/// control (the database columns are unbounded `text`), just a guard against
/// a list view rendered unusable by one pathological value.
const MAX_FIELD_LEN: usize = 256;

/// A bounded list plus whether the bound was hit -- see
/// `crate::admin::LIST_LIMIT`. `truncated` is `true` when exactly `LIST_LIMIT`
/// rows came back, which may mean the table holds exactly that many; erring
/// toward "there may be more" is the honest direction.
pub struct Listing<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}

impl<T> Listing<T> {
    fn new(items: Vec<T>) -> Self {
        let truncated = items.len() as i64 >= LIST_LIMIT;
        Self { items, truncated }
    }
}

fn require_db(db: Option<&Db>) -> Result<&Db, AdminError> {
    db.ok_or(AdminError::DatabaseUnconfigured)
}

/// Trims and rejects an empty or over-long required field.
fn required_text(field: &str, value: &str) -> Result<String, AdminError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AdminError::Invalid(format!("{field} must not be empty")));
    }
    if trimmed.chars().count() > MAX_FIELD_LEN {
        return Err(AdminError::Invalid(format!(
            "{field} must be at most {MAX_FIELD_LEN} characters"
        )));
    }
    Ok(trimmed.to_string())
}

/// Trims an optional field, collapsing "present but blank" to `None` -- an
/// HTML form always submits every field, so a blank input must mean "unset",
/// not "set to the empty string".
fn optional_text(field: &str, value: Option<&str>) -> Result<Option<String>, AdminError> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(v) => Ok(Some(required_text(field, v)?)),
    }
}

pub fn parse_uuid(field: &str, raw: &str) -> Result<Uuid, AdminError> {
    Uuid::parse_str(raw.trim())
        .map_err(|_| AdminError::Invalid(format!("{field} {raw:?} is not a valid uuid")))
}

/// `source` names a provisioning origin (`local`, `oidc`, `scim`) and is part
/// of the UNIQUE `(source, subject)` identity key, so it is restricted to a
/// plain lowercase token rather than accepting arbitrary text that would make
/// two identities differ only by whitespace or case.
fn validate_source(source: &str) -> Result<String, AdminError> {
    let source = required_text("source", source)?;
    let well_formed = source
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !well_formed {
        return Err(AdminError::Invalid(format!(
            "source {source:?} must be lowercase ASCII letters/digits with '_' or '-' (e.g. \
             \"local\", \"oidc\", \"scim\")"
        )));
    }
    Ok(source)
}

/// A `role_bindings.resource_pattern` the policy engine will actually honor:
/// the exact wildcard sentinel, or a well-formed `urc-<id>`.
///
/// Reuses `crate::grpc::validate_new_resource_id` for the non-wildcard case
/// -- the same function `RebacApi::CreateResource` validates a real resource
/// id with -- so "what is a valid resource id" is defined once in this
/// codebase. See reason 2 in this module's doc comment for why a
/// plausible-looking `urc-abc*` must be refused rather than accepted as a
/// prefix pattern.
pub fn validate_resource_pattern(pattern: &str) -> Result<String, AdminError> {
    let pattern = required_text("resource_pattern", pattern)?;
    if pattern == WILDCARD_RESOURCE_PATTERN {
        return Ok(pattern);
    }
    crate::grpc::validate_new_resource_id(&pattern).map_err(|status| {
        AdminError::Invalid(format!(
            "resource_pattern must be the wildcard {WILDCARD_RESOURCE_PATTERN:?} or a specific \
             resource id: {}",
            status.message()
        ))
    })?;
    Ok(pattern)
}

// --- principals ----------------------------------------------------------

/// What an operator may set when creating a principal. Every field is
/// optional except `display_name`; see `db::principals::NewPrincipal` for why
/// `id` and `status` are not settable here at all.
#[derive(Debug, Default, Clone)]
pub struct NewPrincipalInput {
    pub display_name: String,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub external_id: Option<String>,
    pub source: Option<String>,
    pub subject: Option<String>,
    pub is_service_account: bool,
    pub idp: Option<String>,
}

pub async fn list_principals(db: Option<&Db>) -> Result<Listing<Principal>, AdminError> {
    let rows = principals::list_principals(require_db(db)?, LIST_LIMIT)
        .await
        .map_err(|err| AdminError::from_db("list_principals", err))?;
    Ok(Listing::new(rows))
}

pub async fn get_principal(db: Option<&Db>, id: Uuid) -> Result<Principal, AdminError> {
    principals::find_principal(require_db(db)?, id)
        .await
        .map_err(|err| AdminError::from_db("find_principal", err))?
        .ok_or_else(|| AdminError::NotFound(format!("no principal with id {id}")))
}

/// Creates a principal. The new row holds NO role bindings, so this creates
/// an IDENTITY and never an AUTHORIZATION -- the same property that makes
/// OIDC JIT provisioning safe to have on by default (see
/// `crate::oidc_login::resolve_principal`). Granting is a separate, explicit
/// call.
pub async fn create_principal(
    db: Option<&Db>,
    input: NewPrincipalInput,
) -> Result<Principal, AdminError> {
    let db = require_db(db)?;

    let display_name = required_text("display_name", &input.display_name)?;
    let preferred_username =
        optional_text("preferred_username", input.preferred_username.as_deref())?
            .unwrap_or_else(|| display_name.clone());
    let source = match optional_text("source", input.source.as_deref())? {
        Some(source) => validate_source(&source)?,
        None => "local".to_string(),
    };
    let new = NewPrincipal {
        subject: optional_text("subject", input.subject.as_deref())?,
        source,
        external_id: optional_text("external_id", input.external_id.as_deref())?,
        email: optional_text("email", input.email.as_deref())?,
        display_name,
        preferred_username,
        is_service_account: input.is_service_account,
        idp: optional_text("idp", input.idp.as_deref())?,
    };

    let id = Uuid::new_v4();
    match principals::insert_admin_principal(db, id, &new)
        .await
        .map_err(|err| AdminError::from_db("insert_admin_principal", err))?
    {
        InsertPrincipalOutcome::Created => {}
        InsertPrincipalOutcome::DuplicateIdentity => {
            return Err(AdminError::Conflict(format!(
                "a principal already exists with source {:?} and that subject",
                new.source
            )));
        }
    }

    get_principal(Some(db), id).await
}

/// Sets a principal's status. Suspending is this product's widest revocation
/// lever: `db::principals::find_active_principal` returns `None` for a
/// suspended principal, so the next authorization check, login poll, and
/// token exchange all deny -- see the test
/// `admin_suspending_a_principal_denies_the_next_check` in
/// `tests/authz_suite/mod.rs`, which proves that rather than asserting it.
pub async fn set_principal_status(
    db: Option<&Db>,
    id: Uuid,
    status: &str,
) -> Result<Principal, AdminError> {
    let db = require_db(db)?;
    let status = status.trim();
    if !SETTABLE_STATUSES.contains(&status) {
        return Err(AdminError::Invalid(format!(
            "status {status:?} must be one of {}",
            SETTABLE_STATUSES.join(", ")
        )));
    }

    let updated = principals::set_principal_status(db, id, status)
        .await
        .map_err(|err| AdminError::from_db("set_principal_status", err))?;
    if !updated {
        return Err(AdminError::NotFound(format!("no principal with id {id}")));
    }

    get_principal(Some(db), id).await
}

// --- groups --------------------------------------------------------------

pub async fn list_groups(db: Option<&Db>) -> Result<Listing<GroupSummary>, AdminError> {
    let rows = groups::list_groups(require_db(db)?, LIST_LIMIT)
        .await
        .map_err(|err| AdminError::from_db("list_groups", err))?;
    Ok(Listing::new(rows))
}

pub async fn create_group(
    db: Option<&Db>,
    name: &str,
    description: Option<&str>,
) -> Result<GroupSummary, AdminError> {
    let db = require_db(db)?;
    let name = required_text("name", name)?;
    let description = optional_text("description", description)?;

    let id = Uuid::new_v4();
    match groups::insert_group_with_description(db, id, &name, description.as_deref())
        .await
        .map_err(|err| AdminError::from_db("insert_group_with_description", err))?
    {
        groups::InsertGroupOutcome::Created => Ok(GroupSummary {
            id,
            name,
            description,
            source: "local".to_string(),
            status: "active".to_string(),
        }),
        groups::InsertGroupOutcome::DuplicateName => Err(AdminError::Conflict(format!(
            "a group named {name:?} already exists"
        ))),
    }
}

pub async fn list_group_members(
    db: Option<&Db>,
    group_id: Uuid,
) -> Result<Listing<(Uuid, String)>, AdminError> {
    let db = require_db(db)?;
    require_group(db, group_id).await?;
    let rows = groups::list_group_members(db, group_id, LIST_LIMIT)
        .await
        .map_err(|err| AdminError::from_db("list_group_members", err))?;
    Ok(Listing::new(rows))
}

/// Adds a member. Both ids are checked for existence first: the
/// `group_members` table IS foreign-keyed on both backends, but a foreign-key
/// violation surfacing as a 500 tells an operator nothing, and this way the
/// "no such group" and "no such principal" cases are distinguishable to the
/// person who typed one of them wrong.
pub async fn add_group_member(
    db: Option<&Db>,
    group_id: Uuid,
    principal_id: Uuid,
) -> Result<(), AdminError> {
    let db = require_db(db)?;
    require_group(db, group_id).await?;
    get_principal(Some(db), principal_id).await?;

    groups::add_member(db, group_id, principal_id)
        .await
        .map_err(|err| AdminError::from_db("add_member", err))
}

/// Removes a member, and says so when there was nothing to remove -- an
/// operator revoking access must not be told "done" when the membership they
/// meant to remove is still there under a different id.
pub async fn remove_group_member(
    db: Option<&Db>,
    group_id: Uuid,
    principal_id: Uuid,
) -> Result<(), AdminError> {
    let db = require_db(db)?;
    let removed = groups::remove_member(db, group_id, principal_id)
        .await
        .map_err(|err| AdminError::from_db("remove_member", err))?;
    if removed {
        Ok(())
    } else {
        Err(AdminError::NotFound(format!(
            "principal {principal_id} is not a member of group {group_id}"
        )))
    }
}

async fn require_group(db: &Db, group_id: Uuid) -> Result<(), AdminError> {
    let exists = groups::group_exists(db, group_id)
        .await
        .map_err(|err| AdminError::from_db("group_exists", err))?;
    if exists {
        Ok(())
    } else {
        Err(AdminError::NotFound(format!("no group with id {group_id}")))
    }
}

// --- resources -----------------------------------------------------------

pub async fn list_resources(db: Option<&Db>) -> Result<Listing<ResourceSummary>, AdminError> {
    let rows = resources::list_resources(require_db(db)?, LIST_LIMIT)
        .await
        .map_err(|err| AdminError::from_db("list_resources", err))?;
    Ok(Listing::new(rows))
}

/// Registers a resource. Normally lore-server does this for itself over
/// `RebacApi::CreateResource` when a repository is created; this exists for
/// the bring-up case (granting access to a repository that predates this
/// service) and for operators recovering from a resource row that was never
/// created. It validates the id with the SAME function that RPC uses, so the
/// two paths cannot diverge on what a legal resource id is.
pub async fn create_resource(
    db: Option<&Db>,
    resource_id: &str,
    resource_name: Option<&str>,
) -> Result<ResourceSummary, AdminError> {
    let db = require_db(db)?;
    let resource_id = required_text("resource_id", resource_id)?;
    crate::grpc::validate_new_resource_id(&resource_id)
        .map_err(|status| AdminError::Invalid(status.message().to_string()))?;
    let resource_name =
        optional_text("resource_name", resource_name)?.unwrap_or_else(|| resource_id.clone());

    match resources::create_resource(db, &resource_id, &resource_name)
        .await
        .map_err(|err| AdminError::from_db("create_resource", err))?
    {
        resources::CreateResourceOutcome::Created => Ok(ResourceSummary {
            resource_id,
            resource_name,
            deleted: false,
        }),
        resources::CreateResourceOutcome::AlreadyExists => Err(AdminError::Conflict(format!(
            "resource {resource_id:?} already exists"
        ))),
    }
}

/// Soft-deletes a resource (sets `deleted_at`), exactly as
/// `RebacApi::DeleteResource` does -- same function, same audit trail, same
/// effect: every grant naming it stops authorizing anything at the next
/// check, because `resolve_resource_permissions` only ever matches
/// currently-registered rows.
pub async fn delete_resource(db: Option<&Db>, resource_id: &str) -> Result<(), AdminError> {
    let db = require_db(db)?;
    let resource_id = required_text("resource_id", resource_id)?;
    resources::delete_resource(db, &resource_id)
        .await
        .map_err(|err| AdminError::from_db("delete_resource", err))
}

// --- roles and grants ----------------------------------------------------

pub async fn list_roles(db: Option<&Db>) -> Result<Vec<RoleSummary>, AdminError> {
    permissions::list_roles(require_db(db)?)
        .await
        .map_err(|err| AdminError::from_db("list_roles", err))
}

pub async fn list_grants(db: Option<&Db>) -> Result<Listing<GrantSummary>, AdminError> {
    let rows = permissions::list_grants(require_db(db)?, LIST_LIMIT)
        .await
        .map_err(|err| AdminError::from_db("list_grants", err))?;
    Ok(Listing::new(rows))
}

/// What an operator supplies to create a grant. `role` accepts either a role
/// NAME (`"reader"`) or its uuid, because an operator typing a grant by hand
/// knows the name and a script that listed the roles has the id.
#[derive(Debug, Clone)]
pub struct NewGrantInput {
    pub role: String,
    pub resource_pattern: String,
    pub principal_kind: String,
    pub principal_id: Uuid,
}

/// Creates a role binding, after the three checks described in this module's
/// doc comment. Returns the created (or already-existing) binding, so the
/// operator has the id needed to revoke exactly it later.
pub async fn create_grant(
    db: Option<&Db>,
    input: NewGrantInput,
) -> Result<(GrantSummary, bool), AdminError> {
    let db = require_db(db)?;

    let resource_pattern = validate_resource_pattern(&input.resource_pattern)?;
    let principal_kind = input.principal_kind.trim().to_string();
    if !PRINCIPAL_KINDS.contains(&principal_kind.as_str()) {
        return Err(AdminError::Invalid(format!(
            "principal_kind {principal_kind:?} must be one of {}",
            PRINCIPAL_KINDS.join(", ")
        )));
    }

    let role = resolve_role(db, &input.role).await?;

    // The check that stops a grant which would look right and match nothing:
    // the policy engine derives the kind from the principal row, not from the
    // binding (see this module's doc comment, reason 1).
    if principal_kind == "group" {
        require_group(db, input.principal_id).await?;
    } else {
        let principal = get_principal(Some(db), input.principal_id).await?;
        let actual_kind = if principal.is_service_account {
            "service_account"
        } else {
            "user"
        };
        if actual_kind != principal_kind {
            return Err(AdminError::Invalid(format!(
                "principal {} is a {actual_kind}, so a binding with principal_kind \
                 {principal_kind:?} would never match anything -- use {actual_kind:?}",
                principal.id
            )));
        }
    }

    let outcome = permissions::create_grant(
        db,
        role.id,
        &resource_pattern,
        &principal_kind,
        input.principal_id,
    )
    .await
    .map_err(|err| AdminError::from_db("create_grant", err))?;

    let created = matches!(outcome, CreateGrantOutcome::Created(_));
    Ok((
        GrantSummary {
            id: outcome.id(),
            role_id: role.id,
            role_name: role.name,
            resource_pattern,
            principal_kind,
            principal_id: input.principal_id,
        },
        created,
    ))
}

pub async fn delete_grant(db: Option<&Db>, id: Uuid) -> Result<(), AdminError> {
    let db = require_db(db)?;
    let deleted = permissions::delete_grant(db, id)
        .await
        .map_err(|err| AdminError::from_db("delete_grant", err))?;
    if deleted {
        Ok(())
    } else {
        Err(AdminError::NotFound(format!("no grant with id {id}")))
    }
}

/// Resolves a role by name or uuid against the seeded roles. Reads the list
/// (three rows, seeded by migration) rather than issuing a name lookup and a
/// separate id lookup, so there is one query and one place that decides what
/// a valid role is.
async fn resolve_role(db: &Db, role: &str) -> Result<RoleSummary, AdminError> {
    let role = required_text("role", role)?;
    let roles = permissions::list_roles(db)
        .await
        .map_err(|err| AdminError::from_db("list_roles", err))?;

    let by_id = Uuid::parse_str(&role).ok();
    roles
        .into_iter()
        .find(|candidate| candidate.name == role || Some(candidate.id) == by_id)
        .ok_or_else(|| {
            AdminError::NotFound(format!(
                "no role {role:?} -- the built-in roles are reader, writer and admin, and this \
                 product has no role CRUD"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reason 2 in this module's doc comment, as a test: only the EXACT
    /// wildcard sentinel is a wildcard, and a pattern that merely looks like
    /// a glob is refused rather than silently stored as a binding that can
    /// never match.
    #[test]
    fn only_the_exact_wildcard_sentinel_is_accepted_as_a_wildcard() {
        assert_eq!(
            validate_resource_pattern(WILDCARD_RESOURCE_PATTERN).unwrap(),
            WILDCARD_RESOURCE_PATTERN
        );
        assert_eq!(validate_resource_pattern("urc-repo1").unwrap(), "urc-repo1");
        assert_eq!(
            validate_resource_pattern("  urc-repo1  ").unwrap(),
            "urc-repo1"
        );

        for refused in ["urc-abc*", "*", "urc-*extra", "**", "urc-", "repo1", ""] {
            assert!(
                validate_resource_pattern(refused).is_err(),
                "{refused:?} must be refused: the policy engine would store it as a literal id \
                 that can never match, not as a pattern"
            );
        }
    }

    #[test]
    fn a_source_is_a_plain_lowercase_token() {
        assert_eq!(validate_source("local").unwrap(), "local");
        assert_eq!(validate_source("scim-v2").unwrap(), "scim-v2");
        for refused in ["", "  ", "OIDC", "with space", "semi;colon", "\"quoted\""] {
            assert!(
                validate_source(refused).is_err(),
                "{refused:?} must be refused"
            );
        }
    }

    #[test]
    fn blank_optional_fields_collapse_to_none_so_a_form_post_does_not_store_empty_strings() {
        assert_eq!(optional_text("email", Some("")).unwrap(), None);
        assert_eq!(optional_text("email", Some("   ")).unwrap(), None);
        assert_eq!(optional_text("email", None).unwrap(), None);
        assert_eq!(
            optional_text("email", Some(" a@example.com ")).unwrap(),
            Some("a@example.com".to_string())
        );
    }

    #[test]
    fn over_long_and_empty_required_fields_are_refused() {
        assert!(required_text("display_name", "  ").is_err());
        assert!(required_text("display_name", &"x".repeat(MAX_FIELD_LEN + 1)).is_err());
        assert_eq!(
            required_text("display_name", &"x".repeat(MAX_FIELD_LEN)).unwrap(),
            "x".repeat(MAX_FIELD_LEN)
        );
    }
}
