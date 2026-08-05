//! `PgPolicyStore`: the real (Postgres-backed) implementation of
//! `lore_authz_core::policy::PolicyStore`, reading `role_bindings` joined to
//! `roles`, honoring both direct-to-principal grants and grants inherited
//! via `group_members`.
//!
//! This is the single engine shared by BOTH `LookupUserPermissions` and
//! `CheckUserPermission` (see `crates/lore-authz-server/src/grpc.rs`), per
//! the `PolicyStore` trait's own doc comment in lore-authz-core, which names
//! both callers explicitly:
//! - `CheckUserPermission` calls this with the exact `resource_id`s the
//!   caller asked about.
//! - `LookupUserPermissions` first asks `db::resources::
//!   list_resource_ids_with_prefix` for every resource matching
//!   `resource_filter`, then calls this with THAT list as
//!   `requested_resource_ids` -- so a wildcard grant is always expanded to
//!   the concrete, currently-existing resource ids it matches, never
//!   returned as the literal string `"urc-*"` itself. That distinction
//!   matters: lore-server's `RepositoryList` caller strips the `"urc-"`
//!   prefix off every returned `resource_id` and parses the remainder as a
//!   repository id directly (see the fork's
//!   `repository_list::lookup_authorized_repositories`) -- a literal
//!   `"urc-*"` entry would not parse as one and would just be silently
//!   dropped, which is not the same as this function returning the correct,
//!   complete, EXACT set of currently-authorized repositories.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;

use async_trait::async_trait;
use lore_authz_core::AuthzError;
use lore_authz_core::claims::ResourcePermission;
use lore_authz_core::model::Principal;
use lore_authz_core::policy::PolicyStore;
use sqlx::PgPool;
use uuid::Uuid;

/// The literal wildcard resource pattern. A `role_bindings.resource_pattern`
/// row with EXACTLY this value matches every `urc-*` resource for the bound
/// principal (or any member of a bound group) -- see tasks.md "PHASE 1a" and
/// `lore_authz_core::claims::ResourcePermission::is_wildcard`.
pub const WILDCARD_RESOURCE_PATTERN: &str = "urc-*";

/// Fixed ids for the three built-in advisory roles seeded by
/// `migrations/0001_identities_resources_grants.sql` (`ON CONFLICT (id) DO
/// NOTHING`, so these never drift from the migration even if it re-runs).
/// `Uuid::from_u128` is a `const fn`, and `1`/`2`/`3` as a 128-bit
/// big-endian value format exactly as `00000000-0000-0000-0000-00000000000{1,2,3}`,
/// matching the migration's literal UUIDs.
pub const ROLE_READER: Uuid = Uuid::from_u128(1);
pub const ROLE_WRITER: Uuid = Uuid::from_u128(2);
pub const ROLE_ADMIN: Uuid = Uuid::from_u128(3);

/// Grants `role_id` to a principal (or group), either for one specific
/// `resource_pattern` (e.g. `"urc-abc123"`) or, via `WILDCARD_RESOURCE_
/// PATTERN`, for every `urc-*` resource. `principal_kind` must be one of
/// `"user"`, `"service_account"`, `"group"` (matches the `role_bindings`
/// CHECK constraint). Used only by `tests/postgres_backed.rs` today -- see
/// `db::principals::insert_principal`'s doc comment for why this is a plain
/// `pub fn` rather than `#[cfg(test)]`-gated.
pub async fn grant(
    pool: &PgPool,
    role_id: Uuid,
    resource_pattern: &str,
    principal_kind: &str,
    principal_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO role_bindings (id, role_id, resource_pattern, principal_kind, principal_id) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (role_id, resource_pattern, principal_kind, principal_id) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(role_id)
    .bind(resource_pattern)
    .bind(principal_kind)
    .bind(principal_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub struct PgPolicyStore {
    pool: PgPool,
}

impl PgPolicyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct GrantRow {
    resource_pattern: String,
    permissions: Vec<String>,
}

#[async_trait]
impl PolicyStore for PgPolicyStore {
    /// Restricts `requested_resource_ids` down to the subset `principal`
    /// actually holds a grant for AND that is a currently-registered,
    /// not-deleted `resources` row -- directly, via a group they belong to,
    /// or via a wildcard binding (direct or group) -- returning the union of
    /// permission strings for each. Resource ids with NO matching binding at
    /// all, or that do not exist / were deleted (`RebacApi::DeleteResource`),
    /// are simply absent from the result (never returned with an empty
    /// permission list): this is the "no grant = not present, not merely
    /// empty" deny-closed shape both `LookupUserPermissions` and
    /// `CheckUserPermission` build their allow/deny split from.
    ///
    /// The resource-existence check matters even for a WILDCARD grant: a
    /// `urc-*` binding must never authorize a `resource_id` that was never
    /// created (or has since been deleted) just because the caller happened
    /// to ask about it -- `LookupUserPermissions`' own candidate list
    /// (`db::resources::list_resource_ids_with_prefix`) already excludes
    /// those, but `CheckUserPermission` passes `req.resource_id` straight
    /// through from the wire with no such pre-filtering, so the check has to
    /// live here, in the one place both callers share, not in either
    /// caller individually.
    ///
    /// Any DB error is returned as `Err`, never papered over as an empty
    /// `Ok(vec![])` -- a caller must not be able to mistake "the check
    /// itself failed" for "checked, and nothing was granted".
    async fn resolve_resource_permissions(
        &self,
        principal: &Principal,
        requested_resource_ids: &[String],
    ) -> Result<Vec<ResourcePermission>, AuthzError> {
        if requested_resource_ids.is_empty() {
            return Ok(vec![]);
        }

        let existing: HashSet<String> = sqlx::query_scalar(
            "SELECT resource_id FROM resources WHERE deleted_at IS NULL AND resource_id = ANY($1)",
        )
        .bind(requested_resource_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, principal_id = %principal.id, "resource existence query failed");
            AuthzError::Internal
        })?
        .into_iter()
        .collect();

        if existing.is_empty() {
            return Ok(vec![]);
        }

        let principal_kind = if principal.is_service_account {
            "service_account"
        } else {
            "user"
        };

        let rows: Vec<GrantRow> = sqlx::query_as(
            r#"
            SELECT rb.resource_pattern AS resource_pattern, r.permissions AS permissions
            FROM role_bindings rb
            JOIN roles r ON r.id = rb.role_id
            WHERE (
                (rb.principal_kind = $1 AND rb.principal_id = $2)
                OR (
                    rb.principal_kind = 'group'
                    AND rb.principal_id IN (
                        SELECT group_id FROM group_members WHERE principal_id = $2
                    )
                )
            )
            AND (rb.resource_pattern = $3 OR rb.resource_pattern = ANY($4))
            "#,
        )
        .bind(principal_kind)
        .bind(principal.id)
        .bind(WILDCARD_RESOURCE_PATTERN)
        .bind(requested_resource_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, principal_id = %principal.id, "resolve_resource_permissions query failed");
            AuthzError::Internal
        })?;

        // BTreeMap keeps the result deterministically ordered by
        // resource_id -- LookupUserPermissions' own test asserts an EXACT
        // Vec, not just a set, so a stable order matters here. Only ids in
        // `existing` are ever inserted, regardless of which binding matched.
        let mut matched: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for row in rows {
            let perms: BTreeSet<String> = row.permissions.into_iter().collect();
            if row.resource_pattern == WILDCARD_RESOURCE_PATTERN {
                for id in requested_resource_ids {
                    if existing.contains(id) {
                        matched.entry(id.clone()).or_default().extend(perms.clone());
                    }
                }
            } else if existing.contains(&row.resource_pattern)
                && requested_resource_ids.contains(&row.resource_pattern)
            {
                matched
                    .entry(row.resource_pattern.clone())
                    .or_default()
                    .extend(perms);
            }
        }

        Ok(matched
            .into_iter()
            .filter(|(_, perms)| !perms.is_empty())
            .map(|(resource_id, perms)| ResourcePermission {
                resource_id,
                permission: perms.into_iter().collect(),
            })
            .collect())
    }
}
