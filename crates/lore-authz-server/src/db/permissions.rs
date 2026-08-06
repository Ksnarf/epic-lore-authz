//! `DbPolicyStore`: the real, `PolicyStore`-implementing engine reading
//! `role_bindings` joined to `roles` (Postgres) / `role_permissions`
//! (SQLite), honoring both direct-to-principal grants and grants inherited
//! via `group_members`. Dispatches on `Db`'s variant internally (see
//! `db/mod.rs`) -- callers never branch on backend.
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
//!
//! ## Postgres vs SQLite representation of `roles.permissions`
//! Postgres stores it as a native `text[]` column, read directly into
//! `Vec<String>`. SQLite has no array type, so its migration
//! (`migrations_sqlite/0001_...sql`) normalizes it into a `role_permissions`
//! join table instead; the SQLite query path here aggregates it back with
//! `GROUP_CONCAT` into a comma-joined string and splits it in Rust -- same
//! `Vec<String>` shape either way by the time it reaches the shared matching
//! logic at the bottom of `resolve_resource_permissions`. Permission strings
//! (`"read"`/`"write"`/`"admin"`) never contain a comma, so the join/split
//! round-trip is lossless.
//!
//! ## Postgres `= ANY($1)` vs SQLite `IN (...)`
//! SQLite has no array binding, so the SQLite path builds a dynamic
//! `IN (?, ?, ..., ?)` clause (`sqlite_placeholders`) sized to
//! `requested_resource_ids`, binding each element positionally -- the
//! placeholder COUNT is derived from that slice's length (not secret,
//! attacker-uncontrolled-shape data), never from a value, so this is not a
//! SQL-injection risk.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use lore_authz_core::AuthzError;
use lore_authz_core::claims::ResourcePermission;
use lore_authz_core::model::Principal;
use lore_authz_core::policy::PolicyStore;
use uuid::Uuid;

use crate::db::Db;

/// The literal wildcard resource pattern. A `role_bindings.resource_pattern`
/// row with EXACTLY this value matches every `urc-*` resource for the bound
/// principal (or any member of a bound group) -- see tasks.md "PHASE 1a" and
/// `lore_authz_core::claims::ResourcePermission::is_wildcard`. Identical
/// string, identical seeded value, on BOTH backends' migrations.
pub const WILDCARD_RESOURCE_PATTERN: &str = "urc-*";

/// Fixed ids for the three built-in advisory roles seeded by BOTH
/// migration sets (`ON CONFLICT (id) DO NOTHING`, so these never drift from
/// the migrations even if they re-run). `Uuid::from_u128` is a `const fn`,
/// and `1`/`2`/`3` as a 128-bit big-endian value format exactly as
/// `00000000-0000-0000-0000-00000000000{1,2,3}`, matching both migrations'
/// literal seed values (Postgres binds this natively; SQLite via
/// `.to_string()` -- see `db/principals.rs`'s module doc comment for why).
pub const ROLE_READER: Uuid = Uuid::from_u128(1);
pub const ROLE_WRITER: Uuid = Uuid::from_u128(2);
pub const ROLE_ADMIN: Uuid = Uuid::from_u128(3);

fn sqlite_placeholders(n: usize) -> String {
    std::iter::repeat_n("?", n).collect::<Vec<_>>().join(",")
}

/// Grants `role_id` to a principal (or group), either for one specific
/// `resource_pattern` (e.g. `"urc-abc123"`) or, via `WILDCARD_RESOURCE_
/// PATTERN`, for every `urc-*` resource. `principal_kind` must be one of
/// `"user"`, `"service_account"`, `"group"` (matches the `role_bindings`
/// CHECK constraint on both backends). Used only by `tests/` today -- see
/// `db::principals::insert_principal`'s doc comment for why this is a plain
/// `pub fn` rather than `#[cfg(test)]`-gated.
pub async fn grant(
    db: &Db,
    role_id: Uuid,
    resource_pattern: &str,
    principal_kind: &str,
    principal_id: Uuid,
) -> Result<(), sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            sqlx::query(
                "INSERT INTO role_bindings (id, role_id, resource_pattern, principal_kind, \
                 principal_id) VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (role_id, resource_pattern, principal_kind, principal_id) DO \
                 NOTHING",
            )
            .bind(Uuid::new_v4())
            .bind(role_id)
            .bind(resource_pattern)
            .bind(principal_kind)
            .bind(principal_id)
            .execute(&handle.pool)
            .await?;
        }
        Db::Sqlite(handle) => {
            sqlx::query(
                "INSERT INTO role_bindings (id, role_id, resource_pattern, principal_kind, \
                 principal_id) VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT (role_id, resource_pattern, principal_kind, principal_id) DO \
                 NOTHING",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(role_id.to_string())
            .bind(resource_pattern)
            .bind(principal_kind)
            .bind(principal_id.to_string())
            .execute(&handle.pool)
            .await?;
        }
    }
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct PgGrantRow {
    resource_pattern: String,
    permissions: Vec<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct SqliteGrantRow {
    resource_pattern: String,
    /// Comma-joined by SQLite's `GROUP_CONCAT` -- see the module doc
    /// comment for why the join/split round-trip is safe.
    permissions: String,
}

/// The real `PolicyStore` implementation, backed by whichever `Db` variant
/// is live. Constructed fresh per request in `grpc.rs` (cheap: an `Arc`
/// clone), matching the existing per-request-construction pattern.
pub struct DbPolicyStore(Arc<Db>);

impl DbPolicyStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self(db)
    }
}

#[async_trait]
impl PolicyStore for DbPolicyStore {
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

        let principal_kind = if principal.is_service_account {
            "service_account"
        } else {
            "user"
        };

        let (existing, rows): (HashSet<String>, Vec<(String, Vec<String>)>) = match self.0.as_ref()
        {
            Db::Postgres(handle) => {
                let existing_rows: Vec<String> = sqlx::query_scalar(
                    "SELECT resource_id FROM resources WHERE deleted_at IS NULL AND resource_id \
                     = ANY($1)",
                )
                .bind(requested_resource_ids)
                .fetch_all(&handle.pool)
                .await
                .map_err(|err| {
                    tracing::warn!(error = %err, principal_id = %principal.id, "resource existence query failed");
                    AuthzError::Internal
                })?;
                let existing: HashSet<String> = existing_rows.into_iter().collect();

                if existing.is_empty() {
                    return Ok(vec![]);
                }

                let rows: Vec<PgGrantRow> = sqlx::query_as(
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
                .fetch_all(&handle.pool)
                .await
                .map_err(|err| {
                    tracing::warn!(?err, "resolve_resource_permissions query failed");
                    AuthzError::Internal
                })?;

                (
                    existing,
                    rows.into_iter()
                        .map(|r| (r.resource_pattern, r.permissions))
                        .collect(),
                )
            }
            Db::Sqlite(handle) => {
                let placeholders = sqlite_placeholders(requested_resource_ids.len());
                let existing_sql = format!(
                    "SELECT resource_id FROM resources WHERE deleted_at IS NULL AND resource_id \
                     IN ({placeholders})"
                );
                let mut q = sqlx::query_scalar(&existing_sql);
                for id in requested_resource_ids {
                    q = q.bind(id.as_str());
                }
                let existing_rows: Vec<String> = q.fetch_all(&handle.pool).await.map_err(|err| {
                    tracing::warn!(error = %err, principal_id = %principal.id, "resource existence query failed");
                    AuthzError::Internal
                })?;
                let existing: HashSet<String> = existing_rows.into_iter().collect();

                if existing.is_empty() {
                    return Ok(vec![]);
                }

                let grant_sql = format!(
                    "SELECT rb.resource_pattern AS resource_pattern, \
                     GROUP_CONCAT(rp.permission) AS permissions \
                     FROM role_bindings rb \
                     JOIN roles r ON r.id = rb.role_id \
                     JOIN role_permissions rp ON rp.role_id = r.id \
                     WHERE ( \
                         (rb.principal_kind = ? AND rb.principal_id = ?) \
                         OR ( \
                             rb.principal_kind = 'group' \
                             AND rb.principal_id IN ( \
                                 SELECT group_id FROM group_members WHERE principal_id = ? \
                             ) \
                         ) \
                     ) \
                     AND (rb.resource_pattern = ? OR rb.resource_pattern IN ({placeholders})) \
                     GROUP BY rb.id, rb.resource_pattern"
                );
                let mut q = sqlx::query_as::<_, SqliteGrantRow>(&grant_sql);
                q = q
                    .bind(principal_kind)
                    .bind(principal.id.to_string())
                    .bind(principal.id.to_string())
                    .bind(WILDCARD_RESOURCE_PATTERN);
                for id in requested_resource_ids {
                    q = q.bind(id.as_str());
                }
                let rows: Vec<SqliteGrantRow> = q.fetch_all(&handle.pool).await.map_err(|err| {
                    tracing::warn!(?err, "resolve_resource_permissions query failed");
                    AuthzError::Internal
                })?;

                (
                    existing,
                    rows.into_iter()
                        .map(|r| {
                            (
                                r.resource_pattern,
                                r.permissions.split(',').map(str::to_string).collect(),
                            )
                        })
                        .collect(),
                )
            }
        };

        // BTreeMap keeps the result deterministically ordered by
        // resource_id -- LookupUserPermissions' own test asserts an EXACT
        // Vec, not just a set, so a stable order matters here. Only ids in
        // `existing` are ever inserted, regardless of which binding matched.
        // Shared between both backends: by this point `rows` is already
        // normalized to the same `Vec<(resource_pattern, Vec<permission>)>`
        // shape.
        let mut matched: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (resource_pattern, permissions) in rows {
            let perms: BTreeSet<String> = permissions.into_iter().collect();
            if resource_pattern == WILDCARD_RESOURCE_PATTERN {
                for id in requested_resource_ids {
                    if existing.contains(id) {
                        matched.entry(id.clone()).or_default().extend(perms.clone());
                    }
                }
            } else if existing.contains(&resource_pattern)
                && requested_resource_ids.contains(&resource_pattern)
            {
                matched
                    .entry(resource_pattern.clone())
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
