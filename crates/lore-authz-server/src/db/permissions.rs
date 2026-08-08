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

/// The three `principal_kind` values the `role_bindings` CHECK constraint
/// accepts on both backends. Exported so `crate::admin` validates against the
/// same list the database enforces, rather than a second copy that could
/// drift from it.
pub const PRINCIPAL_KINDS: [&str; 3] = ["user", "service_account", "group"];

/// Grants `role_id` to a principal (or group), either for one specific
/// `resource_pattern` (e.g. `"urc-abc123"`) or, via `WILDCARD_RESOURCE_
/// PATTERN`, for every `urc-*` resource. `principal_kind` must be one of
/// `PRINCIPAL_KINDS` (matches the `role_bindings` CHECK constraint on both
/// backends). Used by `tests/` and, through `create_grant`, by
/// `crate::admin` -- see `db::principals::insert_principal`'s doc comment for
/// why this is a plain `pub fn` rather than `#[cfg(test)]`-gated.
pub async fn grant(
    db: &Db,
    role_id: Uuid,
    resource_pattern: &str,
    principal_kind: &str,
    principal_id: Uuid,
) -> Result<(), sqlx::Error> {
    // Delegates to `create_grant` so there is ONE insert statement for a
    // role binding in this codebase, not two that could drift in their
    // conflict handling. The returned outcome is what the admin surface
    // reports to an operator; this older signature does not need it.
    create_grant(db, role_id, resource_pattern, principal_kind, principal_id)
        .await
        .map(|_| ())
}

/// Whether a grant was newly created, and its id either way. `AlreadyExists`
/// carries the EXISTING binding's id rather than erroring, because
/// re-granting something already granted is not a failure -- but the admin
/// surface still tells the operator which of the two happened instead of
/// reporting a create that did not create anything.
pub enum CreateGrantOutcome {
    Created(Uuid),
    AlreadyExists(Uuid),
}

impl CreateGrantOutcome {
    pub fn id(&self) -> Uuid {
        match self {
            CreateGrantOutcome::Created(id) | CreateGrantOutcome::AlreadyExists(id) => *id,
        }
    }
}

/// Creates a role binding and reports its id -- the admin surface needs the
/// id back so the operator can revoke exactly this binding later
/// (`delete_grant`).
///
/// This function performs NO validation of its own: `role_id` is FK-enforced,
/// but `principal_kind`/`principal_id` are the polymorphic pair the schema
/// explicitly cannot constrain (see `migrations/0001_identities_resources_
/// grants.sql`), and `resource_pattern` is a plain string. `crate::admin::ops`
/// is where those are checked before this is called; nothing else in this
/// crate creates a binding from untrusted input.
pub async fn create_grant(
    db: &Db,
    role_id: Uuid,
    resource_pattern: &str,
    principal_kind: &str,
    principal_id: Uuid,
) -> Result<CreateGrantOutcome, sqlx::Error> {
    let id = Uuid::new_v4();
    match db {
        Db::Postgres(handle) => {
            let inserted: Option<(Uuid,)> = sqlx::query_as(
                "INSERT INTO role_bindings (id, role_id, resource_pattern, principal_kind, \
                 principal_id) VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (role_id, resource_pattern, principal_kind, principal_id) DO \
                 NOTHING \
                 RETURNING id",
            )
            .bind(id)
            .bind(role_id)
            .bind(resource_pattern)
            .bind(principal_kind)
            .bind(principal_id)
            .fetch_optional(&handle.pool)
            .await?;
            if inserted.is_some() {
                return Ok(CreateGrantOutcome::Created(id));
            }

            let existing: Option<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM role_bindings WHERE role_id = $1 AND resource_pattern = $2 \
                 AND principal_kind = $3 AND principal_id = $4",
            )
            .bind(role_id)
            .bind(resource_pattern)
            .bind(principal_kind)
            .bind(principal_id)
            .fetch_optional(&handle.pool)
            .await?;
            // `None` here would mean the row vanished between the two
            // statements (a concurrent revoke). Reporting the id we tried to
            // insert would be a lie, so report the conflict against the id
            // the operator asked about -- `AlreadyExists` with a stale id is
            // still honest about the outcome, and the list endpoint is the
            // source of truth for what exists.
            Ok(CreateGrantOutcome::AlreadyExists(
                existing.map(|(id,)| id).unwrap_or(id),
            ))
        }
        Db::Sqlite(handle) => {
            let inserted: Option<(String,)> = sqlx::query_as(
                "INSERT INTO role_bindings (id, role_id, resource_pattern, principal_kind, \
                 principal_id) VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT (role_id, resource_pattern, principal_kind, principal_id) DO \
                 NOTHING \
                 RETURNING id",
            )
            .bind(id.to_string())
            .bind(role_id.to_string())
            .bind(resource_pattern)
            .bind(principal_kind)
            .bind(principal_id.to_string())
            .fetch_optional(&handle.pool)
            .await?;
            if inserted.is_some() {
                return Ok(CreateGrantOutcome::Created(id));
            }

            let existing: Option<(String,)> = sqlx::query_as(
                "SELECT id FROM role_bindings WHERE role_id = ? AND resource_pattern = ? \
                 AND principal_kind = ? AND principal_id = ?",
            )
            .bind(role_id.to_string())
            .bind(resource_pattern)
            .bind(principal_kind)
            .bind(principal_id.to_string())
            .fetch_optional(&handle.pool)
            .await?;
            Ok(CreateGrantOutcome::AlreadyExists(match existing {
                Some((raw,)) => parse_id("role_bindings.id", &raw)?,
                None => id,
            }))
        }
    }
}

/// Revokes exactly one role binding by id, returning whether a row was
/// actually deleted (`false` = no such binding, reported as a 404 by the
/// admin surface rather than a silent success).
///
/// The next `CheckUserPermission` / `LookupUserPermissions` / token exchange
/// stops honoring it, because `resolve_resource_permissions` re-reads
/// `role_bindings` on every request. An AuthZ token already issued keeps its
/// `resources` claim until it expires -- the stateless-revocation window
/// documented in `docs/protocol-notes.md`, unchanged by this surface.
pub async fn delete_grant(db: &Db, id: Uuid) -> Result<bool, sqlx::Error> {
    let rows_affected = match db {
        Db::Postgres(handle) => sqlx::query("DELETE FROM role_bindings WHERE id = $1")
            .bind(id)
            .execute(&handle.pool)
            .await?
            .rows_affected(),
        Db::Sqlite(handle) => sqlx::query("DELETE FROM role_bindings WHERE id = ?")
            .bind(id.to_string())
            .execute(&handle.pool)
            .await?
            .rows_affected(),
    };
    Ok(rows_affected == 1)
}

/// A role binding as the admin surface lists it, with the role's NAME joined
/// in: an operator revoking a grant needs to see "admin on urc-*", not a bare
/// pair of UUIDs.
#[derive(Debug, Clone)]
pub struct GrantSummary {
    pub id: Uuid,
    pub role_id: Uuid,
    pub role_name: String,
    pub resource_pattern: String,
    pub principal_kind: String,
    pub principal_id: Uuid,
}

/// Every role binding, for the admin list view. Ordered by
/// `(resource_pattern, role_name, principal_kind, principal_id)` so the
/// ordering is total and identical on both backends, and bounded by `limit`.
pub async fn list_grants(db: &Db, limit: i64) -> Result<Vec<GrantSummary>, sqlx::Error> {
    const ORDER_BY: &str =
        "ORDER BY rb.resource_pattern, r.name, rb.principal_kind, rb.principal_id";
    match db {
        Db::Postgres(handle) => {
            let rows: Vec<(Uuid, Uuid, String, String, String, Uuid)> = sqlx::query_as(&format!(
                "SELECT rb.id, rb.role_id, r.name, rb.resource_pattern, rb.principal_kind, \
                 rb.principal_id FROM role_bindings rb JOIN roles r ON r.id = rb.role_id \
                 {ORDER_BY} LIMIT $1"
            ))
            .bind(limit)
            .fetch_all(&handle.pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(
                    |(id, role_id, role_name, resource_pattern, principal_kind, principal_id)| {
                        GrantSummary {
                            id,
                            role_id,
                            role_name,
                            resource_pattern,
                            principal_kind,
                            principal_id,
                        }
                    },
                )
                .collect())
        }
        Db::Sqlite(handle) => {
            let rows: Vec<(String, String, String, String, String, String)> =
                sqlx::query_as(&format!(
                    "SELECT rb.id, rb.role_id, r.name, rb.resource_pattern, rb.principal_kind, \
                     rb.principal_id FROM role_bindings rb JOIN roles r ON r.id = rb.role_id \
                     {ORDER_BY} LIMIT ?"
                ))
                .bind(limit)
                .fetch_all(&handle.pool)
                .await?;
            rows.into_iter()
                .map(
                    |(id, role_id, role_name, resource_pattern, principal_kind, principal_id)| {
                        Ok(GrantSummary {
                            id: parse_id("role_bindings.id", &id)?,
                            role_id: parse_id("role_bindings.role_id", &role_id)?,
                            role_name,
                            resource_pattern,
                            principal_kind,
                            principal_id: parse_id("role_bindings.principal_id", &principal_id)?,
                        })
                    },
                )
                .collect()
        }
    }
}

/// A role and its advisory permission strings.
#[derive(Debug, Clone)]
pub struct RoleSummary {
    pub id: Uuid,
    pub name: String,
    pub permissions: Vec<String>,
}

/// The built-in roles, seeded by BOTH migration sets. Read-only by design:
/// there is no role CRUD anywhere in this product, and the admin surface
/// exposes only this list (see `crate::admin`).
///
/// The two backends store `permissions` differently -- a Postgres `text[]`
/// column versus a SQLite `role_permissions` join table (see this module's
/// doc comment) -- and both paths sort the permission strings in Rust,
/// because SQLite's `GROUP_CONCAT` does not promise an order and an
/// unstable list would make the two backends' output differ for no reason.
pub async fn list_roles(db: &Db) -> Result<Vec<RoleSummary>, sqlx::Error> {
    let mut roles: Vec<RoleSummary> = match db {
        Db::Postgres(handle) => {
            let rows: Vec<(Uuid, String, Vec<String>)> =
                sqlx::query_as("SELECT id, name, permissions FROM roles ORDER BY name")
                    .fetch_all(&handle.pool)
                    .await?;
            rows.into_iter()
                .map(|(id, name, permissions)| RoleSummary {
                    id,
                    name,
                    permissions,
                })
                .collect()
        }
        Db::Sqlite(handle) => {
            let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
                "SELECT r.id, r.name, GROUP_CONCAT(rp.permission) \
                 FROM roles r LEFT JOIN role_permissions rp ON rp.role_id = r.id \
                 GROUP BY r.id, r.name ORDER BY r.name",
            )
            .fetch_all(&handle.pool)
            .await?;
            rows.into_iter()
                .map(|(id, name, permissions)| {
                    Ok(RoleSummary {
                        id: parse_id("roles.id", &id)?,
                        name,
                        // LEFT JOIN + GROUP_CONCAT yields NULL, not an empty
                        // string, for a role with no permissions -- so an
                        // unwrap_or_default() here would produce `[""]`
                        // rather than `[]`.
                        permissions: permissions
                            .map(|joined| joined.split(',').map(str::to_string).collect())
                            .unwrap_or_default(),
                    })
                })
                .collect::<Result<Vec<_>, sqlx::Error>>()?
        }
    };
    for role in &mut roles {
        role.permissions.sort();
    }
    Ok(roles)
}

/// Parses a UUID stored as SQLite TEXT -- see
/// `db::principals::sqlite_row_into_principal`'s doc comment for why a
/// malformed value maps to `sqlx::Error::Decode`.
fn parse_id(column: &str, raw: &str) -> Result<Uuid, sqlx::Error> {
    Uuid::parse_str(raw)
        .map_err(|err| sqlx::Error::Decode(format!("{column} {raw:?}: {err}").into()))
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
