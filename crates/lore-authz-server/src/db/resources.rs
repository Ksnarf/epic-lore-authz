//! Backs `RebacApi::CreateResource` / `DeleteResource`, and the candidate
//! resource lookup `LookupUserPermissions` restricts permission resolution
//! to (see `crates/lore-authz-server/src/db/permissions.rs` and
//! `crates/lore-authz-server/src/grpc.rs`).
//!
//! Every function here dispatches on `Db`'s variant (Postgres vs SQLite --
//! see `db/mod.rs`'s module doc comment) internally, so callers never branch
//! on backend themselves.

use crate::db::Db;

pub enum CreateResourceOutcome {
    Created,
    /// Mirrors lore-server's own idempotency expectation (see
    /// `repository_create_auth_resource` in the lore-server fork this repo
    /// implements against): `Code::AlreadyExists` from `CreateResource` is
    /// treated as success by the caller, so this is a normal, common
    /// outcome, not an error condition.
    AlreadyExists,
}

/// Creates a resource row. Idempotent in the sense lore-server needs:
/// calling this twice with the same `resource_id` returns `AlreadyExists`
/// the second time rather than erroring, matching lore-server's own
/// "AlreadyExists is a successful create" handling. Does not "undelete" a
/// soft-deleted resource with the same id (a known, documented
/// simplification for this ephemeral deliverable phase -- see tasks.md
/// "PHASE 1a"); the practical case (a real repository id being reused after
/// its resource was deleted) is not expected to occur.
pub async fn create_resource(
    db: &Db,
    resource_id: &str,
    resource_name: &str,
) -> Result<CreateResourceOutcome, sqlx::Error> {
    let created = match db {
        Db::Postgres(handle) => {
            let inserted: Option<(String,)> = sqlx::query_as(
                "INSERT INTO resources (resource_id, resource_name) VALUES ($1, $2) \
                 ON CONFLICT (resource_id) DO NOTHING \
                 RETURNING resource_id",
            )
            .bind(resource_id)
            .bind(resource_name)
            .fetch_optional(&handle.pool)
            .await?;
            inserted.is_some()
        }
        Db::Sqlite(handle) => {
            // SQLite (bundled via libsqlite3-sys) supports both RETURNING
            // and ON CONFLICT ... DO NOTHING (upsert), so this is the same
            // shape as the Postgres query above, just plain `?` placeholders
            // (this module tree's SQLite convention -- see db/principals.rs).
            let inserted: Option<(String,)> = sqlx::query_as(
                "INSERT INTO resources (resource_id, resource_name) VALUES (?, ?) \
                 ON CONFLICT (resource_id) DO NOTHING \
                 RETURNING resource_id",
            )
            .bind(resource_id)
            .bind(resource_name)
            .fetch_optional(&handle.pool)
            .await?;
            inserted.is_some()
        }
    };

    Ok(if created {
        CreateResourceOutcome::Created
    } else {
        CreateResourceOutcome::AlreadyExists
    })
}

/// Soft-deletes a resource row (sets `deleted_at`), for an audit trail.
/// Idempotent: deleting an already-deleted or never-existing resource_id is
/// NOT an error (0 rows affected is a normal outcome), mirroring
/// `create_resource`'s "AlreadyExists is success" symmetry -- lore-server's
/// own `repository_delete_auth_resource` call site does not special-case a
/// not-found response either.
pub async fn delete_resource(db: &Db, resource_id: &str) -> Result<(), sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            sqlx::query(
                "UPDATE resources SET deleted_at = now() \
                 WHERE resource_id = $1 AND deleted_at IS NULL",
            )
            .bind(resource_id)
            .execute(&handle.pool)
            .await?;
        }
        Db::Sqlite(handle) => {
            // SQLite has no now(); nothing in this codebase parses
            // deleted_at back into Rust (only IS NULL / overwrite), so a
            // plain ISO-8601 UTC text value is sufficient -- see
            // migrations_sqlite/0001_identities_resources_grants.sql.
            sqlx::query(
                "UPDATE resources SET deleted_at = datetime('now') \
                 WHERE resource_id = ? AND deleted_at IS NULL",
            )
            .bind(resource_id)
            .execute(&handle.pool)
            .await?;
        }
    }
    Ok(())
}

/// A resource as the admin surface lists it. Includes soft-deleted rows,
/// flagged -- an operator needs to see that a resource EXISTS BUT IS DELETED
/// (which is why access to it is denied), and a list that silently hid them
/// would make a deleted resource look like a missing one.
#[derive(Debug, Clone)]
pub struct ResourceSummary {
    pub resource_id: String,
    pub resource_name: String,
    pub deleted: bool,
}

/// Every resource, deleted ones included and flagged, for the admin list
/// view. Ordered by `resource_id` (the primary key, so the ordering is total)
/// and bounded by `limit`.
///
/// Deliberately NOT reusing `list_resource_ids_with_prefix` below: that
/// function is an AUTHORIZATION input (`LookupUserPermissions`' candidate
/// set) and must keep excluding deleted rows. Giving it an
/// "include deleted" flag would put a boolean between an authorization path
/// and the rows it is allowed to consider, which is exactly the kind of
/// parameter that gets passed wrong once.
pub async fn list_resources(db: &Db, limit: i64) -> Result<Vec<ResourceSummary>, sqlx::Error> {
    let rows: Vec<(String, String, bool)> = match db {
        Db::Postgres(handle) => {
            sqlx::query_as(
                "SELECT resource_id, resource_name, (deleted_at IS NOT NULL) AS deleted \
                 FROM resources ORDER BY resource_id LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&handle.pool)
            .await?
        }
        Db::Sqlite(handle) => {
            sqlx::query_as(
                "SELECT resource_id, resource_name, (deleted_at IS NOT NULL) AS deleted \
                 FROM resources ORDER BY resource_id LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&handle.pool)
            .await?
        }
    };

    Ok(rows
        .into_iter()
        .map(|(resource_id, resource_name, deleted)| ResourceSummary {
            resource_id,
            resource_name,
            deleted,
        })
        .collect())
}

/// Candidate resource ids for `LookupUserPermissions`: every NOT-deleted
/// resource whose id starts with `prefix` (lore-server's real call site
/// sends the literal string `"urc"` -- see
/// `crates/lore-authz-server/src/grpc.rs` and tasks.md "PHASE 1a" for the
/// chosen `resource_filter` semantics: a plain prefix match, empty matches
/// everything). `%` and `_` in `prefix` are escaped so an operator-controlled
/// filter value can never be misread as a SQL `LIKE` wildcard.
pub async fn list_resource_ids_with_prefix(
    db: &Db,
    prefix: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let escaped = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let pattern = format!("{escaped}%");

    let rows: Vec<(String,)> = match db {
        Db::Postgres(handle) => {
            sqlx::query_as(
                "SELECT resource_id FROM resources \
                 WHERE deleted_at IS NULL AND resource_id LIKE $1 ESCAPE '\\' \
                 ORDER BY resource_id",
            )
            .bind(pattern)
            .fetch_all(&handle.pool)
            .await?
        }
        Db::Sqlite(handle) => {
            // SQLite's LIKE ... ESCAPE works the same way as Postgres's.
            sqlx::query_as(
                "SELECT resource_id FROM resources \
                 WHERE deleted_at IS NULL AND resource_id LIKE ? ESCAPE '\\' \
                 ORDER BY resource_id",
            )
            .bind(pattern)
            .fetch_all(&handle.pool)
            .await?
        }
    };

    Ok(rows.into_iter().map(|(id,)| id).collect())
}
