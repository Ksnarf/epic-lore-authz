//! Backs `RebacApi::CreateResource` / `DeleteResource`, and the candidate
//! resource lookup `LookupUserPermissions` restricts permission resolution
//! to (see `crates/lore-authz-server/src/db/permissions.rs` and
//! `crates/lore-authz-server/src/grpc.rs`).

use sqlx::PgPool;

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
    pool: &PgPool,
    resource_id: &str,
    resource_name: &str,
) -> Result<CreateResourceOutcome, sqlx::Error> {
    let inserted: Option<(String,)> = sqlx::query_as(
        "INSERT INTO resources (resource_id, resource_name) VALUES ($1, $2) \
         ON CONFLICT (resource_id) DO NOTHING \
         RETURNING resource_id",
    )
    .bind(resource_id)
    .bind(resource_name)
    .fetch_optional(pool)
    .await?;

    Ok(if inserted.is_some() {
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
pub async fn delete_resource(pool: &PgPool, resource_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE resources SET deleted_at = now() \
         WHERE resource_id = $1 AND deleted_at IS NULL",
    )
    .bind(resource_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Candidate resource ids for `LookupUserPermissions`: every NOT-deleted
/// resource whose id starts with `prefix` (lore-server's real call site
/// sends the literal string `"urc"` -- see
/// `crates/lore-authz-server/src/grpc.rs` and tasks.md "PHASE 1a" for the
/// chosen `resource_filter` semantics: a plain prefix match, empty matches
/// everything). `%` and `_` in `prefix` are escaped so an operator-controlled
/// filter value can never be misread as a SQL `LIKE` wildcard.
pub async fn list_resource_ids_with_prefix(
    pool: &PgPool,
    prefix: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let escaped = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let pattern = format!("{escaped}%");

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT resource_id FROM resources \
         WHERE deleted_at IS NULL AND resource_id LIKE $1 ESCAPE '\\' \
         ORDER BY resource_id",
    )
    .bind(pattern)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}
