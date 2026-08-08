//! Groups and group membership. `insert_group` / `add_member` predate the
//! admin surface and are also used by `tests/` to seed the
//! group-inherited-grant case; the `list_*` / `remove_member` /
//! `insert_group_with_description` / `group_exists` functions back
//! `crate::admin` (SCIM group sync is still Phase 3, see tasks.md). Plain
//! `pub fn`, not `#[cfg(test)]`-gated -- see
//! `db::principals::insert_principal`'s doc comment for why. Dispatches on
//! `Db`'s variant internally (see `db/mod.rs`); ids are bound as their
//! canonical string form for SQLite (TEXT column, no native uuid type
//! there), natively for Postgres.

use uuid::Uuid;

use crate::db::Db;

/// A group as the admin surface lists it. Not `lore_authz_core::model::Group`
/// because that type is not what this table stores column-for-column; keeping
/// the row shape in this crate matches `db::principals`' arrangement (see its
/// module doc comment).
#[derive(Debug, Clone)]
pub struct GroupSummary {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source: String,
    pub status: String,
}

/// Whether an admin group create actually inserted, or collided with an
/// existing group. Reported, never swallowed -- see
/// `db::principals::InsertPrincipalOutcome`.
pub enum InsertGroupOutcome {
    Created,
    /// The `name` UNIQUE constraint (or, impossibly, the `id` primary key)
    /// already holds a row.
    DuplicateName,
}

pub async fn insert_group(db: &Db, id: Uuid, name: &str) -> Result<(), sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            sqlx::query(
                "INSERT INTO groups (id, name, source, status) VALUES ($1, $2, 'local', \
                 'active') ON CONFLICT (id) DO NOTHING",
            )
            .bind(id)
            .bind(name)
            .execute(&handle.pool)
            .await?;
        }
        Db::Sqlite(handle) => {
            sqlx::query(
                "INSERT INTO groups (id, name, source, status) VALUES (?, ?, 'local', \
                 'active') ON CONFLICT (id) DO NOTHING",
            )
            .bind(id.to_string())
            .bind(name)
            .execute(&handle.pool)
            .await?;
        }
    }
    Ok(())
}

/// Creates a group from the admin surface, with an optional description.
///
/// Separate from `insert_group` above rather than replacing it, on purpose:
/// that function's `ON CONFLICT (id) DO NOTHING` is the right idempotency for
/// a test fixture seeding a known id, while this one needs a bare
/// `ON CONFLICT DO NOTHING` (covering the `name` UNIQUE constraint too) so a
/// duplicate NAME can be reported to the operator instead of silently
/// doing nothing.
///
/// Creating a group grants nothing: a group with no `role_bindings` conveys no
/// access, and adding a member to it conveys exactly whatever the group has
/// been granted, which starts out as nothing.
pub async fn insert_group_with_description(
    db: &Db,
    id: Uuid,
    name: &str,
    description: Option<&str>,
) -> Result<InsertGroupOutcome, sqlx::Error> {
    let inserted = match db {
        Db::Postgres(handle) => {
            let row: Option<(Uuid,)> = sqlx::query_as(
                "INSERT INTO groups (id, name, description, source, status) \
                 VALUES ($1, $2, $3, 'local', 'active') \
                 ON CONFLICT DO NOTHING RETURNING id",
            )
            .bind(id)
            .bind(name)
            .bind(description)
            .fetch_optional(&handle.pool)
            .await?;
            row.is_some()
        }
        Db::Sqlite(handle) => {
            let row: Option<(String,)> = sqlx::query_as(
                "INSERT INTO groups (id, name, description, source, status) \
                 VALUES (?, ?, ?, 'local', 'active') \
                 ON CONFLICT DO NOTHING RETURNING id",
            )
            .bind(id.to_string())
            .bind(name)
            .bind(description)
            .fetch_optional(&handle.pool)
            .await?;
            row.is_some()
        }
    };

    Ok(if inserted {
        InsertGroupOutcome::Created
    } else {
        InsertGroupOutcome::DuplicateName
    })
}

/// Every group, for the admin list view. Ordered by `name` (which is UNIQUE,
/// so the ordering is already total) and bounded by `limit`.
pub async fn list_groups(db: &Db, limit: i64) -> Result<Vec<GroupSummary>, sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            let rows: Vec<(Uuid, String, Option<String>, String, String)> = sqlx::query_as(
                "SELECT id, name, description, source, status FROM groups ORDER BY name LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&handle.pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|(id, name, description, source, status)| GroupSummary {
                    id,
                    name,
                    description,
                    source,
                    status,
                })
                .collect())
        }
        Db::Sqlite(handle) => {
            let rows: Vec<(String, String, Option<String>, String, String)> = sqlx::query_as(
                "SELECT id, name, description, source, status FROM groups ORDER BY name LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&handle.pool)
            .await?;
            rows.into_iter()
                .map(|(id, name, description, source, status)| {
                    Ok(GroupSummary {
                        id: parse_id("groups.id", &id)?,
                        name,
                        description,
                        source,
                        status,
                    })
                })
                .collect()
        }
    }
}

/// Whether a group id exists. Used by `crate::admin` to validate a
/// `principal_kind = 'group'` role binding before creating it: the
/// `role_bindings.principal_id` column is polymorphic and therefore NOT
/// FK-enforced (see `migrations/0001_identities_resources_grants.sql`), so
/// "validated at the application layer" has to actually happen somewhere, and
/// this is where.
pub async fn group_exists(db: &Db, id: Uuid) -> Result<bool, sqlx::Error> {
    // Selects the id column itself rather than a literal `1`: the two
    // backends type an integer literal differently (Postgres `int4`, SQLite
    // `INTEGER`), and there is no reason to make this function's row type
    // backend-dependent when the column it is looking for is right there.
    Ok(match db {
        Db::Postgres(handle) => {
            let row: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM groups WHERE id = $1")
                .bind(id)
                .fetch_optional(&handle.pool)
                .await?;
            row.is_some()
        }
        Db::Sqlite(handle) => {
            let row: Option<(String,)> = sqlx::query_as("SELECT id FROM groups WHERE id = ?")
                .bind(id.to_string())
                .fetch_optional(&handle.pool)
                .await?;
            row.is_some()
        }
    })
}

/// The members of one group, as `(principal_id, display_name)`, for the admin
/// list view. Ordered by display name then id, matching
/// `db::principals::list_principals`.
pub async fn list_group_members(
    db: &Db,
    group_id: Uuid,
    limit: i64,
) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            let rows: Vec<(Uuid, String)> = sqlx::query_as(
                "SELECT p.id, p.display_name FROM group_members gm \
                 JOIN principals p ON p.id = gm.principal_id \
                 WHERE gm.group_id = $1 ORDER BY p.display_name, p.id LIMIT $2",
            )
            .bind(group_id)
            .bind(limit)
            .fetch_all(&handle.pool)
            .await?;
            Ok(rows)
        }
        Db::Sqlite(handle) => {
            let rows: Vec<(String, String)> = sqlx::query_as(
                "SELECT p.id, p.display_name FROM group_members gm \
                 JOIN principals p ON p.id = gm.principal_id \
                 WHERE gm.group_id = ? ORDER BY p.display_name, p.id LIMIT ?",
            )
            .bind(group_id.to_string())
            .bind(limit)
            .fetch_all(&handle.pool)
            .await?;
            rows.into_iter()
                .map(|(id, name)| Ok((parse_id("group_members.principal_id", &id)?, name)))
                .collect()
        }
    }
}

/// Removes a member, returning whether a row was actually deleted (`false` =
/// that principal was not in that group, which the admin surface reports
/// rather than treating as a successful revoke).
///
/// This is a real revocation lever: a grant held by the GROUP stops applying
/// to this principal at the next authorization call, since
/// `db::permissions::resolve_resource_permissions` re-reads `group_members` on
/// every request. Already-issued AuthZ tokens keep their `resources` claim
/// until they expire -- the same stateless-revocation window documented for
/// every other revoke in this product (see `docs/protocol-notes.md`).
pub async fn remove_member(
    db: &Db,
    group_id: Uuid,
    principal_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let rows_affected = match db {
        Db::Postgres(handle) => {
            sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND principal_id = $2")
                .bind(group_id)
                .bind(principal_id)
                .execute(&handle.pool)
                .await?
                .rows_affected()
        }
        Db::Sqlite(handle) => {
            sqlx::query("DELETE FROM group_members WHERE group_id = ? AND principal_id = ?")
                .bind(group_id.to_string())
                .bind(principal_id.to_string())
                .execute(&handle.pool)
                .await?
                .rows_affected()
        }
    };
    Ok(rows_affected == 1)
}

/// Parses a UUID stored as SQLite TEXT, mapping a malformed value to
/// `sqlx::Error::Decode` -- see `db::principals::sqlite_row_into_principal`'s
/// doc comment for why that is the right error variant here.
fn parse_id(column: &str, raw: &str) -> Result<Uuid, sqlx::Error> {
    Uuid::parse_str(raw)
        .map_err(|err| sqlx::Error::Decode(format!("{column} {raw:?}: {err}").into()))
}

pub async fn add_member(db: &Db, group_id: Uuid, principal_id: Uuid) -> Result<(), sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            sqlx::query(
                "INSERT INTO group_members (group_id, principal_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(group_id)
            .bind(principal_id)
            .execute(&handle.pool)
            .await?;
        }
        Db::Sqlite(handle) => {
            sqlx::query(
                "INSERT INTO group_members (group_id, principal_id) VALUES (?, ?) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(group_id.to_string())
            .bind(principal_id.to_string())
            .execute(&handle.pool)
            .await?;
        }
    }
    Ok(())
}
