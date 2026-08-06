//! Groups and group membership. There is no admin API or SCIM group sync
//! yet (Phase 2 / Phase 3, see tasks.md), so these are currently only used
//! by `tests/` to seed the group-inherited-grant test case. Plain `pub fn`,
//! not `#[cfg(test)]`-gated -- see `db::principals::insert_principal`'s doc
//! comment for why. Dispatches on `Db`'s variant internally (see
//! `db/mod.rs`); ids are bound as their canonical string form for SQLite
//! (TEXT column, no native uuid type there), natively for Postgres.

use uuid::Uuid;

use crate::db::Db;

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
