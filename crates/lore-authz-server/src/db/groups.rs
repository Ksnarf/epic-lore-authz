//! Groups and group membership. There is no admin API or SCIM group sync
//! yet (Phase 2 / Phase 3, see tasks.md), so these are currently only used
//! by `tests/postgres_backed.rs` to seed the group-inherited-grant test
//! case. Plain `pub fn`, not `#[cfg(test)]`-gated -- see
//! `db::principals::insert_principal`'s doc comment for why.

use sqlx::PgPool;
use uuid::Uuid;

pub async fn insert_group(pool: &PgPool, id: Uuid, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO groups (id, name, source, status) VALUES ($1, $2, 'local', 'active') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn add_member(
    pool: &PgPool,
    group_id: Uuid,
    principal_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO group_members (group_id, principal_id) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
    )
    .bind(group_id)
    .bind(principal_id)
    .execute(pool)
    .await?;
    Ok(())
}
