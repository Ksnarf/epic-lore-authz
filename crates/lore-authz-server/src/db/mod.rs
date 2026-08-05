//! Postgres-backed persistence for identities, groups, resources, and
//! permission grants -- PHASE 1a (see tasks.md): `LookupUserPermissions`,
//! `CheckUserPermission`, and `RebacApi::CreateResource` / `DeleteResource`.
//! This is the only part of epic-lore-authz that talks to Postgres so far;
//! `auth_sessions` / `signing_keys` persistence / `audit_log` are later
//! phases and still do not exist.
//!
//! ## Ephemeral-deliverable constraints (see docs/configuration.md)
//! This product owns exactly ONE schema inside whatever database it is
//! pointed at via `DATABASE_URL`, named by `DB_SCHEMA` (never `public`,
//! never a dedicated database, never superuser -- see `validate_schema_
//! identifier` below and `docs/configuration.md`). Every pooled connection
//! has its `search_path` set to that one schema in `after_connect`, so every
//! migration file and every query in this module tree is schema-UNQUALIFIED
//! on purpose: do not hardcode the schema name anywhere else in this crate.
//!
//! Only the runtime-checked `sqlx::query` / `sqlx::query_as` APIs are used
//! anywhere in this module tree, never the compile-time-checked `query!` /
//! `query_as!` macros -- those require a reachable Postgres (or a `.sqlx`
//! offline cache) at `cargo build` time, which this project's pinned build
//! image (`docker/Dockerfile.build`) does not have. `cargo build` must never
//! need Postgres; only the tests in `tests/postgres_backed.rs` do.

use sqlx::Executor;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub mod groups;
pub mod permissions;
pub mod principals;
pub mod resources;

/// Only plain SQL identifiers are accepted for `DB_SCHEMA`. It is
/// operator-controlled, not attacker input, but neither `CREATE SCHEMA` nor
/// `SET search_path` lets an identifier be passed as a bound query
/// parameter (only values can be bound) -- this guards against a
/// misconfigured `DB_SCHEMA` producing a string that can't be safely
/// interpolated into that SQL, and against accidentally pointing at
/// `public`, which this product must never touch (see
/// docs/configuration.md).
fn validate_schema_identifier(schema: &str) -> anyhow::Result<()> {
    let mut chars = schema.chars();
    let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_');
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    anyhow::ensure!(
        !schema.is_empty() && first_ok && rest_ok && schema.len() <= 63,
        "DB_SCHEMA {schema:?} is not a plain SQL identifier (ASCII letters/digits/underscore, \
         must not start with a digit, max 63 bytes)"
    );
    anyhow::ensure!(
        !schema.eq_ignore_ascii_case("public"),
        "DB_SCHEMA must not be \"public\" -- this product owns exactly one non-public schema"
    );
    Ok(())
}

/// A connected, schema-scoped Postgres handle with the embedded migrations
/// already applied.
pub struct Db {
    pool: PgPool,
    schema: String,
}

impl Db {
    /// Connects to `database_url`, creates `schema` if it does not already
    /// exist (never `public`, never `CREATE DATABASE`; requires only
    /// `CREATE` on the target database, not superuser), points every pooled
    /// connection's `search_path` at it, and runs the embedded migrations.
    ///
    /// Safe to call more than once against the same database/schema:
    /// `CREATE SCHEMA IF NOT EXISTS` is a no-op on the second call, and
    /// sqlx's migrator tracks which migrations already applied inside that
    /// schema's own history table (see `migrate` below).
    pub async fn connect(database_url: &str, schema: &str) -> anyhow::Result<Self> {
        validate_schema_identifier(schema)?;

        // A short-lived bootstrap connection creates the schema itself.
        // `SET search_path` (used below, on every pooled connection) does
        // NOT fail for a schema that does not exist yet, but an unqualified
        // `CREATE TABLE` inside a migration needs the schema to already
        // exist and be first-resolvable in search_path -- so the schema
        // must exist before any pooled connection is handed to the
        // migrator.
        let bootstrap = PgPool::connect(database_url).await?;
        bootstrap
            .execute(format!("CREATE SCHEMA IF NOT EXISTS \"{schema}\"").as_str())
            .await?;
        bootstrap.close().await;

        let schema_for_hook = schema.to_string();
        let pool = PgPoolOptions::new()
            .after_connect(move |conn, _meta| {
                let schema = schema_for_hook.clone();
                Box::pin(async move {
                    conn.execute(format!("SET search_path TO \"{schema}\"").as_str())
                        .await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await?;

        let db = Db {
            pool,
            schema: schema.to_string(),
        };
        db.migrate().await?;
        Ok(db)
    }

    /// Runs the embedded migrations (`./migrations`, relative to this
    /// crate). Idempotent: sqlx tracks already-applied migrations in this
    /// schema's own `_sqlx_migrations` table (created inside `schema`
    /// because of the `search_path` every pooled connection gets above --
    /// never in `public`), so calling this twice is a no-op the second
    /// time. See `tests/postgres_backed.rs`'s `migrations_are_idempotent`.
    pub async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }
}
