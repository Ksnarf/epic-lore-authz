//! Persistence for identities, groups, resources, and permission grants --
//! PHASE 1a (see tasks.md): `LookupUserPermissions`, `CheckUserPermission`,
//! and `RebacApi::CreateResource` / `DeleteResource`. This is the only part
//! of epic-lore-authz that talks to a database so far; `auth_sessions` /
//! `signing_keys` persistence / `audit_log` are later phases and still do
//! not exist.
//!
//! ## Two backends, selected at runtime from `DATABASE_URL`'s scheme
//! `postgres://` / `postgresql://` -> Postgres (multi-replica, required
//! behind a load balancer -- see README.md and docs/configuration.md).
//! `sqlite:` -> SQLite (dev / single-instance ONLY: SQLite's single-writer
//! lock makes it the wrong choice behind a load balancer; nothing in this
//! product coordinates writers across processes). `Db` is the one type the
//! rest of this crate holds; `db::resources` / `db::principals` /
//! `db::groups` / `db::permissions` each dispatch on `Db`'s variant
//! internally, so `crates/lore-authz-server/src/grpc.rs` and `tests/` never
//! need to know which backend is live.
//!
//! ## Ephemeral-deliverable constraints (Postgres only -- see
//! docs/configuration.md)
//! Under Postgres, this product owns exactly ONE schema inside whatever
//! database it is pointed at via `DATABASE_URL`, named by `DB_SCHEMA` (never
//! `public`, never a dedicated database, never superuser -- see
//! `validate_schema_identifier` below). Every pooled connection has its
//! `search_path` set to that one schema in `after_connect`, so every
//! Postgres migration file and every Postgres query in this module tree is
//! schema-UNQUALIFIED on purpose.
//!
//! `DB_SCHEMA` has NO EQUIVALENT under SQLite (SQLite has no schema
//! concept) and is an explicit, logged no-op there -- see `Db::connect`'s
//! sqlite branch below and docs/configuration.md. It does not error, and it
//! does not silently do nothing without saying so.
//!
//! Only the runtime-checked `sqlx::query` / `sqlx::query_as` APIs are used
//! anywhere in this module tree, never the compile-time-checked `query!` /
//! `query_as!` macros -- those require a reachable database (or a `.sqlx`
//! offline cache) at `cargo build` time, which this project's pinned build
//! image (`docker/Dockerfile.build`) does not have. `cargo build` must never
//! need a live database; only the tests in `tests/` do.

use std::str::FromStr;

use sqlx::Executor;
use sqlx::PgPool;
use sqlx::SqlitePool;
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::sqlite::SqlitePoolOptions;

pub mod groups;
pub mod permissions;
pub mod principals;
pub mod resources;

/// Only plain SQL identifiers are accepted for `DB_SCHEMA` (Postgres only --
/// see the module doc comment). It is operator-controlled, not attacker
/// input, but neither `CREATE SCHEMA` nor `SET search_path` lets an
/// identifier be passed as a bound query parameter (only values can be
/// bound) -- this guards against a misconfigured `DB_SCHEMA` producing a
/// string that can't be safely interpolated into that SQL, and against
/// accidentally pointing at `public`, which this product must never touch.
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

/// A connected, migrated Postgres handle: the multi-replica-safe backend
/// (see the module doc comment).
pub struct PostgresHandle {
    pool: PgPool,
    schema: String,
}

/// A connected, migrated SQLite handle: the dev/single-instance-ONLY
/// backend. No `schema` field -- SQLite has none; see `Db::schema`.
pub struct SqliteHandle {
    pool: SqlitePool,
}

/// The one persistence handle the rest of this crate holds. Which variant
/// is live is decided once, at startup, from `DATABASE_URL`'s scheme (see
/// `Db::connect`) -- nothing downstream re-checks it per call.
pub enum Db {
    Postgres(PostgresHandle),
    Sqlite(SqliteHandle),
}

impl Db {
    /// Connects to `database_url`, selecting the backend from its scheme
    /// (`postgres://` / `postgresql://` vs `sqlite:`), and runs that
    /// backend's embedded migrations (`./migrations` for Postgres,
    /// `./migrations_sqlite` for SQLite -- see both directories' own doc
    /// comments for why they are kept separate, not shared, and how they
    /// are kept in step).
    ///
    /// `db_schema` (`DB_SCHEMA`) is Postgres-only: under Postgres it names
    /// the one non-`public` schema this product owns (never a dedicated
    /// database, never superuser). Under SQLite it is an explicit no-op --
    /// logged, not silently ignored, per docs/configuration.md -- because
    /// SQLite has no schema concept at all.
    ///
    /// Safe to call more than once against the same database/schema/file:
    /// schema/file creation is idempotent, and sqlx's migrator tracks which
    /// migrations already applied in its own history table.
    pub async fn connect(database_url: &str, db_schema: &str) -> anyhow::Result<Self> {
        if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
            Self::connect_postgres(database_url, db_schema).await
        } else if database_url.starts_with("sqlite:") {
            Self::connect_sqlite(database_url, db_schema).await
        } else {
            anyhow::bail!(
                "unsupported DATABASE_URL scheme (expected \"postgres://\" or \"sqlite:\"): \
                 {database_url:?} -- see docs/configuration.md"
            )
        }
    }

    async fn connect_postgres(database_url: &str, schema: &str) -> anyhow::Result<Self> {
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

        let db = Db::Postgres(PostgresHandle {
            pool,
            schema: schema.to_string(),
        });
        db.migrate().await?;
        Ok(db)
    }

    async fn connect_sqlite(database_url: &str, db_schema: &str) -> anyhow::Result<Self> {
        // DB_SCHEMA no-op, LOGGED not silent -- see the module doc comment
        // and docs/configuration.md. Always noted at info level; escalated
        // to a warning if the operator set it to something other than the
        // documented default, since that specifically suggests they expect
        // it to do something here.
        if db_schema == "loreauth" {
            tracing::info!(
                "DB_SCHEMA is a no-op under the sqlite:// backend (SQLite has no schema \
                 concept) -- see docs/configuration.md"
            );
        } else {
            tracing::warn!(
                db_schema,
                "DB_SCHEMA is set but has NO EFFECT under the sqlite:// backend (SQLite has no \
                 schema concept) -- see docs/configuration.md"
            );
        }

        let options = SqliteConnectOptions::from_str(database_url)?.create_if_missing(true);
        let pool = SqlitePoolOptions::new().connect_with(options).await?;

        let db = Db::Sqlite(SqliteHandle { pool });
        db.migrate().await?;
        Ok(db)
    }

    /// Runs the embedded migrations for whichever backend is live. Safe to
    /// call twice: sqlx tracks already-applied migrations in its own
    /// history table, kept inside `DB_SCHEMA` for Postgres (never `public`)
    /// and in the one SQLite database for SQLite. See
    /// `tests/authz_suite`'s `migrations_are_idempotent`, run against BOTH
    /// backends.
    pub async fn migrate(&self) -> anyhow::Result<()> {
        match self {
            Db::Postgres(handle) => {
                sqlx::migrate!("./migrations").run(&handle.pool).await?;
            }
            Db::Sqlite(handle) => {
                sqlx::migrate!("./migrations_sqlite")
                    .run(&handle.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// The active Postgres schema, or a fixed string explaining why SQLite
    /// has none -- used only for startup logging (`main.rs`).
    pub fn schema(&self) -> &str {
        match self {
            Db::Postgres(handle) => &handle.schema,
            Db::Sqlite(_) => "(sqlite: no schema concept -- DB_SCHEMA is a no-op)",
        }
    }

    /// A short, human-readable name for startup logging.
    pub fn backend_name(&self) -> &'static str {
        match self {
            Db::Postgres(_) => "postgres",
            Db::Sqlite(_) => "sqlite (dev/single-instance ONLY -- see docs/configuration.md)",
        }
    }

    /// Closes the underlying connection pool. Used by
    /// `tests/authz_suite`'s `database_failure_denies_rather_than_grants` to
    /// simulate a real database failure out from under an otherwise fully
    /// authorized request, against BOTH backends -- not a normal shutdown
    /// path (nothing in `main.rs` calls this).
    pub async fn close(&self) {
        match self {
            Db::Postgres(handle) => handle.pool.close().await,
            Db::Sqlite(handle) => handle.pool.close().await,
        }
    }
}
