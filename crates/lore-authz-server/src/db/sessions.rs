//! Persistence for the `StartAuthSession` / `GetAuthSession` login session
//! (PHASE 1b, see tasks.md). Backs `auth_sessions` on both database
//! backends; see `migrations/0002_auth_sessions.sql` for the schema and for
//! why each column is stored hashed or raw.
//!
//! ## The state machine, and where it is enforced
//! `pending` -> `authenticated` -> `consumed`, forwards only. Both
//! transitions are conditional UPDATEs whose WHERE clause contains the
//! expected current state, and both report how many rows they changed. That
//! is what makes single-use real rather than aspirational: two concurrent
//! polls of the same authenticated session race on ONE `UPDATE ... WHERE
//! status = 'authenticated'`, and the database guarantees exactly one of
//! them sees `rows_affected == 1`. A read-then-write in Rust would not.
//!
//! ## Expiry is checked in SQL, not only in Rust
//! Every state-changing statement carries `AND expires_at_ms > ?`, so an
//! expired session cannot be authenticated or consumed even if a caller
//! forgets to check the row it read. `find_*` deliberately does NOT filter
//! on expiry: callers need to distinguish "no such session" from "expired
//! session" internally even though both look identical to a client (see
//! `crate::grpc`'s `get_auth_session`).

use uuid::Uuid;

use crate::db::Db;

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_AUTHENTICATED: &str = "authenticated";
pub const STATUS_CONSUMED: &str = "consumed";

/// Everything `StartAuthSession` inserts. All three `*_hash` fields are
/// SHA-256 fingerprints (`crate::secret::sha256_b64url`); `oidc_state`,
/// `oidc_nonce` and `pkce_verifier` are raw because the login leg has to
/// reproduce them, not just recognize them -- see the migration's comment.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub session_code_hash: String,
    pub login_code_hash: String,
    pub client_state_hash: String,
    pub oidc_state: String,
    pub oidc_nonce: String,
    pub pkce_verifier: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

/// A session as read back. Deliberately does NOT expose `session_code_hash`
/// or `login_code_hash`: a caller that already looked a session up by one of
/// those has no further use for them, and not returning them keeps them out
/// of logs and error messages by construction.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub client_state_hash: String,
    pub oidc_state: String,
    pub oidc_nonce: String,
    pub pkce_verifier: String,
    pub status: String,
    pub principal_id: Option<Uuid>,
    pub expires_at_ms: i64,
    /// Path A IdP groups support (see `docs/configuration.md` and
    /// `migrations/0003_auth_session_groups.sql`): a login-time snapshot of
    /// the groups the identity provider reported, set by
    /// `mark_authenticated` and read back by `crate::login::poll_session`.
    /// `None` until authenticated, and also `None` after authentication if
    /// the IdP never emitted the configured claim.
    pub groups: Option<Vec<String>>,
}

impl SessionRow {
    pub fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_at_ms <= now_ms
    }
}

#[derive(Debug, sqlx::FromRow)]
struct PgSessionRow {
    client_state_hash: String,
    oidc_state: String,
    oidc_nonce: String,
    pkce_verifier: String,
    status: String,
    principal_id: Option<Uuid>,
    expires_at_ms: i64,
    groups_json: Option<String>,
}

/// Same shape, but `principal_id` as the TEXT SQLite stores (see
/// `db/principals.rs`'s module doc comment for why this crate converts UUIDs
/// explicitly at the boundary rather than relying on sqlx's SQLite blob
/// encoding).
#[derive(Debug, sqlx::FromRow)]
struct SqliteSessionRow {
    client_state_hash: String,
    oidc_state: String,
    oidc_nonce: String,
    pkce_verifier: String,
    status: String,
    principal_id: Option<String>,
    expires_at_ms: i64,
    groups_json: Option<String>,
}

/// `groups_json` is a JSON-encoded array of strings, or NULL -- see
/// `migrations/0003_auth_session_groups.sql`. A decode failure here means
/// something wrote the column outside `mark_authenticated`, which is a real
/// corruption, not a "no groups" case; it is surfaced as an error rather
/// than silently treated as `None`.
fn parse_groups_json(raw: Option<String>) -> Result<Option<Vec<String>>, sqlx::Error> {
    match raw {
        None => Ok(None),
        Some(raw) => serde_json::from_str(&raw).map(Some).map_err(|err| {
            sqlx::Error::Decode(format!("auth_sessions.groups_json {raw:?}: {err}").into())
        }),
    }
}

fn pg_row_into_session(row: PgSessionRow) -> Result<SessionRow, sqlx::Error> {
    Ok(SessionRow {
        client_state_hash: row.client_state_hash,
        oidc_state: row.oidc_state,
        oidc_nonce: row.oidc_nonce,
        pkce_verifier: row.pkce_verifier,
        status: row.status,
        principal_id: row.principal_id,
        expires_at_ms: row.expires_at_ms,
        groups: parse_groups_json(row.groups_json)?,
    })
}

fn sqlite_row_into_session(row: SqliteSessionRow) -> Result<SessionRow, sqlx::Error> {
    let principal_id = match row.principal_id {
        Some(raw) => Some(Uuid::parse_str(&raw).map_err(|err| {
            sqlx::Error::Decode(format!("auth_sessions.principal_id {raw:?}: {err}").into())
        })?),
        None => None,
    };
    Ok(SessionRow {
        client_state_hash: row.client_state_hash,
        oidc_state: row.oidc_state,
        oidc_nonce: row.oidc_nonce,
        pkce_verifier: row.pkce_verifier,
        status: row.status,
        principal_id,
        expires_at_ms: row.expires_at_ms,
        groups: parse_groups_json(row.groups_json)?,
    })
}

const SELECT_COLUMNS: &str = "client_state_hash, oidc_state, oidc_nonce, pkce_verifier, status, \
                              principal_id, expires_at_ms, groups_json";

pub async fn insert(db: &Db, session: &NewSession) -> Result<(), sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            sqlx::query(
                "INSERT INTO auth_sessions (session_code_hash, login_code_hash, \
                 client_state_hash, oidc_state, oidc_nonce, pkce_verifier, status, \
                 created_at_ms, expires_at_ms) \
                 VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)",
            )
            .bind(&session.session_code_hash)
            .bind(&session.login_code_hash)
            .bind(&session.client_state_hash)
            .bind(&session.oidc_state)
            .bind(&session.oidc_nonce)
            .bind(&session.pkce_verifier)
            .bind(session.created_at_ms)
            .bind(session.expires_at_ms)
            .execute(&handle.pool)
            .await?;
        }
        Db::Sqlite(handle) => {
            sqlx::query(
                "INSERT INTO auth_sessions (session_code_hash, login_code_hash, \
                 client_state_hash, oidc_state, oidc_nonce, pkce_verifier, status, \
                 created_at_ms, expires_at_ms) \
                 VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
            )
            .bind(&session.session_code_hash)
            .bind(&session.login_code_hash)
            .bind(&session.client_state_hash)
            .bind(&session.oidc_state)
            .bind(&session.oidc_nonce)
            .bind(&session.pkce_verifier)
            .bind(session.created_at_ms)
            .bind(session.expires_at_ms)
            .execute(&handle.pool)
            .await?;
        }
    }
    Ok(())
}

async fn find_by(db: &Db, column: &str, value: &str) -> Result<Option<SessionRow>, sqlx::Error> {
    // `column` is one of three hardcoded &'static str values, chosen by this
    // module's own three public wrappers below -- never caller input, never
    // a value. The bound parameter is the only thing that comes from
    // outside, and the debug_assert makes a future fourth caller passing
    // something else fail loudly in tests rather than quietly build SQL.
    debug_assert!(matches!(
        column,
        "session_code_hash" | "login_code_hash" | "oidc_state"
    ));
    match db {
        Db::Postgres(handle) => {
            let row: Option<PgSessionRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_COLUMNS} FROM auth_sessions WHERE {column} = $1"
            ))
            .bind(value)
            .fetch_optional(&handle.pool)
            .await?;
            row.map(pg_row_into_session).transpose()
        }
        Db::Sqlite(handle) => {
            let row: Option<SqliteSessionRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_COLUMNS} FROM auth_sessions WHERE {column} = ?"
            ))
            .bind(value)
            .fetch_optional(&handle.pool)
            .await?;
            row.map(sqlite_row_into_session).transpose()
        }
    }
}

/// Looks a session up by the SHA-256 of the `session_code` the CLI polls
/// with. Returns expired sessions too -- see the module doc comment.
pub async fn find_by_session_code_hash(
    db: &Db,
    session_code_hash: &str,
) -> Result<Option<SessionRow>, sqlx::Error> {
    find_by(db, "session_code_hash", session_code_hash).await
}

/// Looks a session up by the SHA-256 of the `login_code` embedded in the
/// browser login URL.
pub async fn find_by_login_code_hash(
    db: &Db,
    login_code_hash: &str,
) -> Result<Option<SessionRow>, sqlx::Error> {
    find_by(db, "login_code_hash", login_code_hash).await
}

/// Looks a session up by the OIDC `state` the IdP echoed back on the
/// redirect. This IS the state validation's lookup: an unrecognized `state`
/// simply finds nothing, and the callback fails closed.
pub async fn find_by_oidc_state(
    db: &Db,
    oidc_state: &str,
) -> Result<Option<SessionRow>, sqlx::Error> {
    find_by(db, "oidc_state", oidc_state).await
}

/// `pending` -> `authenticated`, binding the session to `principal_id` and
/// to this login's groups snapshot.
///
/// Returns whether the transition actually happened. It does NOT happen if
/// the session is already authenticated (a replayed IdP callback), already
/// consumed, or expired -- all three are ordinary, expected outcomes of a
/// hostile or a merely slow browser, not errors. The caller decides what to
/// show; this function's job is to make the transition atomic.
///
/// `groups_json` is the already-extracted-and-filtered groups claim
/// (`crate::oidc::extract_groups`), pre-encoded as a JSON array of strings
/// by the caller (`crate::oidc_login::complete_callback`). `None` means the
/// IdP did not emit the configured claim this login -- a normal outcome,
/// refreshed on every login rather than carried over from a previous one.
pub async fn mark_authenticated(
    db: &Db,
    oidc_state: &str,
    principal_id: Uuid,
    groups_json: Option<&str>,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let rows = match db {
        Db::Postgres(handle) => sqlx::query(
            "UPDATE auth_sessions SET status = 'authenticated', principal_id = $1, \
                 groups_json = $2 \
                 WHERE oidc_state = $3 AND status = 'pending' AND expires_at_ms > $4",
        )
        .bind(principal_id)
        .bind(groups_json)
        .bind(oidc_state)
        .bind(now_ms)
        .execute(&handle.pool)
        .await?
        .rows_affected(),
        Db::Sqlite(handle) => sqlx::query(
            "UPDATE auth_sessions SET status = 'authenticated', principal_id = ?, \
                 groups_json = ? \
                 WHERE oidc_state = ? AND status = 'pending' AND expires_at_ms > ?",
        )
        .bind(principal_id.to_string())
        .bind(groups_json)
        .bind(oidc_state)
        .bind(now_ms)
        .execute(&handle.pool)
        .await?
        .rows_affected(),
    };
    Ok(rows == 1)
}

/// `authenticated` -> `consumed`. Returns whether THIS caller is the one
/// that consumed it.
///
/// This is the single-use guarantee. Every caller must mint a token ONLY
/// when this returns `true`: a second poll of the same session, a replayed
/// `session_code`, and a concurrent racing poll all get `false` from the
/// database itself, not from a check that could be raced.
pub async fn consume(db: &Db, session_code_hash: &str, now_ms: i64) -> Result<bool, sqlx::Error> {
    let rows = match db {
        Db::Postgres(handle) => sqlx::query(
            "UPDATE auth_sessions SET status = 'consumed' \
                 WHERE session_code_hash = $1 AND status = 'authenticated' AND expires_at_ms > $2",
        )
        .bind(session_code_hash)
        .bind(now_ms)
        .execute(&handle.pool)
        .await?
        .rows_affected(),
        Db::Sqlite(handle) => sqlx::query(
            "UPDATE auth_sessions SET status = 'consumed' \
                 WHERE session_code_hash = ? AND status = 'authenticated' AND expires_at_ms > ?",
        )
        .bind(session_code_hash)
        .bind(now_ms)
        .execute(&handle.pool)
        .await?
        .rows_affected(),
    };
    Ok(rows == 1)
}

/// Deletes every session past its expiry, whatever its status. Called
/// opportunistically from `StartAuthSession` rather than from a background
/// reaper task: login volume is exactly the rate at which this table grows,
/// so the cleanup rate tracks the growth rate for free, with no task to
/// supervise and nothing extra to run in tests.
///
/// Returns the number of rows removed (for logging only -- a failure here is
/// never allowed to fail a login).
pub async fn delete_expired(db: &Db, now_ms: i64) -> Result<u64, sqlx::Error> {
    let rows = match db {
        Db::Postgres(handle) => sqlx::query("DELETE FROM auth_sessions WHERE expires_at_ms <= $1")
            .bind(now_ms)
            .execute(&handle.pool)
            .await?
            .rows_affected(),
        Db::Sqlite(handle) => sqlx::query("DELETE FROM auth_sessions WHERE expires_at_ms <= ?")
            .bind(now_ms)
            .execute(&handle.pool)
            .await?
            .rows_affected(),
    };
    Ok(rows)
}
