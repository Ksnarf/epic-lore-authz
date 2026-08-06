//! Reads the `principals` table into `lore_authz_core::model::Principal`.
//! `lore-authz-core` stays I/O-free (see its module doc comment) so this
//! crate owns the row shape and the mapping.
//!
//! Dispatches on `Db`'s variant internally (see `db/mod.rs`). The one
//! backend-specific wrinkle: SQLite has no native uuid type, so its
//! `principals.id` column is TEXT holding the canonical hyphenated UUID
//! string -- converted explicitly at this boundary (`Uuid::to_string()` /
//! `Uuid::parse_str`), never relying on sqlx's own Uuid<->Sqlite blob
//! encoding. Postgres's native `uuid` column needs no such conversion.

use lore_authz_core::model::Principal;
use lore_authz_core::model::PrincipalStatus;
use uuid::Uuid;

use crate::db::Db;

/// The one column list every principal query below selects, so a new column
/// cannot be added to one backend's query and forgotten in the other's.
const SELECT_COLUMNS: &str = "id, subject, external_id, source, email, display_name, \
                              preferred_username, is_service_account, status, idp";

#[derive(Debug, sqlx::FromRow)]
struct PrincipalRow {
    id: Uuid,
    subject: String,
    external_id: Option<String>,
    source: String,
    email: Option<String>,
    display_name: String,
    preferred_username: String,
    is_service_account: bool,
    status: String,
    idp: Option<String>,
}

/// Same shape as `PrincipalRow`, but `id` as the TEXT sqlx/SQLite actually
/// hands back -- parsed into a `Uuid` explicitly in `sqlite_row_into`.
#[derive(Debug, sqlx::FromRow)]
struct SqlitePrincipalRow {
    id: String,
    subject: String,
    external_id: Option<String>,
    source: String,
    email: Option<String>,
    display_name: String,
    preferred_username: String,
    is_service_account: bool,
    status: String,
    idp: Option<String>,
}

fn parse_status(raw: &str) -> PrincipalStatus {
    match raw {
        "suspended" => PrincipalStatus::Suspended,
        "deprovisioned" => PrincipalStatus::Deprovisioned,
        // The DB CHECK constraint only allows these three values; anything
        // else reaching here would be a schema/constraint mismatch, not a
        // real runtime case. Default to the safe (non-active) reading
        // rather than panicking on an unexpected string from the database.
        "active" => PrincipalStatus::Active,
        _ => PrincipalStatus::Suspended,
    }
}

impl From<PrincipalRow> for Principal {
    fn from(row: PrincipalRow) -> Self {
        Principal {
            id: row.id,
            idp_connection_id: None,
            subject: row.subject,
            external_id: row.external_id,
            source: row.source,
            email: row.email,
            display_name: row.display_name,
            preferred_username: row.preferred_username,
            is_service_account: row.is_service_account,
            status: parse_status(&row.status),
            idp: row.idp,
        }
    }
}

/// Fails the same way `Uuid::parse_str` would surface as a query error: a
/// non-UUID `id` in the `principals` table would be a schema/constraint
/// mismatch (nothing in this codebase writes one), not a real runtime case,
/// so this maps to `sqlx::Error::Decode` rather than adding a new error
/// variant just for it.
fn sqlite_row_into_principal(row: SqlitePrincipalRow) -> Result<Principal, sqlx::Error> {
    let id = Uuid::parse_str(&row.id)
        .map_err(|err| sqlx::Error::Decode(format!("principals.id {:?}: {err}", row.id).into()))?;
    Ok(Principal {
        id,
        idp_connection_id: None,
        subject: row.subject,
        external_id: row.external_id,
        source: row.source,
        email: row.email,
        display_name: row.display_name,
        preferred_username: row.preferred_username,
        is_service_account: row.is_service_account,
        status: parse_status(&row.status),
        idp: row.idp,
    })
}

/// Inserts a principal directly. There is no OIDC/SCIM provisioning yet
/// (Phase 1b / Phase 3, see tasks.md), so this is currently the only way any
/// principal ever enters `principals` -- used by `tests/` to seed users and
/// service accounts (`is_service_account = true`). Not gated behind
/// `#[cfg(test)]`: integration tests in `tests/` link the crate's normal
/// (non-`cfg(test)`) compilation, so a helper only tests can see must be a
/// plain `pub fn`. `source` is always `"local"` for a row created this way
/// (see `Principal::source` doc comment).
pub async fn insert_principal(
    db: &Db,
    id: Uuid,
    display_name: &str,
    is_service_account: bool,
) -> Result<(), sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            sqlx::query(
                "INSERT INTO principals (id, subject, display_name, preferred_username, \
                 is_service_account, status) \
                 VALUES ($1, $2, $3, $3, $4, 'active') \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(id)
            .bind(id.to_string())
            .bind(display_name)
            .bind(is_service_account)
            .execute(&handle.pool)
            .await?;
        }
        Db::Sqlite(handle) => {
            // Plain `?` placeholders throughout this module tree's SQLite
            // queries (never numbered `?1`/`?2`), bound strictly in
            // left-to-right order -- avoids any ambiguity from mixing
            // numbered and anonymous placeholders in one statement. A value
            // used twice in the SQL text (display_name / preferred_username
            // here) is simply bound twice, rather than reusing a numbered
            // placeholder the way the Postgres query above reuses `$3`.
            sqlx::query(
                "INSERT INTO principals (id, subject, display_name, preferred_username, \
                 is_service_account, status) \
                 VALUES (?, ?, ?, ?, ?, 'active') \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(id.to_string())
            .bind(id.to_string())
            .bind(display_name)
            .bind(display_name)
            .bind(is_service_account)
            .execute(&handle.pool)
            .await?;
        }
    }
    Ok(())
}

/// Looks up a principal by id, but ONLY if it is `active`. A caller decoded
/// from an otherwise-valid, correctly-signed bearer token whose `sub` does
/// not resolve to an `active` principal (never provisioned, or suspended /
/// deprovisioned) gets `Ok(None)` here -- callers MUST treat that as deny,
/// never as "no restriction". See `crates/lore-authz-server/src/grpc.rs` and
/// `tests/authz_suite`'s `unknown_principal_id_denies*` tests, run against
/// BOTH backends.
pub async fn find_active_principal(db: &Db, id: Uuid) -> Result<Option<Principal>, sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            let row: Option<PrincipalRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_COLUMNS} FROM principals WHERE id = $1 AND status = 'active'"
            ))
            .bind(id)
            .fetch_optional(&handle.pool)
            .await?;
            Ok(row.map(Into::into))
        }
        Db::Sqlite(handle) => {
            let row: Option<SqlitePrincipalRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_COLUMNS} FROM principals WHERE id = ? AND status = 'active'"
            ))
            .bind(id.to_string())
            .fetch_optional(&handle.pool)
            .await?;
            row.map(sqlite_row_into_principal).transpose()
        }
    }
}

/// Looks a principal up by the external identity that proved it: the IdP's
/// `sub` claim (`subject`), scoped by where it came from (`source`, e.g.
/// `"oidc"`). Unlike `find_active_principal` this returns SUSPENDED and
/// DEPROVISIONED rows too, because the login leg has to tell "this person
/// has no account here" (which may JIT-provision one) apart from "this
/// person's account is disabled" (which must never be silently
/// re-provisioned into a working one). See `crate::oidc_login`.
pub async fn find_principal_by_subject(
    db: &Db,
    source: &str,
    subject: &str,
) -> Result<Option<Principal>, sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            let row: Option<PrincipalRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_COLUMNS} FROM principals WHERE source = $1 AND subject = $2"
            ))
            .bind(source)
            .bind(subject)
            .fetch_optional(&handle.pool)
            .await?;
            Ok(row.map(Into::into))
        }
        Db::Sqlite(handle) => {
            let row: Option<SqlitePrincipalRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_COLUMNS} FROM principals WHERE source = ? AND subject = ?"
            ))
            .bind(source)
            .bind(subject)
            .fetch_optional(&handle.pool)
            .await?;
            row.map(sqlite_row_into_principal).transpose()
        }
    }
}

/// The identity attributes an identity provider asserted about a user, as
/// the login leg wants to record them. Deliberately NOT the whole
/// `Principal`: nothing about a login may set `status`, `is_service_account`
/// or `id`.
#[derive(Debug, Clone)]
pub struct ExternalIdentity {
    /// The IdP's `sub` claim. Opaque and provider-scoped; never an email.
    pub subject: String,
    /// Where it came from -- the `source` column. `"oidc"` today.
    pub source: String,
    /// The value to stamp as the `idp` claim on this principal's AuthZ
    /// tokens (see `Principal::idp`).
    pub idp: String,
    pub display_name: String,
    pub preferred_username: String,
    pub email: Option<String>,
}

/// Creates a principal for an externally-authenticated identity that has no
/// row yet ("JIT provisioning"), returning it.
///
/// The created principal has NO role bindings, so it can authenticate and
/// gets an AuthZ token whose `resources` claim is empty -- it can see
/// nothing until an operator grants it something. That is the fail-closed
/// property that makes JIT provisioning safe to have on by default: it
/// creates an IDENTITY, never an AUTHORIZATION.
///
/// `ON CONFLICT DO NOTHING` on `(source, subject)` handles two concurrent
/// logins for the same brand-new identity racing here; the caller re-reads
/// the row afterwards, so the loser of the race gets the winner's principal
/// rather than an error.
pub async fn insert_external_principal(
    db: &Db,
    id: Uuid,
    identity: &ExternalIdentity,
) -> Result<(), sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            sqlx::query(
                "INSERT INTO principals (id, subject, source, email, display_name, \
                 preferred_username, is_service_account, status, idp) \
                 VALUES ($1, $2, $3, $4, $5, $6, false, 'active', $7) \
                 ON CONFLICT (source, subject) DO NOTHING",
            )
            .bind(id)
            .bind(&identity.subject)
            .bind(&identity.source)
            .bind(&identity.email)
            .bind(&identity.display_name)
            .bind(&identity.preferred_username)
            .bind(&identity.idp)
            .execute(&handle.pool)
            .await?;
        }
        Db::Sqlite(handle) => {
            sqlx::query(
                "INSERT INTO principals (id, subject, source, email, display_name, \
                 preferred_username, is_service_account, status, idp) \
                 VALUES (?, ?, ?, ?, ?, ?, 0, 'active', ?) \
                 ON CONFLICT (source, subject) DO NOTHING",
            )
            .bind(id.to_string())
            .bind(&identity.subject)
            .bind(&identity.source)
            .bind(&identity.email)
            .bind(&identity.display_name)
            .bind(&identity.preferred_username)
            .bind(&identity.idp)
            .execute(&handle.pool)
            .await?;
        }
    }
    Ok(())
}

/// Refreshes the mutable identity attributes an IdP asserted on an EXISTING
/// principal. Touches only what the IdP is authoritative for: display name,
/// preferred username, email, and which IdP proved the identity.
///
/// It explicitly does NOT touch `status`. A suspended or deprovisioned
/// principal logging in again must not be silently reactivated by the login
/// path -- that is a deliberate omission, not an oversight.
pub async fn update_external_identity(
    db: &Db,
    id: Uuid,
    identity: &ExternalIdentity,
) -> Result<(), sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            sqlx::query(
                "UPDATE principals SET display_name = $1, preferred_username = $2, email = $3, \
                 idp = $4, updated_at = now() WHERE id = $5",
            )
            .bind(&identity.display_name)
            .bind(&identity.preferred_username)
            .bind(&identity.email)
            .bind(&identity.idp)
            .bind(id)
            .execute(&handle.pool)
            .await?;
        }
        Db::Sqlite(handle) => {
            sqlx::query(
                "UPDATE principals SET display_name = ?, preferred_username = ?, email = ?, \
                 idp = ?, updated_at = datetime('now') WHERE id = ?",
            )
            .bind(&identity.display_name)
            .bind(&identity.preferred_username)
            .bind(&identity.email)
            .bind(&identity.idp)
            .bind(id.to_string())
            .execute(&handle.pool)
            .await?;
        }
    }
    Ok(())
}
