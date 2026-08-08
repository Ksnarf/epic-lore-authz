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

/// The attributes the ADMIN surface may set when it provisions a principal
/// by hand (`crate::admin`). Deliberately not the whole `Principal`: `id` is
/// generated by this service (never operator-supplied, so an operator cannot
/// pre-image the `sub` of a token), and `status` is always `active` on
/// creation -- moving a principal to `suspended` is a separate, explicit
/// operation (`set_principal_status`), not something a create call can do in
/// passing.
///
/// `external_id` and `source` are here because SCIM (Phase 3) keys on them:
/// an operator pre-provisioning the identity their IdP will later assert can
/// record it now, and the SCIM leg will find that row instead of creating a
/// duplicate.
#[derive(Debug, Clone)]
pub struct NewPrincipal {
    /// The identity key inside `source`. `None` means "no external identity
    /// yet", and the caller's generated `id` is stored as the subject (the
    /// same convention `insert_principal` uses), so the UNIQUE `(source,
    /// subject)` index is satisfied without inventing a placeholder that
    /// could collide with a real IdP `sub`.
    pub subject: Option<String>,
    /// Where this identity came from: `"local"` for an operator-created
    /// principal, or the value the eventual IdP/SCIM leg will use (`"oidc"`,
    /// `"scim"`) when pre-provisioning.
    pub source: String,
    pub external_id: Option<String>,
    pub email: Option<String>,
    pub display_name: String,
    pub preferred_username: String,
    pub is_service_account: bool,
    /// Value to stamp as the `idp` claim on this principal's AuthZ tokens.
    /// `None` falls back to `TOKEN_IDP` at exchange time (see
    /// `crate::login::LoginSettings::default_idp`), which is guaranteed
    /// non-empty, so a principal created here can never mint a token with an
    /// empty `idp` (which fails SILENTLY at lore-server -- see
    /// docs/protocol-notes.md section 2).
    pub idp: Option<String>,
}

/// Whether an admin create actually inserted, or collided with an identity
/// that already exists. Reported to the operator rather than swallowed: an
/// admin API that silently no-ops on a duplicate leaves the operator
/// believing they created something they did not.
pub enum InsertPrincipalOutcome {
    Created,
    /// `(source, subject)` already exists (the UNIQUE index added in
    /// `migrations/0002_auth_sessions.sql`).
    DuplicateIdentity,
}

/// Creates a principal from the admin surface. Like every other creation path
/// in this project, it creates an IDENTITY and never an AUTHORIZATION: the
/// row holds no `role_bindings`, so a principal created here can authenticate
/// (once it has a way to) and receives an AuthZ token whose `resources` claim
/// is empty until an operator grants it something explicitly.
///
/// A bare `ON CONFLICT DO NOTHING` (no conflict target) covers BOTH unique
/// constraints on the table -- the `id` primary key and the `(source,
/// subject)` index -- so a collision on either is reported as
/// `DuplicateIdentity` rather than surfacing as a raw database error whose
/// text would name internals.
pub async fn insert_admin_principal(
    db: &Db,
    id: Uuid,
    new: &NewPrincipal,
) -> Result<InsertPrincipalOutcome, sqlx::Error> {
    let subject = new.subject.clone().unwrap_or_else(|| id.to_string());

    let inserted = match db {
        Db::Postgres(handle) => {
            let row: Option<(Uuid,)> = sqlx::query_as(
                "INSERT INTO principals (id, subject, external_id, source, email, display_name, \
                 preferred_username, is_service_account, status, idp) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9) \
                 ON CONFLICT DO NOTHING \
                 RETURNING id",
            )
            .bind(id)
            .bind(&subject)
            .bind(&new.external_id)
            .bind(&new.source)
            .bind(&new.email)
            .bind(&new.display_name)
            .bind(&new.preferred_username)
            .bind(new.is_service_account)
            .bind(&new.idp)
            .fetch_optional(&handle.pool)
            .await?;
            row.is_some()
        }
        Db::Sqlite(handle) => {
            let row: Option<(String,)> = sqlx::query_as(
                "INSERT INTO principals (id, subject, external_id, source, email, display_name, \
                 preferred_username, is_service_account, status, idp) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?) \
                 ON CONFLICT DO NOTHING \
                 RETURNING id",
            )
            .bind(id.to_string())
            .bind(&subject)
            .bind(&new.external_id)
            .bind(&new.source)
            .bind(&new.email)
            .bind(&new.display_name)
            .bind(&new.preferred_username)
            .bind(new.is_service_account)
            .bind(&new.idp)
            .fetch_optional(&handle.pool)
            .await?;
            row.is_some()
        }
    };

    Ok(if inserted {
        InsertPrincipalOutcome::Created
    } else {
        InsertPrincipalOutcome::DuplicateIdentity
    })
}

/// Every principal, whatever its status, for the admin surface's list view.
/// `limit` is applied in SQL (the caller passes `crate::admin::LIST_LIMIT`),
/// so an operator with a large directory gets a bounded page rather than a
/// response that grows without limit -- see `crate::admin`'s doc comment on
/// what that means and does not mean.
///
/// Ordered by `display_name` then `id` so the ordering is total and stable on
/// both backends (a name is not unique; an id is).
pub async fn list_principals(db: &Db, limit: i64) -> Result<Vec<Principal>, sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            let rows: Vec<PrincipalRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_COLUMNS} FROM principals ORDER BY display_name, id LIMIT $1"
            ))
            .bind(limit)
            .fetch_all(&handle.pool)
            .await?;
            Ok(rows.into_iter().map(Into::into).collect())
        }
        Db::Sqlite(handle) => {
            let rows: Vec<SqlitePrincipalRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_COLUMNS} FROM principals ORDER BY display_name, id LIMIT ?"
            ))
            .bind(limit)
            .fetch_all(&handle.pool)
            .await?;
            rows.into_iter().map(sqlite_row_into_principal).collect()
        }
    }
}

/// Looks up a principal by id REGARDLESS of status -- the admin read path.
///
/// Deliberately distinct from `find_active_principal` (below), which every
/// authorization path uses: an operator must be able to see that a principal
/// is suspended, whereas an authorization decision must never see a
/// suspended principal at all. Two intents, two functions, so neither can
/// be used for the other's job by accident.
pub async fn find_principal(db: &Db, id: Uuid) -> Result<Option<Principal>, sqlx::Error> {
    match db {
        Db::Postgres(handle) => {
            let row: Option<PrincipalRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_COLUMNS} FROM principals WHERE id = $1"
            ))
            .bind(id)
            .fetch_optional(&handle.pool)
            .await?;
            Ok(row.map(Into::into))
        }
        Db::Sqlite(handle) => {
            let row: Option<SqlitePrincipalRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_COLUMNS} FROM principals WHERE id = ?"
            ))
            .bind(id.to_string())
            .fetch_optional(&handle.pool)
            .await?;
            row.map(sqlite_row_into_principal).transpose()
        }
    }
}

/// Sets a principal's `status`, returning whether a row was actually updated
/// (`false` = no such principal, which the admin surface reports as a 404
/// rather than a silent success).
///
/// `status` is NOT free text: the caller must pass a value from
/// `crate::admin`'s validated set, and the DB `CHECK` constraint on both
/// backends is the second line of defence. Suspending is the revocation lever
/// with the widest reach in this product -- `find_active_principal` returns
/// `None` for a suspended principal, so every authorization path, the login
/// poll, and the token exchange all deny at the NEXT call.
pub async fn set_principal_status(db: &Db, id: Uuid, status: &str) -> Result<bool, sqlx::Error> {
    let rows_affected = match db {
        Db::Postgres(handle) => {
            sqlx::query("UPDATE principals SET status = $1, updated_at = now() WHERE id = $2")
                .bind(status)
                .bind(id)
                .execute(&handle.pool)
                .await?
                .rows_affected()
        }
        Db::Sqlite(handle) => sqlx::query(
            "UPDATE principals SET status = ?, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(status)
        .bind(id.to_string())
        .execute(&handle.pool)
        .await?
        .rows_affected(),
    };
    Ok(rows_affected == 1)
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
