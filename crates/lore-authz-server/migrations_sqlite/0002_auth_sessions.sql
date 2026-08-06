-- SQLite dialect of migrations/0002_auth_sessions.sql. Read that file first:
-- it carries the full rationale (why sessions are in the database at all,
-- and the per-column "hashed vs raw" decision), which is identical here and
-- deliberately not duplicated.
--
-- Differences from the Postgres migration, forced by SQLite itself:
--   * `principal_id` is TEXT holding the canonical hyphenated UUID string,
--     not a native uuid -- same convention as 0001, converted explicitly at
--     the Rust boundary (see crates/lore-authz-server/src/db/sessions.rs).
--   * `bigint` is spelled INTEGER. SQLite INTEGER is up to 8 bytes, so epoch
--     milliseconds fit with room to spare.
--   * `ALTER TABLE ... ADD COLUMN` has no `IF NOT EXISTS` form in SQLite.
--     That is safe here regardless: sqlx's migrator records which migrations
--     have already run (`_sqlx_migrations`) and never re-runs this file, so
--     the ADD COLUMN below executes exactly once per database. The
--     `IF NOT EXISTS` clauses on the CREATEs are belt-and-braces, matching
--     the style of 0001.

CREATE TABLE IF NOT EXISTS auth_sessions (
    session_code_hash   TEXT PRIMARY KEY,
    login_code_hash     TEXT NOT NULL,
    client_state_hash   TEXT NOT NULL,
    oidc_state          TEXT NOT NULL,
    oidc_nonce          TEXT NOT NULL,
    pkce_verifier       TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'authenticated', 'consumed')),
    principal_id        TEXT,
    created_at_ms       INTEGER NOT NULL,
    expires_at_ms       INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_sessions_login_code_hash_idx
    ON auth_sessions (login_code_hash);

CREATE UNIQUE INDEX IF NOT EXISTS auth_sessions_oidc_state_idx
    ON auth_sessions (oidc_state);

CREATE INDEX IF NOT EXISTS auth_sessions_expires_at_ms_idx
    ON auth_sessions (expires_at_ms);

ALTER TABLE principals ADD COLUMN idp TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS principals_source_subject_idx
    ON principals (source, subject);
