-- SQLite dialect of migrations/0001_identities_resources_grants.sql. Kept in
-- step with it deliberately: same tables, same columns (bar the differences
-- below), same semantics. This is the DEV / SINGLE-INSTANCE backend -- see
-- README.md and docs/configuration.md: SQLite's single-writer lock makes it
-- the wrong choice behind a load balancer. Postgres/RDS is required for any
-- multi-replica deployment; the migration set above (`../migrations/`) is
-- the one that matters there.
--
-- Differences from the Postgres migration, forced by SQLite itself, not by
-- choice:
--   * No CREATE SCHEMA / search_path: SQLite has no schema concept at all.
--     DB_SCHEMA is an explicit no-op for this backend -- see
--     crates/lore-authz-server/src/db/mod.rs's `Db::connect` and
--     docs/configuration.md. Every table here is therefore in SQLite's one
--     and only namespace, not "unqualified because search_path points at
--     it" the way the Postgres migration's tables are.
--   * uuid columns (`principals.id`, `groups.id`, `role_bindings.
--     principal_id`, etc.) are declared TEXT here, storing the canonical
--     hyphenated UUID string (e.g. "00000000-0000-0000-0000-000000000001"),
--     not a native uuid type -- SQLite has none. `crates/lore-authz-server/
--     src/db/*.rs`'s SQLite code paths convert explicitly at the boundary
--     (`Uuid::to_string()` / `Uuid::parse_str()`) rather than relying on
--     sqlx's built-in Uuid<->Sqlite blob encoding, so the seed data below
--     reads identically to the Postgres migration's.
--   * timestamptz columns are declared TEXT DEFAULT (datetime('now')):
--     SQLite has no timestamptz type or now() function. Nothing in this
--     codebase parses these columns back into Rust today (only `IS NULL` /
--     overwrite-on-delete), so a plain ISO-8601 UTC text default is
--     sufficient -- see db/resources.rs's SQLite `delete_resource`.
--   * `roles.permissions` (a Postgres `text[]` column) has no SQLite
--     equivalent (no array type), so it is normalized into a
--     `role_permissions` join table instead. `db/permissions.rs`'s SQLite
--     `resolve_resource_permissions` aggregates it back into the exact same
--     `Vec<String>` shape the Postgres array column produces -- see that
--     file's module doc comment.
--
-- IDEMPOTENCY: `IF NOT EXISTS` / `ON CONFLICT DO NOTHING` throughout, plus
-- sqlx's own migration-history tracking (`_sqlx_migrations`, created by the
-- same `sqlx::migrate!` call as the Postgres set, just against this
-- database instead). Safe to run twice.

CREATE TABLE IF NOT EXISTS principals (
    id                  TEXT PRIMARY KEY,
    subject             TEXT NOT NULL,
    external_id         TEXT,
    source              TEXT NOT NULL DEFAULT 'local',
    email               TEXT,
    display_name        TEXT NOT NULL,
    preferred_username  TEXT NOT NULL,
    is_service_account  BOOLEAN NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'suspended', 'deprovisioned')),
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS groups (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    description         TEXT,
    external_id         TEXT,
    source              TEXT NOT NULL DEFAULT 'local',
    status              TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'suspended', 'deprovisioned')),
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id            TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    principal_id        TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    added_at            TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (group_id, principal_id)
);

-- Populated by RebacApi::CreateResource / DeleteResource. Same
-- resource_id = "urc-{repository_id}" convention as the Postgres table;
-- soft-deleted (deleted_at) rather than removed.
CREATE TABLE IF NOT EXISTS resources (
    resource_id         TEXT PRIMARY KEY,
    resource_name       TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    deleted_at          TEXT
);

-- Advisory permission vocabulary, same as the Postgres migration -- see its
-- comment. `permissions` here is NOT a column: SQLite has no array type, so
-- it is normalized into role_permissions below instead.
CREATE TABLE IF NOT EXISTS roles (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id             TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission          TEXT NOT NULL,
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE IF NOT EXISTS role_bindings (
    id                  TEXT PRIMARY KEY,
    role_id             TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    resource_pattern    TEXT NOT NULL,
    principal_kind      TEXT NOT NULL
                            CHECK (principal_kind IN ('user', 'service_account', 'group')),
    principal_id        TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (role_id, resource_pattern, principal_kind, principal_id)
);

CREATE INDEX IF NOT EXISTS role_bindings_principal_idx
    ON role_bindings (principal_kind, principal_id);

CREATE INDEX IF NOT EXISTS role_bindings_resource_pattern_idx
    ON role_bindings (resource_pattern);

-- Built-in advisory roles -- same fixed ids (as canonical UUID text, see the
-- note above) as the Postgres migration, so
-- crates/lore-authz-server/src/db/permissions.rs's ROLE_READER / ROLE_WRITER
-- / ROLE_ADMIN constants are valid against EITHER backend without a
-- backend-specific branch.
INSERT INTO roles (id, name) VALUES
    ('00000000-0000-0000-0000-000000000001', 'reader'),
    ('00000000-0000-0000-0000-000000000002', 'writer'),
    ('00000000-0000-0000-0000-000000000003', 'admin')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission) VALUES
    ('00000000-0000-0000-0000-000000000001', 'read'),
    ('00000000-0000-0000-0000-000000000002', 'read'),
    ('00000000-0000-0000-0000-000000000002', 'write'),
    ('00000000-0000-0000-0000-000000000003', 'read'),
    ('00000000-0000-0000-0000-000000000003', 'write'),
    ('00000000-0000-0000-0000-000000000003', 'admin')
ON CONFLICT (role_id, permission) DO NOTHING;
