-- PHASE 1a (see tasks.md): identities, groups, resources, and permission
-- grants backing LookupUserPermissions / CheckUserPermission /
-- RebacApi::CreateResource / DeleteResource.
--
-- SCHEMA-QUALIFICATION NOTE: every statement below is schema-UNQUALIFIED on
-- purpose. `Db::connect` (crates/lore-authz-server/src/db/mod.rs) creates
-- the configured DB_SCHEMA and points every pooled connection's
-- `search_path` at it (never `public`) before this migration ever runs, so
-- unqualified `CREATE TABLE` etc. land in that schema. Do not hardcode a
-- schema name in this file -- DB_SCHEMA is a runtime value, not known at
-- migration-authoring time.
--
-- IDEMPOTENCY: `IF NOT EXISTS` / `ON CONFLICT DO NOTHING` throughout, plus
-- sqlx's own migration-history tracking (itself created inside DB_SCHEMA,
-- never `public`, for the same search_path reason). Safe to run twice; see
-- crates/lore-authz-server/tests/postgres_backed.rs's
-- `migrations_are_idempotent` test.

-- Users AND service accounts share one id space (see
-- lore-authz-core::model::Principal doc comment) so `sub` in every minted
-- token, and every `principal_id` a role_binding grants to, is always a
-- `principals.id`. `external_id` / `source` / `status` exist now so SCIM
-- provisioning (Phase 3) is purely additive later, even though nothing
-- populates `external_id` via SCIM yet.
CREATE TABLE IF NOT EXISTS principals (
    id                  uuid PRIMARY KEY,
    subject             text NOT NULL,
    external_id         text,
    source              text NOT NULL DEFAULT 'local',
    email               text,
    display_name        text NOT NULL,
    preferred_username  text NOT NULL,
    is_service_account  boolean NOT NULL DEFAULT false,
    status              text NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'suspended', 'deprovisioned')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS groups (
    id                  uuid PRIMARY KEY,
    name                text NOT NULL UNIQUE,
    description         text,
    external_id         text,
    source              text NOT NULL DEFAULT 'local',
    status              text NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'suspended', 'deprovisioned')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id            uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    principal_id        uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    added_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, principal_id)
);

-- Populated by RebacApi::CreateResource / DeleteResource. resource_id is
-- lore's own "urc-{repository_id}" convention -- never the literal wildcard
-- "urc-*" (that only ever appears as a role_bindings.resource_pattern, see
-- below). Soft-deleted (deleted_at) rather than removed, for an audit trail;
-- LookupUserPermissions' candidate query filters `deleted_at IS NULL`.
CREATE TABLE IF NOT EXISTS resources (
    resource_id         text PRIMARY KEY,
    resource_name       text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    deleted_at          timestamptz
);

-- Advisory permission vocabulary (see lore-authz-core::model::Role doc
-- comment): the upstream OSS lore-server does not itself enforce these
-- strings, only membership in the `resources` claim. Modeled and emitted
-- honestly anyway.
CREATE TABLE IF NOT EXISTS roles (
    id                  uuid PRIMARY KEY,
    name                text NOT NULL UNIQUE,
    permissions         text[] NOT NULL
);

-- The single table LookupUserPermissions / CheckUserPermission (and, later,
-- AuthZ token minting) read to answer "what can this principal see".
-- resource_pattern is always a literal string: either a specific
-- "urc-{repository_id}" or the literal wildcard "urc-*", which matches ANY
-- urc-* resource for the bound principal (or any member of a bound group).
-- principal_kind in ('user','service_account') both reference principals.id
-- (both live in that one table); principal_kind='group' references
-- groups.id. Polymorphic on purpose (see lore-authz-core::model::RoleBinding
-- doc comment) -- not FK-enforced across both possible targets, since
-- Postgres has no native polymorphic FK; validated at the application layer.
CREATE TABLE IF NOT EXISTS role_bindings (
    id                  uuid PRIMARY KEY,
    role_id             uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    resource_pattern    text NOT NULL,
    principal_kind      text NOT NULL
                            CHECK (principal_kind IN ('user', 'service_account', 'group')),
    principal_id        uuid NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (role_id, resource_pattern, principal_kind, principal_id)
);

CREATE INDEX IF NOT EXISTS role_bindings_principal_idx
    ON role_bindings (principal_kind, principal_id);

CREATE INDEX IF NOT EXISTS role_bindings_resource_pattern_idx
    ON role_bindings (resource_pattern);

-- Built-in advisory roles. Fixed ids so tests and future migrations can
-- reference them by literal UUID instead of a name lookup.
INSERT INTO roles (id, name, permissions) VALUES
    ('00000000-0000-0000-0000-000000000001', 'reader', ARRAY['read']),
    ('00000000-0000-0000-0000-000000000002', 'writer', ARRAY['read', 'write']),
    ('00000000-0000-0000-0000-000000000003', 'admin',  ARRAY['read', 'write', 'admin'])
ON CONFLICT (id) DO NOTHING;
