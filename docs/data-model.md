# Data model (PHASE 1a)

This describes what epic-lore-authz's own schema does today, on EITHER
supported backend (Postgres or SQLite -- see docs/configuration.md's
"Choosing a database backend" section for why there are two and which one a
real deployment should use). The two backends' tables carry the same
columns and the same semantics, with a small number of representation
differences forced by SQLite itself, called out below and in
`migrations_sqlite/0001_identities_resources_grants.sql`'s own comment. See
`tasks.md` for phase-by-phase status and `docs/protocol-notes.md` /
`docs/open-questions.md` for the wire-contract reasoning that drove these
choices. This page only describes THIS project's server-side behavior, not
lore-server's internals.

## Operating constraints

- One `DATABASE_URL`, whose scheme selects the backend
  (`crates/lore-authz-server/src/db/mod.rs`'s `Db::connect`).
- **Postgres**: one `DB_SCHEMA` (default `loreauth`, see
  `docs/configuration.md`). Never `public`, never `CREATE DATABASE`, never
  superuser -- `validate_schema_identifier` rejects anything else before a
  single query runs. Every pooled connection has its `search_path` pointed
  at `DB_SCHEMA` in `after_connect`, so every table name in
  `migrations/0001_identities_resources_grants.sql` is deliberately
  UNqualified -- the schema is a runtime value (`DB_SCHEMA`), not something
  the SQL file can know at authoring time.
- **SQLite**: no schema concept at all. `DB_SCHEMA` is an explicit no-op,
  logged at startup -- see docs/configuration.md.
- Migrations run automatically at process startup (`main.rs` calls
  `Db::connect`, which runs them before the gRPC/HTTP listeners start) via
  `sqlx::migrate!`, against whichever backend-specific migration directory
  is live (`migrations/` for Postgres, `migrations_sqlite/` for SQLite),
  which tracks applied migrations in its own history table (created inside
  `DB_SCHEMA` for Postgres, never `public`; in the one SQLite database for
  SQLite). Safe to run twice: `IF NOT EXISTS` / `ON CONFLICT DO NOTHING`
  throughout the SQL itself, on top of sqlx's own migration tracking. There
  is no separate "migrate" command -- connecting IS migrating, by design,
  since this product has no other startup-ordering mechanism to depend on
  in an arbitrary deployment.

## Tables

- `principals` -- users AND service accounts share one id space
  (`is_service_account` distinguishes them), so `sub` in every minted token
  and every `role_bindings.principal_id` a grant targets is always a
  `principals.id`. Carries `external_id` / `source` / `status` now (Phase
  1a) even though nothing populates `external_id` yet -- no SCIM client
  exists -- so SCIM provisioning (Phase 3) is purely additive later, not a
  migration.
- `groups` / `group_members` -- same `external_id` / `source` / `status`
  rationale as `principals`.
- `resources` -- populated by `RebacApi::CreateResource` / `DeleteResource`.
  `resource_id` is lore's own `urc-{repository_id}` convention. Soft-deleted
  (`deleted_at`) for an audit trail, never hard-deleted.
- `roles` / `role_bindings` -- three built-in, fixed-id, advisory roles
  (`reader`={read}, `writer`={read,write}, `admin`={read,write,admin}).
  Advisory because the upstream OSS `lore-server`'s own authorization check
  only tests resource membership, never inspects a permission string --
  this project models and emits the vocabulary honestly, but does not
  promise per-permission enforcement it does not control. A
  `role_bindings.resource_pattern` is either a specific `urc-{repository_id}`
  or the literal wildcard string `"urc-*"` (never `NULL` -- see
  `db::permissions`'s module doc comment for why a literal sentinel was
  chosen over an `Option`), and `principal_kind` is `'user'`,
  `'service_account'`, or `'group'`. On Postgres, `roles.permissions` is a
  native `text[]` column; SQLite has no array type, so its migration
  normalizes the same data into a `role_permissions(role_id, permission)`
  join table instead -- `db::permissions`'s SQLite query path aggregates it
  back into the identical `Vec<String>` shape via `GROUP_CONCAT`, so nothing
  above the query layer can tell the difference.

## What `LookupUserPermissions` / `CheckUserPermission` actually check

Both RPCs are implemented against ONE shared engine,
`db::permissions::DbPolicyStore::resolve_resource_permissions`
(`crates/lore-authz-server/src/db/permissions.rs`, implementing
`lore_authz_core::policy::PolicyStore`), which dispatches to whichever
backend is live and:

1. Restricts the requested resource ids down to ones that are
   currently-registered AND not soft-deleted in `resources` -- this holds
   even under a WILDCARD grant: a `urc-*` binding never authorizes a
   resource_id that was never created, or that has since been deleted (see
   `tests/authz_suite`'s `nonexistent_resource_is_denied_not_errored` and
   `delete_resource_revokes_access_and_is_idempotent`, run against BOTH
   backends).
2. For each surviving resource id, checks whether the calling principal
   holds a matching `role_bindings` row -- directly, via a group they
   belong to (`group_members`), or via a wildcard binding (direct or
   group) -- and unions the granted permission strings.
3. A resource id with NO matching grant at all is simply absent from the
   result, never present with an empty permission list. "Not present"
   is the deny signal both RPCs build their allow/deny split from.
4. Any database error propagates as `Err` (mapped to `Status::internal` at
   the gRPC boundary), never as an empty or partial `Ok` -- a caller must
   not be able to mistake "the check itself failed" for "checked, and
   nothing was granted."

`LookupUserPermissions` additionally resolves `resource_filter` to a
concrete candidate list FIRST (`db::resources::list_resource_ids_with_prefix`,
a plain prefix match, see `docs/open-questions.md` Q5), then calls the
engine above with that list -- so its response is always a concrete,
currently-existing resource id per entry, never the literal wildcard
string, which the real `lore-server` call site would otherwise silently
drop (see the Q5 writeup for why that specific failure mode matters).

Caller identity for both RPCs comes from `crates/lore-authz-server/src/
caller.rs`: it verifies a bearer JWT (either the request's `authorization`
metadata, or `CheckUserPermissionRequest.target_user.user_token` if
supplied) against this server's own active signing key, and recovers the
`sub` claim as a `principals.id`. A missing/invalid/expired token denies
with `Status::unauthenticated`; a validly-signed token whose `sub` does not
resolve to an `active` row in `principals` denies with
`Status::unauthenticated` as well (see
`db::principals::find_active_principal`) -- unknown, suspended, and
deprovisioned principals are all treated identically: deny, not "no
restriction."

## Who writes these tables

Reading them was implemented well before writing them, so it is worth being
explicit about which component owns each write:

| Table | Written by |
|---|---|
| `principals` | The OIDC login leg (JIT provisioning, `crates/lore-authz-server/src/oidc_login.rs`) and the admin surface (`POST /admin/v1/principals`, `POST /admin/v1/principals/{id}/status`). |
| `groups`, `group_members` | The admin surface only. There is no SCIM group sync yet (Phase 3). |
| `resources` | `RebacApi::CreateResource`/`DeleteResource`, called by lore-server when a repository is created or deleted -- and the admin surface, for the bring-up case (a repository that predates this service) and for repairing a missing row. Both paths call the same `db::resources` functions and validate the id with the same rule. |
| `roles` | The migrations, and nothing else. There is no role CRUD anywhere in this product. |
| `role_bindings` | The admin surface only. This is the table that decides what anyone can see, and until the admin surface existed nothing could write it except a database client. |
| `auth_sessions` | The login flow (`crates/lore-authz-server/src/login.rs`, `oidc_login.rs`). |

Every admin write goes through `crates/lore-authz-server/src/admin/ops.rs`,
which is also where the checks a database constraint cannot express live
(`principal_kind` agreeing with the principal's own `is_service_account`,
`resource_pattern` being the literal wildcard or a well-formed resource id,
and the polymorphic `role_bindings.principal_id` actually existing). See
`docs/configuration.md`'s `ADMIN_API_TOKEN` section.

## Testing

`crates/lore-authz-server/tests/authz_suite/` defines the shared test
bodies that exercise all of the above; `tests/postgres_backed.rs` and
`tests/sqlite_backed.rs` are thin wrappers calling the SAME bodies against a
REAL Postgres container and a REAL SQLite file, respectively -- neither is a
mock, and neither is a subset of the other. See `authz_suite/mod.rs`'s own
module doc comment for the full list of cases, and the repo root
`docker-compose.test.yml` / `README.md` for how to run both.
