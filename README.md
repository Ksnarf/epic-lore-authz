# epic-lore-authz

An enterprise SSO / authorization sidecar for
[`EpicGames/lore`](https://github.com/EpicGames/lore) (Epic's open source
version control system).

## What this is

`lore-server` and the `lore` CLI already implement a complete enterprise-auth
**client**: browser SSO login, service-account token exchange, and
per-repository authorization checks on every RPC. The two proto files that
define that contract (`auth_api.proto`, `rebac_api.proto`) are MIT licensed
and public. What is not public is a **server** implementation of them --
upstream's own build (`lore-proto/build.rs`) compiles both with
`.build_server(false)`, i.e. it generates gRPC client stubs only, because
Epic's own auth service is closed source.

epic-lore-authz vendors those two proto files (see `proto/vendor/`,
provenance in `proto/vendor/UPSTREAM.md`) and compiles them with
`.build_server(true)` to provide a real, open source server implementation:
a single sidecar binary that speaks OIDC and SAML to a real enterprise
identity provider, so an **unmodified** `lore-server` and **unmodified**
`lore` CLI can be pointed at real SSO.

See `docs/architecture.md` for the full design, and `docs/protocol-notes.md`
before touching anything claim- or JWKS-shaped -- the claim contract has
several gotchas that fail silently rather than loudly.

## What this is NOT

- Not a fork or a patch of `lore-server` or the `lore` CLI. Both are used
  unmodified; this project only implements the server side of a contract
  they already speak.
- Not affiliated with or endorsed by Epic Games, Inc.
- Not a fine-grained permission enforcement layer. `lore-server`'s own
  authorization check only checks repository membership, never a
  permission string (see `docs/protocol-notes.md`). This project does not
  promise enforcement `lore-server` itself does not perform.
- Not (yet) a finished product. See `tasks.md`. As of PHASE 1a,
  `LookupUserPermissions`, `CheckUserPermission`, and
  `RebacApi::CreateResource`/`DeleteResource` are real, database-backed
  logic (see `docs/data-model.md`); the auth-session login flow
  (`StartAuthSession`/`GetAuthSession`/`ExchangeUserTokenForMultiresourceToken`),
  OIDC, and SAML are still `Status::unimplemented` stubs (Phase 1b/2).
- **SQLite is a dev / single-instance convenience, not a production
  multi-replica option.** Two backends are supported, selected at runtime
  from `DATABASE_URL`'s scheme: Postgres (`postgres://`) and SQLite
  (`sqlite:`). SQLite's single-writer file lock makes it the wrong choice
  behind a load balancer or with more than one replica of this service
  running -- use Postgres/RDS for that. See docs/configuration.md's
  "Choosing a database backend" section.

## License and attribution

This project is licensed MIT (see `LICENSE`, Copyright (c) 2026 Ksnarf).

`proto/vendor/auth_api.proto` and `proto/vendor/rebac_api.proto` are vendored
verbatim from `EpicGames/lore` (also MIT licensed, Copyright (c) 2026 Epic
Games, Inc.) at the pinned commit `f205899adf24b13b2d28e5c08d9256ac99c69f0c`.
Full attribution and license text: `proto/vendor/UPSTREAM.md`.

## Quickstart (placeholder -- Phase 0 in progress, see tasks.md)

Prerequisites: a Rust stable toolchain (`rustup`), and `protoc` on `PATH` or
pointed to via the `PROTOC` env var (required at build time to generate the
gRPC server code from the vendored protos -- see
`crates/lore-authz-proto/build.rs`).

```sh
git clone https://github.com/Ksnarf/epic-lore-authz.git
cd epic-lore-authz
cp .env.example .env   # then fill in real values -- see docs/configuration.md
cargo build --workspace
```

Running the binary (once Phase 0 lands -- see `tasks.md`):

```sh
cargo run -p lore-authz-server
```

Then point an unmodified `lore-server` at it:
- `auth.jwk.endpoint` -> `http(s)://<this-host>:<HTTP_LISTEN_ADDR port><JWKS_PATH>`
- `environment.endpoint.auth_url` -> `https://<this-host>:<GRPC_LISTEN_ADDR port>`
  (see `docs/open-questions.md` Q2 -- the exact config key is unconfirmed)
- `auth.jwt_issuer` / `auth.jwt_audience` -> matching `JWT_ISSUER` /
  `JWT_AUDIENCE` in this project's config (see `docs/configuration.md`)

## Testing

`crates/lore-authz-server/tests/authz_suite/` is the one shared
authorization test suite, run against BOTH backends -- `tests/
postgres_backed.rs` (real Postgres, not a mock) and `tests/sqlite_backed.rs`
(real SQLite file, not a mock) are thin wrappers calling the exact same test
bodies, so SQLite is never a lesser-tested path. See `docs/data-model.md`
for what the suite proves. To run everything with nothing but Docker:

```sh
docker compose -f docker-compose.test.yml run --rm --build tests
docker compose -f docker-compose.test.yml down -v   # tear down the throwaway Postgres
```

This runs every test in the workspace (`cargo test --workspace` is the
compose service's command): unit tests, the lore-server compat suite, the
shared authz suite against both a real throwaway Postgres container AND a
real throwaway SQLite file per test, and the OIDC login-flow suite against a
real identity provider.

`crates/lore-authz-server/tests/oidc_flow.rs` drives the browser login leg
against a REAL OpenID Connect provider (Dex, in the `dex` compose service --
see `docker/dex/config.yaml`): a real discovery document, real PKCE
enforcement, real one-time authorization codes, and real RS256 ID tokens
signed with a real key served from a real JWKS endpoint. Nothing in it mocks
an HTTP response, and nothing in it is provider-specific -- every endpoint
comes from the provider's own discovery document, so pointing the suite at a
different IdP is a matter of changing `TEST_OIDC_*` variables, not test
code. Its headline case binds this service's real axum router to a real
socket and walks the entire flow with a redirect-following HTTP client, just
as a browser would.

`docker-compose.test.yml` never touches a shared or long-lived database:
`postgres` there uses a `tmpfs` data directory, the Postgres-backed tests
each create their own randomly-named schema, and the SQLite-backed tests
each get their own temp-file database, never a shared one. Every credential
in that file and in `docker/dex/config.yaml` is a fixed, publicly-known,
throwaway test value.

`.github/workflows/ci.yml` runs the same suite on every push/PR, against a
GitHub Actions Postgres service container and the same Dex image and config
file (the SQLite tests need no service container at all).

## Repository layout

```
epic-lore-authz/
  Cargo.toml                    workspace
  proto/vendor/                 vendored auth_api.proto + rebac_api.proto, provenance, hashes
  crates/
    lore-authz-proto/           tonic-build with build_server(true) -- the crux of the project
    lore-authz-core/            domain types + I/O-free traits, no business logic implemented yet
    lore-authz-server/          the binary: gRPC + HTTP listeners, config, stubbed RPC handlers
      migrations/                 Postgres migrations
      migrations_sqlite/          SQLite migrations (kept in step with the above by hand)
      tests/authz_suite/           shared authz test bodies, run against both backends
  docs/                         architecture, protocol gotchas, open questions, config reference
  .github/workflows/            ci.yml (fmt/build/test/clippy), proto-drift.yml (upstream drift guard)
  tasks.md                      phased delivery plan with pass/fail proof criteria per phase
```

## Status

Scaffold only. See `tasks.md` for the phased delivery plan and current
status of each phase.
