# tasks

Checkbox scheme: `[ ]` open, `[x]` done, `[~]` partial, `[?]` blocked.
Provenance tags on `[x]`/`[~]` items: `[verified-e2e]` (real integration run,
evidence logged), `[code-says]` (code exists / builds, not run end-to-end),
`[deployed-not-proven]`, `[not-built]`, `[blocked]`.

This phased breakdown is adapted from the design plan (section E, kept
outside this repo). Each phase lists its own "how we prove it works" test --
do not flip a task to `[x]` without that proof; see the individual gate notes.

## Phase 0 - "lore accepts our tokens" (thinnest possible thing)

- [x] Vendor `auth_api.proto` and `rebac_api.proto` from `EpicGames/lore` at
      pinned commit `f205899adf24b13b2d28e5c08d9256ac99c69f0c`, with
      `UPSTREAM.md` provenance and real `SHA256SUMS`.
      [code-says] files present at `proto/vendor/`; hashes computed for real
      via PowerShell `Get-FileHash` (see UPSTREAM.md), not fabricated.
- [x] Scaffold `lore-authz-proto` crate: `build.rs` compiling the vendored
      protos with `tonic_prost_build` and `.build_server(true)`.
      [code-says] file exists at `crates/lore-authz-proto/build.rs`; NOT
      compiled (no local Rust toolchain on the scaffolding machine -- see
      repo root note below). Needs a real `cargo build` with `protoc` on
      `PATH` to confirm the generated code actually compiles and that the
      `include!` path (`OUT_DIR`) resolves as expected.
- [ ] gRPC server implementing (real logic, not stubs):
      `HealthCheck` [x, real, trivial], `StartAuthSession`, `GetAuthSession`,
      `ExchangeUserTokenForMultiresourceToken`.
      Currently: signatures + `Status::unimplemented` stubs only in
      `crates/lore-authz-server/src/grpc.rs`.
- [ ] `RebacApi` `CreateResource` / `DeleteResource` (in-memory).
      Currently: signatures + `Status::unimplemented` stubs only.
- [ ] axum HTTP server: real `GET /.well-known/jwks.json` (from actual
      signing keys, not the current empty-array placeholder), and a stub
      `GET /login/{session_code}` page with a single "Approve as
      `<configured test user>`" button (no real IdP yet).
      Currently: routes wired in `crates/lore-authz-server/src/http.rs`
      returning placeholders / 501.
- [ ] One ES256 signing key loaded from env or file (`SIGNING_KEY_SOURCE`).
      Sessions and grants in memory. No Postgres yet.
      Currently: `SIGNING_KEY_SOURCE` config var exists; nothing reads it.
- [ ] Claims exactly per `docs/protocol-notes.md` section 2, including `env`
      and `idp`. `aud` per section 3.
      Currently: `AuthzClaims` / `AuthnClaims` shapes exist in
      `crates/lore-authz-core/src/claims.rs`; no minting code uses them yet.
- [ ] Compat test: deserialize a token minted from `AuthzClaims` using a
      VERBATIM copy of lore-server's `AuthorizationToken` struct (MIT
      licensed, safe to vendor for test purposes). Assert `resources` is
      `Some` and contains the expected `urc-` id. This is the single
      highest-value test in the project per the design plan -- it is the
      only thing that would have caught a missing `idp` claim in CI before
      a customer does.
      Not started. Proposed location: `tests/compat/` (not yet created;
      out of scope for this scaffold pass).
- [ ] Compat test: feed our JWKS document to a verbatim copy of
      lore-server's `JwkServiceImpl` and assert `get_key(kid)` succeeds.
      Catches the missing-`alg` trap. Not started.
- [ ] Integration test (the only proof that counts): run real UNMODIFIED
      `lore-server` in Docker configured with `auth.jwk.endpoint` pointing
      at our JWKS, `auth.jwt_issuer` / `auth.jwt_audience` set to our
      values, and `endpoint.auth_url` pointing at our gRPC. Then run the
      real unmodified `lore` CLI: `lore auth login --no-browser`, then
      `lore clone` / `lore push` / `lore pull`. Success criterion: a real
      push and a real pull complete. Not started.
- [ ] Integration test: create a repository and assert `lore-server` calls
      our `CreateResource` with `resource_id "urc-<repoid>"`. Not started.
- [ ] Settle `docs/open-questions.md` Q1 (`UserToken.expires_at` units)
      empirically: assert the CLI does not immediately re-login. Not
      started.
- [ ] Settle `docs/open-questions.md` Q3 (correlation-id metadata key
      name). Not started.

**Phase 0 exit gate**: the integration test above passes against an
unmodified upstream `lore-server` binary and unmodified `lore` CLI. Nothing
in this phase may be marked `[x]` with `[verified-e2e]` until that
integration test has actually been run and its output logged.

## Phase 1 - Real IdP, persistence, service accounts

- [ ] Postgres, sqlx migrations, schema-qualified DDL, `DB_SCHEMA` config
      honored (never `public`, never a dedicated database, never
      superuser).
- [ ] OIDC authorization code + PKCE against Okta, Entra ID, Auth0,
      Keycloak.
- [ ] JIT user provisioning, group claim to `groups` mapping.
- [ ] Full RBAC: roles, role_bindings, wildcard bindings. Token minter
      reads real policy (`lore-authz-core::policy::PolicyStore`).
- [ ] `ExchangeExternalTokenForUserToken` (api-key and CI-OIDC token
      types), `ExchangeAPIKeyForUserToken`.
- [ ] `GetUserInfo`, `GetUserId`, `GetProviderUserId`.
- [ ] `CheckUserPermission`, `LookupUserPermissions` with pagination.
- [ ] Key rotation: `Pending` -> `Active` -> `Retired` with JWKS
      pre-publication of the next key.
- [ ] Session reaper, `audit_log` writes, `status = deprovisioned`
      enforcement.

**Phase 1 proof**: automated e2e per IdP using containerized Keycloak in
CI, plus manual smoke against Okta and Entra ID trial tenants. Assert that
revoking a `role_binding` denies the NEXT exchange, and that an
already-issued AuthZ token still works until its short TTL expires
(document that window explicitly -- see `docs/protocol-notes.md` #7).

## Phase 2 - SAML 2.0 and admin surface

- [ ] SP metadata endpoint, ACS with signature + condition + replay
      validation, SP-initiated and IdP-initiated, group attribute mapping.
      Behind the `saml` cargo feature (see `docs/architecture.md`).
- [ ] Admin REST API `/admin/v1` for users, groups, roles, bindings, api
      keys, idp connections.
- [ ] Minimal admin web UI (optional, can slip to a later phase).

**Phase 2 proof**: SAML conformance against Keycloak-as-SAML-IdP in CI,
plus one real Entra ID SAML app. Assert that a signature-stripped assertion
and a replayed assertion are BOTH rejected -- negative tests are the entire
point of a SAML implementation.

## Phase 3 - SCIM 2.0 and operational hardening

- [ ] `/scim/v2/Users` and `/scim/v2/Groups`, PATCH semantics, filter
      subset, bearer token auth.
- [ ] Deprovisioning propagation, multi-replica correctness (sessions
      already in Postgres by Phase 1), Prometheus metrics, OpenTelemetry
      traces, structured audit export.

**Phase 3 proof**: run Okta and Entra ID SCIM provisioning against it.
Assert a suspended user's next exchange fails and existing tokens expire
within TTL.

## Phase 4 - Distribution

- [ ] Helm chart, docker-compose reference, Terraform module, signed
      multi-arch images, SBOM, security docs, threat model, upgrade/rebase
      guide against lore releases.

## Scaffold housekeeping (this pass, 2026-08-03)

- [x] Workspace `Cargo.toml` with versions pinned to match
      `EpicGames/lore`'s own `[workspace.dependencies]` at the pinned
      commit (tonic 0.14.2, tonic-prost / tonic-prost-build 0.14.2, prost
      0.14.1, jsonwebtoken 9.3.1). [code-says], not built (no local Rust
      toolchain -- see verification note below).
- [x] CI workflows: `ci.yml` (fmt/build/test/clippy),
      `proto-drift.yml` (pinned-commit hash check + upstream-main warn).
      [code-says], not run (would require a push to GitHub Actions; this
      repo is commit-only per the task constraints, not pushed).
- [x] `docs/architecture.md`, `docs/protocol-notes.md`,
      `docs/open-questions.md`, `docs/configuration.md`.
- [x] `.env.example` with placeholder-only values covering every config
      surface documented in `docs/configuration.md`.
- [x] `.gitignore` / `.gitattributes` / `rust-toolchain.toml`.

**Verification note**: `cargo`/`rustc` are not installed on the machine this
scaffold was written on (confirmed via both Bash and PowerShell: "command
not found" / "not recognized"). `cargo fmt --check` and `cargo build` could
NOT be run. Everything under crates/ is UNVERIFIED to compile. This is
called out honestly rather than claimed as working; the first real task for
whoever picks this up should be installing a Rust toolchain + `protoc` and
running `cargo build --workspace` for the first time.
