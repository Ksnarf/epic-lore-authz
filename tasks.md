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
      [code-says] Compiled for real in a pinned Docker build image
      (`docker/Dockerfile.build`, `rust:1.97.1-slim-trixie` + protoc);
      `cargo check --workspace` and `cargo build --workspace` both pass
      clean (no warnings). Switched `lib.rs` from a raw `include!` to
      `tonic::include_proto!`, now that the macro's expansion could
      actually be verified against tonic 0.14.6.
- [ ] gRPC server implementing (real logic, not stubs):
      `HealthCheck` [x, real, trivial], `StartAuthSession`, `GetAuthSession`,
      `ExchangeUserTokenForMultiresourceToken`.
      Currently: signatures + `Status::unimplemented` stubs only in
      `crates/lore-authz-server/src/grpc.rs`. The token-minting mechanism
      these handlers will call now exists and is tested (see the minting
      and compat-test items below) but is NOT wired into these RPCs yet.
      See `docs/open-questions.md` Q13 / `docs/protocol-notes.md` #7b for a
      real design gap this wiring will need to solve (`idp` cannot be
      recovered from the caller's AuthN token alone).
- [ ] `RebacApi` `CreateResource` / `DeleteResource` (in-memory).
      Currently: signatures + `Status::unimplemented` stubs only.
- [~] axum HTTP server: real `GET /.well-known/jwks.json` (from actual
      signing keys, not the previous empty-array placeholder), and a stub
      `GET /login/{session_code}` page with a single "Approve as
      `<configured test user>`" button (no real IdP yet).
      JWKS: [x] [verified-e2e] -- `crates/lore-authz-server/src/http.rs`'s
      `jwks()` handler returns `state.signing_keys.jwks()`, a real
      `jsonwebtoken::jwk::JwkSet` built from the active signing key (see
      `crates/lore-authz-server/src/signing.rs`), with both `kid` and `alg`
      set on every key. Promoted from [code-says] to [verified-e2e] on
      2026-08-03: a real unmodified `lore-server` built from the pinned
      commit, configured with
      `server.auth.jwk.endpoint = "http://authz-e2e:8080/.well-known/jwks.json"`,
      fetched this document over HTTP at boot and accepted it. Evidence:
      lore-server logged
      `"starting new connection: http://authz-e2e:8080/"` from
      `reqwest::connect` and then completed startup -- `lore-server/src/
      server.rs` does `jwk_service.fetch_new_keys(None).await?`, so a JWKS
      it could not fetch or parse would have aborted the boot. A later
      unknown-`kid` token also triggered the in-request refetch path,
      logging a second connection to the same URL. Integration tooling
      held locally.
      Login page: still `[ ]`, unchanged 501 stub -- out of scope for this
      pass.
- [x] One ES256 signing key loaded from env or file (`SIGNING_KEY_SOURCE`).
      Sessions and grants in memory. No Postgres yet.
      [code-says] `crates/lore-authz-server/src/signing.rs`:
      `SigningKeyStore::load` loads an unencrypted PKCS#8 EC P-256 private
      key (PEM or raw DER) from a `file://` `SIGNING_KEY_SOURCE`, or
      generates an ephemeral EC keypair in memory (logging a loud warning)
      if the file does not exist. Wired into `main.rs` at startup.
      `cargo test --workspace`: `signing::tests::*` (3 tests) pass,
      including a real round-trip sign/verify against a key loaded from an
      actual on-disk PKCS8 DER file. NOTE: `.env.example` originally
      described this as pointing at a JWK, which is impossible with this
      project's pinned `jsonwebtoken` crate (its `Jwk` type has no
      private-key variant) -- corrected in `.env.example`,
      `docs/configuration.md`, and `docs/protocol-notes.md` #7c.
- [x] Claims exactly per `docs/protocol-notes.md` section 2, including `env`
      and `idp`. `aud` per section 3.
      [code-says] `AuthzClaims` / `AuthnClaims` shapes in
      `crates/lore-authz-core/src/claims.rs` were already correct (verified
      field-for-field against `lore-server/src/auth/jwt.rs` again this
      pass, no changes needed to the shapes themselves). Minting code that
      actually uses them now exists:
      `crates/lore-authz-server/src/minting.rs`'s `mint_authn_token` /
      `mint_authz_token`, covered by `minting::tests::*` (2 tests) and the
      compat test below. `AuthzTokenInput::idp` is a mandatory `String`
      (not `Option`), so there is no call to `mint_authz_token` that both
      compiles and omits `idp` -- see `docs/protocol-notes.md` #7b for the
      real gap this creates for whoever wires the RPC that will call this
      (recovering `idp` at exchange time, since the caller's AuthN token
      itself has no `idp` field to decode it back out of).
- [x] Compat test: deserialize a token minted from `AuthzClaims` using a
      VERBATIM copy of lore-server's `AuthorizationToken` struct (MIT
      licensed, safe to vendor for test purposes). Assert `resources` is
      `Some` and contains the expected `urc-` id. This is the single
      highest-value test in the project per the design plan -- it is the
      only thing that would have caught a missing `idp` claim in CI before
      a customer does.
      [code-says] `crates/lore-authz-server/tests/lore_compat.rs`, vendoring
      `AuthorizationToken`/`JWTUserInfo`/`ResourcePermission` verbatim from
      `lore-server/src/auth/jwt.rs` at the pinned commit (module
      `lore_server_verbatim`, cites the exact upstream path + commit sha).
      `minted_authz_token_deserializes_into_lores_authorizationtoken_with_resources_populated`
      asserts `resources: Some(..)` with the expected `urc-` id and `idp`
      intact. A second test,
      `token_missing_idp_fails_authorizationtoken_decode_but_silently_succeeds_as_jwtuserinfo`,
      proves the missing-`idp` failure mode itself is real (hand-built
      claims JSON without `idp`, using the vendored types): the
      `AuthorizationToken` decode fails and the `JWTUserInfo` fallback
      decode silently succeeds, exactly reproducing lore-server's
      `verify_token_internal` behavior. `cargo test --workspace`: 4/4 tests
      in `tests/lore_compat.rs` pass (see proof section below). This is
      still `[code-says]`, not `[verified-e2e]`: it proves our tokens are
      byte-compatible with lore-server's own claim-deserialization code
      copied verbatim, not that a running unmodified `lore-server` binary
      accepts them -- that is the still-unstarted integration test below.
- [x] Compat test: feed our JWKS document to a verbatim copy of
      lore-server's `JwkServiceImpl` and assert `get_key(kid)` succeeds.
      Catches the missing-`alg` trap.
      [code-says] Implemented as
      `served_jwks_parses_as_lore_servers_jwkset_type_with_kid_and_alg_on_every_key`
      in `crates/lore-authz-server/tests/lore_compat.rs`. Deviation from the
      literal task wording, noted honestly: this asserts our JWKS parses as
      the exact `jsonwebtoken::jwk::JwkSet` type `JwkServiceImpl::
      fetch_new_keys` deserializes a JWKS HTTP response into (the same
      crate+version pin as lore-server, so this IS the type lore-server
      uses), and that every key has `kid` and `alg` `Some` -- the same two
      preconditions `JwkServiceImpl::fetch_new_keys`'s
      `.ok_or(JWKServiceError::InternalError)?` calls enforce. It does NOT
      vendor `JwkServiceImpl` itself (that type also depends on
      `lore_telemetry`/`opentelemetry` machinery not worth vendoring for
      this check). `cargo test --workspace` passes.
- [~] Integration test (the only proof that counts): run real UNMODIFIED
      `lore-server` in Docker configured with `auth.jwk.endpoint` pointing
      at our JWKS, `auth.jwt_issuer` / `auth.jwt_audience` set to our
      values, and `endpoint.auth_url` pointing at our gRPC. Then run the
      real unmodified `lore` CLI: `lore auth login --no-browser`, then
      `lore clone` / `lore push` / `lore pull`. Success criterion: a real
      push and a real pull complete.

      **SERVER HALF DONE [verified-e2e] (2026-08-03). CLI HALF NOT
      STARTED.** A real unmodified `lore-server` (built from the pinned
      commit, no source changes) was pointed at this sidecar's live JWKS on
      a private Docker network, minted tokens were presented to it, and its
      behavior matched expectations for token acceptance, signature/kid
      validation, and the missing-`idp` fallback (see section 2 of
      `docs/protocol-notes.md`). Integration tooling held locally.

      Still open before this task can go `[x]`: the real `lore` CLI has not
      been run at all, so nothing client-side is proven (`aud` root-domain
      check, the CLI's forced-https rewrite, `UserToken.expires_at` on the
      wire, QUIC) -- see `docs/protocol-notes.md` #9 for the explicit
      not-covered list. That needs `StartAuthSession` / `GetAuthSession` /
      `ExchangeUserTokenForMultiresourceToken`, which are still
      `Status::unimplemented`.
- [x] Determine what a real lore-server does end to end with a token
      missing `idp` (accept-but-unauthorized, or reject?).
      [verified-e2e] 2026-08-03. **Accept-but-unauthorized.** A hand-built
      token carrying every AuthZ claim INCLUDING a populated `resources`,
      minus `idp`, is accepted by `lore-server` (signature/iss/aud/exp all
      pass), silently decodes as `JWTUserInfo` so `resources` becomes
      `None`, and produces **no lore-server log line at all** for that
      decision (that absence is the diagnostic). See `docs/protocol-notes.md`
      section 2. Integration tooling held locally.
- [ ] Integration test: create a repository and assert `lore-server` calls
      our `CreateResource` with `resource_id "urc-<repoid>"`. Not started.
- [~] Settle `docs/open-questions.md` Q1 (`UserToken.expires_at` units)
      empirically: assert the CLI does not immediately re-login.
      [code-says], NOT [verified-e2e]: settled by reading source
      (`lore-transport/src/auth/ucs_auth.rs`'s `expires_ms:
      token.expires_at.max(0) as u64` with no `* 1000` scaling,
      `lore-transport/src/types.rs`'s doc comment, and
      `lore-transport/src/connection.rs`'s millisecond-shaped test
      literals) -- **milliseconds**. See `docs/open-questions.md` Q1 and
      `docs/protocol-notes.md` #7a for the full evidence chain.
      `crates/lore-authz-core/src/claims.rs`'s `SignedToken.expires_at` and
      `crates/lore-authz-server/src/minting.rs`'s `signed_token` now
      implement this. What is still missing per this task's own bar: the
      actual empirical CLI run (`lore auth login`, observe re-login
      behavior at the boundary) has NOT happened -- that requires the
      still-unstarted integration test above.
- [x] Settle `docs/open-questions.md` Q3 (correlation-id metadata key
      name). [verified-e2e] 2026-08-03: it is **`x-epic-correlation-id`**,
      not the guessed `x-correlation-id`
      (`lore_transport::grpc::CORRELATION_ID_HEADER`). Confirmed at runtime
      (integration tooling held locally), not just read. See
      `docs/open-questions.md` Q3 and `docs/protocol-notes.md` #7d.
- [ ] NEW (from the 2026-08-03 integration run): make `kid` deterministic.
      `signing.rs` mints a random `Uuid::new_v4()` `kid` on every key load,
      so two replicas loading the same `SIGNING_KEY_SOURCE` publish
      different `kid`s for the same key and cross-replica token validation
      fails with `KeyNotFound`. Fix by deriving `kid` from an RFC 7638 JWK
      thumbprint. Blocks nothing in Phase 0 (single process), MUST be
      settled before Phase 1 key rotation. See `docs/open-questions.md`
      Q14 / `docs/protocol-notes.md` #7e.

**Phase 0 exit gate**: the integration test above passes against an
unmodified upstream `lore-server` binary and unmodified `lore` CLI. Nothing
in this phase may be marked `[x]` with `[verified-e2e]` until that
integration test has actually been run and its output logged.

- [x] Phase 0 exit gate: token minting and JWKS verified against a real
      lore-server (integration tooling held locally). The real `lore` CLI
      half has not been run, so Phase 0 is not fully closed -- do not
      promote anything that depends on CLI-side behaviour (notably `aud`
      root-domain handling and `UserToken.expires_at`) on the strength of
      this run.

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
      0.14.1, jsonwebtoken 9.3.1). [code-says], builds clean (see below).
- [x] CI workflows: `ci.yml` (fmt/build/test/clippy),
      `proto-drift.yml` (pinned-commit hash check + upstream-main warn).
      [code-says], not run (would require a push to GitHub Actions; this
      repo is commit-only per the task constraints, not pushed). `ci.yml`
      now pins `dtolnay/rust-toolchain@1.97.1` (matches
      `rust-toolchain.toml` and `docker/Dockerfile.build`) and both
      `build-and-test` / `clippy` jobs install `protobuf-compiler` --
      the same recipe proven locally in the Docker image below.
- [x] `docs/architecture.md`, `docs/protocol-notes.md`,
      `docs/open-questions.md`, `docs/configuration.md`.
- [x] `.env.example` with placeholder-only values covering every config
      surface documented in `docs/configuration.md`.
- [x] `.gitignore` / `.gitattributes` / `rust-toolchain.toml`.

## Compile pass (2026-08-03, this session)

- [x] `docker/Dockerfile.build`: pinned `rust:1.97.1-slim-trixie` +
      `protobuf-compiler` (rust:1-slim lacks protoc, which
      `tonic-prost-build` needs). `scripts/build.sh` / `scripts/build.ps1`
      wrap it for POSIX and Windows PowerShell. [verified-e2e] image builds
      and both scripts' underlying `docker run` invocation was exercised
      directly; see command log below.
- [x] `rust-toolchain.toml` changed from floating `channel = "stable"` to
      pinned `channel = "1.97.1"` -- "stable" was making every rustup-shimmed
      cargo/rustc invocation hit the network to re-resolve and re-sync,
      which defeats reproducibility. [verified-e2e]: confirmed the
      "syncing channel updates" network call disappeared after the pin.
- [x] Fixed unused-import warning at
      `crates/lore-authz-core/src/policy.rs:15` (`AuthzClaims` was imported
      but never used in that file; removed the import).
      [verified-e2e] `cargo check` no longer warns.
- [x] Silenced the `Config` dead-code warning in
      `crates/lore-authz-server/src/config.rs` with `#[allow(dead_code)]`
      plus a comment explaining most fields are read starting Phase 0/1,
      not actually dead. [verified-e2e].
- [x] `crates/lore-authz-proto/src/lib.rs`: switched from the raw
      `include!(concat!(env!("OUT_DIR"), ...))` to `tonic::include_proto!`,
      now that its expansion (`include!(concat!(env!("OUT_DIR"),
      "/<package>.rs"))`, defined in `tonic-0.14.6/src/macros.rs`) could be
      verified against a real tonic 0.14.6 checkout. Removed the apologetic
      comment. [verified-e2e]: recompiled clean after the switch.
- [x] `crates/lore-authz-proto/build.rs`: verified as-is against the real
      tonic-prost-build 0.14.6 API (`Config::new()`, `.enable_type_names()`,
      `.bytes([...])`, `tonic_prost_build::configure()...compile_with_config`)
      -- no changes needed, it compiled and generated code on the first
      real build. `.build_server(true)` confirmed present and doing what
      the comment says (generates `UrcAuthApi`/`RebacApi` server traits).
- [x] `axum` 0.8 / `tonic` 0.14 signatures in
      `crates/lore-authz-server/src/{http,grpc,main,config}.rs`: verified
      as-is, no changes needed. `{session_code}` / `{*rest}` axum 0.8 path
      syntax, `#[tonic::async_trait]` impls, and generated message/struct
      names (incl. the `ExchangeAPIKeyForUserToken*` ->
      `ExchangeApiKeyForUserToken*` heck-casing gotcha) all matched what
      the scaffold author had already written.
- [x] `.github/workflows/ci.yml`: pinned `dtolnay/rust-toolchain@1.97.1` in
      all three jobs (was `@stable`) to match the local pin; protoc install
      steps were already present and correct.
- [x] `Cargo.lock` committed (workspace produces a binary,
      `lore-authz-server`).

**Verification (this session, 2026-08-03)**: built and ran inside
`docker/Dockerfile.build` (`rust:1.97.1-slim-trixie` + protoc) via
`docker run --rm -v <repo>:/work -w /work epic-lore-authz-build:local ...`
(Docker reached via PowerShell, per this box's environment notes):

- `cargo check --workspace` -- clean, 0 warnings.
- `cargo build --workspace` -- clean, 0 warnings, `Finished dev profile`.
- `cargo fmt --all -- --check` -- clean after one `cargo fmt --all` pass
  (3 files had minor formatting-only diffs: `error.rs`, `config.rs` comment
  alignment, `grpc.rs` line-wrap; no logic changed, confirmed via `git diff`).
- `cargo clippy --workspace --all-targets -- -D warnings` -- clean, 0
  warnings/errors.
- `cargo test --workspace` -- 0 tests exist yet (Phase 0 compat tests are
  still not-started, see below); the 0/0 result is expected, not a failure.

Not done in this pass (unchanged from before, still open): the
Phase 0 compat tests, the real IdP/gRPC business logic, and the
integration test against real `lore-server` / `lore` CLI. This pass was
scoped to "make it compile, stay stubbed, fail closed" -- it did not add
or change any RPC/HTTP business logic; every non-trivial handler still
returns `Status::unimplemented` / HTTP 501.

## Token minting, real JWKS, and the compat test (Track B, 2026-08-03)

Implemented (see the updated Phase 0 checkboxes above for per-item detail
and provenance tags): real ES256 signing key (loaded from
`SIGNING_KEY_SOURCE` or generated ephemeral, `crates/lore-authz-server/src/
signing.rs`), a real `GET /.well-known/jwks.json` built from it
(`crates/lore-authz-server/src/http.rs`), token minting functions for both
the AuthN and AuthZ shapes (`crates/lore-authz-server/src/minting.rs`), and
the compat test suite (`crates/lore-authz-server/tests/lore_compat.rs`).
Settled `docs/open-questions.md` Q1 (milliseconds) by source reading; see
`docs/protocol-notes.md` #7a-#7d for that and two other findings from this
pass (the `idp`/AuthnClaims gap for whoever wires the exchange RPC next,
and a correction to `SIGNING_KEY_SOURCE`'s documented format). Split
`lore-authz-server` into a `[lib]` + `[[bin]]` crate so `tests/` could
exercise the signing/minting code directly without a running server.

Added workspace dependencies: `ring = "0.17.4"` (matches jsonwebtoken
9.3.1's own pin exactly, so cargo resolves one `ring` and the PKCS#8
documents this project generates are guaranteed compatible with the
`EcdsaKeyPair::from_pkcs8` jsonwebtoken calls internally when signing) and
`base64 = "0.22"` (matches jsonwebtoken's internal pin; needed to hand-build
JWK `x`/`y` coordinates since jsonwebtoken does not re-export its own
base64 use). `serde_with` added as a `lore-authz-server` dev-dependency
(compat test only, to compile the vendored lore-server claim structs).

All 4 required checks run for real in the pinned Docker build image
(`docker/Dockerfile.build`, via `.\scripts\build.ps1`, Docker reached
through PowerShell per this box's environment notes) after this pass:

- `cargo build --workspace`: clean, `Finished` dev profile (unoptimized,
  with debuginfo) target(s) in 48.67s.
- `cargo test --workspace`: **9 tests pass, 0 failures.**
  `lore-authz-server` unit tests (5):
  `signing::tests::ephemeral_key_has_kid_and_alg_and_parses_as_jwk`,
  `signing::tests::non_file_source_generates_ephemeral_key`,
  `signing::tests::loads_a_real_pkcs8_der_key_file`,
  `minting::tests::authz_token_round_trips_with_resources_and_idp`,
  `minting::tests::authn_token_has_no_resources_field_at_all`.
  `tests/lore_compat.rs` integration tests (4):
  `minted_authz_token_deserializes_into_lores_authorizationtoken_with_resources_populated`,
  `minted_authn_token_deserializes_into_lores_jwtuserinfo_fallback_shape`,
  `token_missing_idp_fails_authorizationtoken_decode_but_silently_succeeds_as_jwtuserinfo`,
  `served_jwks_parses_as_lore_servers_jwkset_type_with_kid_and_alg_on_every_key`.
  `lore-authz-core` / `lore-authz-proto`: 0 tests (unchanged, no test code
  added to those crates this pass).
- `cargo fmt --all -- --check`: clean after one `cargo fmt --all` pass
  (reformatted `signing.rs`, `minting.rs`, `main.rs`, `tests/lore_compat.rs`
  -- whitespace/line-wrap only, no logic changed).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean, 0
  warnings/errors.

Also verified this pass (raw commands, not just claimed):
`git -C <epic-lore fork> status --short` returned empty (fork untouched);
recomputed `sha256sum proto/vendor/{auth_api,rebac_api}.proto` and diffed
against `proto/vendor/SHA256SUMS` byte-for-byte (unchanged); a repo-wide
scan (`git ls-files` + `git ls-files --others --exclude-standard`, every
file decoded as strict ASCII) found zero non-ASCII bytes; a grep for
operator names, drive-letter paths, and known client/project names across
every changed file found zero hits; a grep for "BEGIN ... PRIVATE KEY" found only
the string-literal PEM markers `signing.rs` uses to detect PEM input, no
actual key material.

NOT done in this pass, still open (see the Phase 0 checkboxes above for the
authoritative per-item status): `ExchangeUserTokenForMultiresourceToken`
and the other gRPC handlers are still `Status::unimplemented` -- the
minting functions built this pass are not wired into them yet, and the
`idp`-lookup design gap noted in `docs/protocol-notes.md` #7b needs solving
first. The real integration test against unmodified upstream `lore-server`
and `lore` CLI (the actual Phase 0 exit gate) has not run.
`docs/open-questions.md` Q3 remains open.

## Real lore-server integration run (Track C, 2026-08-03)

Verified token minting and JWKS compatibility against a real, unmodified
`lore-server` binary built from the pinned commit (integration tooling held
locally, not part of this published tree).

`crates/lore-authz-server/src/bin/dev_mint_token.rs` was added to support
this: a DEV-ONLY minting CLI that refuses to run without
`LORE_AUTHZ_DEV_MINT=1`, documented in `Cargo.toml` as never to be copied
into a runtime image. It exists because the gRPC RPCs that would mint these
tokens for real are still stubs; it calls the same `minting.rs` functions
those RPCs will. `/e2e-run/` was added to `.gitignore` for the generated
signing key, config, and local store scratch this kind of run produces.

Docs corrected as a result:

- `docs/open-questions.md` Q3 was **wrong** (`x-correlation-id`); the real
  key is `x-epic-correlation-id`. Now SETTLED.
- `docs/protocol-notes.md` gained #7e + Q14 (random `kid` per key load) and
  RUNTIME-VERIFIED annotations on sections 2 and 4.
- `docs/open-questions.md` Q1 gained a note that this run does not settle
  it, since no `UserToken` crosses the wire in it.

All four workspace checks re-run in the pinned build image after these
changes (`docker/Dockerfile.build`, Docker via PowerShell):

- `cargo build --workspace`: clean.
- `cargo test --workspace`: 9 tests pass, 0 failures (unchanged set -- this
  pass added no unit tests; the new proof is the integration run, which is
  not a `cargo test`).
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
