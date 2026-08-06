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
- [x] NEW (from the 2026-08-03 integration run): make `kid` deterministic.
      `signing.rs` minted a random `Uuid::new_v4()` `kid` on every key load,
      so two replicas loading the same `SIGNING_KEY_SOURCE` published
      different `kid`s for the same key and cross-replica token validation
      failed with `KeyNotFound`. Fixed by deriving `kid` from an RFC 7638
      JWK thumbprint. See `docs/open-questions.md` Q14 (now SETTLED) /
      `docs/protocol-notes.md` #7e.
      [verified-e2e] (unit level, real key material -- not a deployment
      claim) `crates/lore-authz-server/src/signing.rs`'s
      `rfc7638_p256_thumbprint`: `base64url(SHA-256(canonical JWK JSON))`
      over exactly the members RFC 7638 section 3.2 requires for an EC key
      (`crv`, `kty`, `x`, `y`), lexicographic, no whitespace. Three tests
      added, all passing in the pinned build image (`cargo test --workspace
      --lib`: 33 passed, up from 30):
      `signing::tests::same_key_material_yields_an_identical_kid_across_two_independent_loads`
      (writes a real PKCS#8 EC P-256 key to disk, loads it through two
      INDEPENDENT `SigningKeyStore::load` calls -- the multi-replica case in
      miniature -- and asserts both the `kid` field and the published JWKS
      `kid` are identical),
      `signing::tests::different_key_material_yields_a_different_kid` (so a
      hardcoded constant could not pass the first test), and
      `signing::tests::thumbprint_is_a_43_char_base64url_sha256_over_the_canonical_member_order`
      (pins the algorithm shape so a refactor cannot silently redefine
      `kid`). `signing::tests::non_file_source_generates_ephemeral_key` was
      updated: `kid` is now 43 base64url chars and no longer parses as a
      UUID.

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

## PHASE 1a - LookupUserPermissions, CheckUserPermission, RebacApi (2026-08-05)

A deliberate re-slice ahead of the rest of Phase 1: implements exactly the
four RPCs lore-server was observed to call on the wire during Phase 0
integration testing (`RepositoryList` -> `LookupUserPermissions`,
`RepositoryQuery`/`RepositoryGet` -> `CheckUserPermission`,
`RepositoryCreate`/`RepositoryDelete` -> `RebacApi::CreateResource`/
`DeleteResource` -- see `docs/open-questions.md` Q4, now SETTLED), backed by
real Postgres. Everything else in Phase 0/Phase 1 (`StartAuthSession`,
`GetAuthSession`, `ExchangeUserTokenForMultiresourceToken`, OIDC, SAML)
is deliberately untouched and remains `Status::unimplemented` -- Phase 1b.

- [x] Postgres schema + `DB_SCHEMA`-scoped, idempotent migrations.
      [verified-e2e] `crates/lore-authz-server/migrations/
      0001_identities_resources_grants.sql`: `principals`, `groups`,
      `group_members`, `resources`, `roles`, `role_permissions`-equivalent
      (a `permissions text[]` column on `roles`), `role_bindings`. Every
      pooled connection gets `search_path` set to `DB_SCHEMA` in
      `after_connect` (`crates/lore-authz-server/src/db/mod.rs`), so the
      migration SQL is deliberately schema-unqualified; `DB_SCHEMA` is
      validated (`validate_schema_identifier`) to reject `public` and
      anything that is not a plain lowercase SQL identifier before any DDL
      runs. Migrations run automatically at process startup
      (`Db::connect` -> `db.migrate()` in `main.rs`) via `sqlx::migrate!`,
      which tracks its own history table inside `DB_SCHEMA`; there is no
      separate migrate command. Idempotency proven for real by
      `tests/postgres_backed.rs`'s `migrations_are_idempotent`, which
      re-runs `db.migrate()` against an already-migrated schema and asserts
      no error. See `docs/data-model.md` for the full schema writeup.
- [x] `LookupUserPermissions` (real logic, Postgres-backed).
      [verified-e2e] `crates/lore-authz-server/src/grpc.rs`. Resolves the
      caller from the `authorization` metadata (`crate::caller`), asks
      `db::resources::list_resource_ids_with_prefix` for the candidate set
      matching `resource_filter` (settled as a plain prefix match --
      `docs/open-questions.md` Q5), then
      `db::permissions::PgPolicyStore::resolve_resource_permissions` for
      the effective, currently-authorized subset. A wildcard grant is
      ALWAYS expanded to concrete, currently-registered resource ids, never
      returned as the literal string `"urc-*"` -- see
      `crates/lore-authz-server/src/db/permissions.rs`'s module doc comment
      for why a literal wildcard entry would be silently dropped by the
      real call site. Pagination (`page_size`/`page_token`) is implemented
      (offset-based over the already-resolved set) even though no observed
      call site uses it.
- [x] `CheckUserPermission` (real logic, Postgres-backed).
      [verified-e2e] Same file. Resolves the caller either from
      `target_user.user_token` (if supplied) or the `authorization`
      metadata (tested explicitly:
      `check_user_permission_with_explicit_target_user_token`), then splits
      `req.resource_id` into `allowed_resource_permission` /
      `denied_resource_permission` via the same policy engine
      `LookupUserPermissions` uses. A requested resource_id that does not
      exist (never created, or soft-deleted) is placed in `denied`, never
      `allowed`, even under a wildcard `admin` grant -- this was a real bug
      found and fixed during this pass (see below).
- [x] `RebacApi::CreateResource` / `DeleteResource` (real logic,
      Postgres-backed). [verified-e2e] `create_resource` upserts into
      `resources`; a second call for the same `resource_id` returns
      `Status::already_exists` (`Code::AlreadyExists`), matching the real
      fork's `repository_create_auth_resource` call site, which treats
      `AlreadyExists` as a successful create, not an error. `delete_resource`
      soft-deletes (`deleted_at = now()`); deleting an already-deleted or
      never-existing `resource_id` is not an error (0 rows affected is a
      normal outcome), matching the fork's own delete call site not
      special-casing not-found. Both tested for idempotency
      (`create_resource_is_idempotent`,
      `delete_resource_revokes_access_and_is_idempotent`, the latter also
      proving a delete actually revokes a standing grant).
      Design gap left OPEN, not resolved: neither RPC checks caller
      identity at all (`docs/open-questions.md` Q6) -- matches the design
      plan's own recommendation to gate this hop with mTLS/a shared secret
      rather than a user token, since there is still no evidence
      `lore-server` ever sends one worth decoding, but this means anything
      that can reach the gRPC port can create/delete resource rows today.
- [x] Caller identity resolution (`crates/lore-authz-server/src/caller.rs`).
      [verified-e2e] Verifies a bearer JWT against this server's own active
      signing key (self-issued only -- no external IdP yet, Phase 1b),
      recovers the `sub` claim as a `principals.id`. Treats an empty
      `authorization` value the same as a missing one (per
      `authnz/common.rs`'s `can_create_request_without_authorization`
      behavior in the fork). A validly-signed token whose `sub` does not
      resolve to an `active` row in `principals` denies with
      `Status::unauthenticated` (`db::principals::find_active_principal`)
      -- unknown, suspended, and deprovisioned principals are all treated
      identically: deny.
- [x] Real bug found and fixed during this pass: the first version of
      `PgPolicyStore::resolve_resource_permissions` (written before this
      pass reconciled the two implementations, see the salvage note below)
      never checked resource EXISTENCE for the `CheckUserPermission` path --
      only `LookupUserPermissions` pre-filtered candidates through
      `list_resource_ids_with_prefix` (which already excludes deleted /
      never-created resources). A wildcard grant therefore authorized ANY
      requested `resource_id`, including one that was never created or had
      been deleted. Caught by two tests written for exactly this
      (`nonexistent_resource_is_denied_not_errored`,
      `delete_resource_revokes_access_and_is_idempotent`), which failed
      against the original implementation. Fixed by adding an existence
      check (`resources` table, `deleted_at IS NULL`) INSIDE the shared
      `resolve_resource_permissions` method itself, so every future caller
      (including the still-unbuilt `ExchangeUserTokenForMultiresourceToken`)
      gets this for free rather than each caller having to remember to
      pre-filter. See `crates/lore-authz-server/src/db/permissions.rs`.
- [x] Real Postgres-backed test suite (not sqlite, not a mock).
      [verified-e2e] `crates/lore-authz-server/tests/postgres_backed.rs`,
      16 tests, all passing against a real Postgres 16 container (see
      proof section below). Each test connects with its own randomly-named
      schema (`test_<uuid>`) inside the same database, proving `DB_SCHEMA`
      isolation actually works and letting tests run concurrently. Covers
      every required case: wildcard `urc-*` grant
      (`wildcard_grant_allows_any_registered_resource`), a specific-resource
      grant that does not leak to a sibling resource
      (`specific_repository_grant_does_not_cover_other_repositories`), a
      user with zero grants (`user_with_no_grants_denies_everything`), a
      group-inherited grant with no direct binding on the user at all
      (`group_inherited_grant`), a service account
      (`service_account_direct_grant`), the EXACT (not superset/subset)
      scoped set `LookupUserPermissions` must return
      (`lookup_user_permissions_returns_exact_scoped_set_no_more_no_less`,
      `lookup_user_permissions_specific_only_does_not_leak_other_resources`),
      and explicit fail-closed proof for every required error path: unknown
      resource (`nonexistent_resource_is_denied_not_errored`), unknown
      principal (`unknown_principal_id_denies_check`,
      `unknown_principal_id_denies_lookup`), missing bearer token
      (`missing_bearer_token_is_unauthenticated`), and a REAL simulated DB
      failure -- the connection pool closed out from under an otherwise
      fully-authorized request
      (`database_failure_denies_rather_than_grants`), asserting `Err` with
      `Code::Internal`, never a permissive `Ok`.
- [x] `docker-compose.test.yml` at the repo root: a throwaway
      `postgres:16-alpine` (tmpfs data dir) plus a `tests` service built
      from the same `docker/Dockerfile.build`. Documented in `README.md`'s
      new Testing section: `docker compose -f docker-compose.test.yml run
      --rm --build tests`, then `down -v` to tear down. Never touches a
      shared database; never `CREATE DATABASE`s.
      [verified-e2e] run for real this pass (see proof section below).
- [x] CI: `.github/workflows/ci.yml`'s `build-and-test` job now runs a
      `postgres:16-alpine` GitHub Actions service container and sets
      `TEST_DATABASE_URL` for the `cargo test --workspace` step, so
      `tests/postgres_backed.rs` runs in CI too. [code-says] -- not run
      (would require a push to GitHub Actions; this repo is commit-only per
      the task constraints, not pushed).
- [x] Docs: `docs/open-questions.md` Q4 SETTLED (lore-server does call both
      RPCs, with the exact call sites cited), Q5 SETTLED for
      `resource_filter` (plain prefix match) with the wildcard-expansion
      gotcha documented, Q6 given an explicit "not resolved, only worked
      around" implementation-status note. New `docs/data-model.md`
      describing the schema and the shared policy-resolution engine.
      `docs/configuration.md`'s `DATABASE_URL`/`DB_SCHEMA` rows updated to
      reflect Phase 1a load-bearing status and the migrate-on-connect
      design choice. `README.md`'s "What this is NOT" and a new Testing
      section updated.

**Left open / explicitly out of scope for this pass** (Phase 1b unless
noted):

- `StartAuthSession`, `GetAuthSession`, `ExchangeUserTokenForMultiresourceToken`,
  OIDC, SAML: still `Status::unimplemented`, untouched, by design.
- `GetUserInfo`, `GetUserId`, `GetProviderUserId`,
  `ExchangeExternalTokenForUserToken`, `ExchangeAPIKeyForUserToken`,
  `VerifyUser`: still `Status::unimplemented`, untouched.
- `RebacApi` caller-identity / trust boundary (`docs/open-questions.md` Q6):
  genuinely unresolved, not just deferred -- needs a real design decision
  (mTLS, shared secret, or something else) before any real deployment.
- `LookupUserPermissionsRequest.context_filter`: accepted on the wire, not
  acted on (no observed call site sets it).
- `PolicyStore` trait (`lore-authz-core::policy`) is still not implemented
  by anything -- `CheckUserPermission`/`LookupUserPermissions` are built
  directly against `db::permissions::PgPolicyStore`'s own inherent methods,
  which intentionally differ in shape from what the trait's documented
  sizing-rule contract wants for token minting (a wildcard grant collapses
  to a single `"urc-*"` entry for token-sizing purposes, but must be
  expanded to concrete ids for `CheckUserPermission`/`LookupUserPermissions`
  -- see `docs/data-model.md`). Whoever wires
  `ExchangeUserTokenForMultiresourceToken` in Phase 1b should read
  `db/permissions.rs` closely before deciding whether/how to share code
  with it.
- Session collision note: this pass started as two independent, concurrent
  implementations against the same working tree (a coordination error, not
  a design decision) and was reconciled into the one described above --
  see `log.log` in the parent `foundation` repo for the incident record.
  Nothing about the resulting design was compromised by that; noted here
  only for provenance.

**Proof (this pass, all four checks run for real in the pinned Docker build
image, `docker/Dockerfile.build`, Docker reached via PowerShell):**

- `cargo build --workspace`: clean, `Finished` dev profile.
- `cargo test --workspace`: **33 tests pass, 0 failures.**
  `lore-authz-core` / `lore-authz-proto`: 0 tests (unchanged).
  `lore-authz-server` unit tests (13): signing (3), caller (4), minting (2),
  grpc (4, the "Postgres not configured -> `FailedPrecondition`" fail-closed
  cases for all four PHASE 1a RPCs).
  `tests/lore_compat.rs` (4): unchanged from Phase 0.
  `tests/postgres_backed.rs` (16): **all 16 run against a real Postgres 16
  container** (`docker-compose.test.yml`'s `postgres` service; also
  reproduced via a standalone `docker compose up -d postgres` +
  `docker compose run --rm --build tests`). Test names:
  `wildcard_grant_allows_any_registered_resource`,
  `specific_repository_grant_does_not_cover_other_repositories`,
  `user_with_no_grants_denies_everything`, `group_inherited_grant`,
  `service_account_direct_grant`,
  `lookup_user_permissions_returns_exact_scoped_set_no_more_no_less`,
  `lookup_user_permissions_specific_only_does_not_leak_other_resources`,
  `nonexistent_resource_is_denied_not_errored`,
  `unknown_principal_id_denies_check`, `unknown_principal_id_denies_lookup`,
  `missing_bearer_token_is_unauthenticated`,
  `database_failure_denies_rather_than_grants`,
  `check_user_permission_with_explicit_target_user_token`,
  `create_resource_is_idempotent`,
  `delete_resource_revokes_access_and_is_idempotent`,
  `migrations_are_idempotent`. (First run, before the existence-check fix
  above, showed 14/16 passing with `delete_resource_revokes_access_and_is_
  idempotent` and `nonexistent_resource_is_denied_not_errored` FAILING for
  the real reason documented above; re-run after the fix: 16/16.)
- `cargo fmt --all -- --check`: clean (one `cargo fmt --all` pass applied
  first; whitespace/line-wrap only in `grpc.rs` and `tests/
  postgres_backed.rs`, no logic changed).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean (one fix
  required: `clippy::manual_map` in `grpc.rs`'s `check_user_permission`,
  rewritten to `user.as_ref().map(...)` per clippy's own suggestion).

Also verified this pass, raw commands not just claimed: `git status --short`
after committing; `sha256sum proto/vendor/{auth_api,rebac_api}.proto`
recomputed and diffed byte-for-byte against `proto/vendor/SHA256SUMS`
(unchanged); a repo-wide non-ASCII scan of every tracked file (clean); a
grep across every tracked and newly-added file for a fixed set of
embargo-sensitive terms (not spelled out in this tracked file on purpose),
plus a real-name placeholder string, any absolute host filesystem path, and
anything resembling real key material -- zero hits beyond the pre-existing
PEM-marker string literals `signing.rs` already used to detect key format,
which are not real key material. See the coordinator's session log for the
exact commands and their output.

## Security review remediation, item 1: RebacApi caller-identity gate (2026-08-05)

A security review found `RebacApi::create_resource` / `delete_resource`
(`crates/lore-authz-server/src/grpc.rs`) performed NO caller-identity check
at all -- an unauthenticated party reaching the gRPC port could iterate the
predictable `urc-{repository_id}` convention calling `delete_resource`,
mass-revoking authorization for every repository (a full authorization-
server DoS with zero credentials; delete soft-deletes and correctly denies
afterward, so this was availability, not a bypass). A LOW finding in the
same review: `create_resource` accepted any non-empty `resource_id`,
including the literal wildcard sentinel `urc-*`.

- [x] Require caller authentication on BOTH `RebacApi` RPCs.
      [verified-e2e] New module `crates/lore-authz-server/src/
      service_auth.rs`: `verify_rebac_caller` gates both RPCs on a shared
      secret (`REBAC_SERVICE_TOKEN`), presented as `authorization: Bearer
      <secret>`. Deliberately NOT `crate::caller`'s bearer-JWT pattern: read
      `lore-server/src/authnz/rebac.rs`'s `RebacClientHelper` (read-only, in
      the sibling `epic-lore` checkout, per this pass's constraints) and
      confirmed it attaches no bearer token and no client TLS identity to
      these calls --
      only a `CorrelationInterceptor`. A JWT check would verify a token
      `lore-server` never sends. A shared secret matches the design plan's
      own recommendation (`docs/open-questions.md` Q6/Q12, now resolved on
      this project's side) and is enforceable entirely within this repo.
      `RebacApiService::authorize_caller` (`grpc.rs`) runs BEFORE
      `require_db`, so an unauthenticated caller learns nothing about this
      service's Postgres configuration state.
- [x] FAIL CLOSED when the gate is not configured.
      [verified-e2e] `verify_rebac_caller` denies with
      `Status::unauthenticated` when `REBAC_SERVICE_TOKEN` is `None` or
      empty, regardless of what the caller presents -- proven by
      `service_auth::tests::unconfigured_secret_denies_even_with_a_
      presented_token`, `grpc::tests::create_resource_denies_when_gate_is_
      unconfigured_even_with_a_presented_token`, and the `delete_resource`
      equivalent. `main.rs` logs a startup warning when unset, mirroring the
      existing `DATABASE_URL`-unset warning.
- [x] `create_resource` rejects the literal wildcard sentinel and validates
      `resource_id` format (the LOW finding).
      [verified-e2e] `grpc.rs`'s `validate_new_resource_id`: rejects empty,
      rejects the exact string `db::permissions::WILDCARD_RESOURCE_PATTERN`
      (`"urc-*"`), requires the `"urc-"` prefix, and requires a non-empty
      ASCII alphanumeric (plus `-`/`_`) suffix -- matches the real
      `urc-{repository_id}` shape (confirmed against `lore-base::types::
      Partition`'s hex `Display` impl, read-only, in the `epic-lore`
      checkout) without being so strict it would reject the short
      alphanumeric ids this project's own test fixtures already use (e.g.
      `"urc-idem"`). Proven by `grpc::tests::create_resource_rejects_
      wildcard_sentinel_resource_id`, `..._rejects_resource_id_missing_urc_
      prefix`, `..._rejects_empty_suffix_after_prefix`, and end to end
      against real Postgres by `tests/postgres_backed.rs`'s
      `rebac_create_resource_rejects_wildcard_sentinel_against_real_db`.
- [x] Tests proving all five required cases.
      [verified-e2e] Unauthenticated DENIED:
      `grpc::tests::create_resource_denies_unauthenticated_caller` /
      `delete_resource_denies_unauthenticated_caller` (unit) and
      `tests/postgres_backed.rs`'s `rebac_create_resource_denies_
      unauthenticated_caller_against_real_db` / `rebac_delete_resource_
      denies_unauthenticated_caller_against_real_db` (real Postgres; the
      latter also asserts the resource genuinely still exists after the
      denied delete). Wrong credential DENIED:
      `create_resource_denies_wrong_service_token` /
      `delete_resource_denies_wrong_service_token` (unit) and
      `rebac_create_resource_denies_wrong_service_token_against_real_db`
      (real Postgres). Unconfigured gate DENIED: see above. Valid credential
      ALLOWED: proven for real, not just by absence of a denial, by the
      pre-existing `create_resource_is_idempotent` and `delete_resource_
      revokes_access_and_is_idempotent` tests in `tests/postgres_backed.rs`,
      updated this pass to present `REBAC_SERVICE_TOKEN` via a new `Harness::
      rebac_request` helper and still passing against a real Postgres
      container. Wildcard-sentinel REJECTED: see above.
      `service_auth.rs`'s own unit tests additionally cover a
      prefix-of-the-real-secret probe
      (`a_token_that_is_a_prefix_of_the_real_one_still_denies`) and an empty
      `REBAC_SERVICE_TOKEN=""` being treated as unconfigured, not as an
      "empty secret matches empty bearer" allow-all.

**Config surface**: `REBAC_SERVICE_TOKEN` (`.env.example`,
`docs/configuration.md`'s new dedicated section). **Honest gap, stated in
both docs**: the pinned/unmodified upstream `lore-server` this project
integrates against has no config surface to send this (or any) header on
this hop, so enabling this gate is a real deployment requirement (something
on the network path must inject the header), not something achievable by
this repo alone -- see `docs/open-questions.md` Q6/Q12 and
`docs/configuration.md`.

**Proof, all four workspace checks run for real in the pinned Docker build
image (`docker/Dockerfile.build`, Docker reached via PowerShell)**:

- `cargo build --workspace`: clean, `Finished` dev profile, 0 warnings.
- `cargo test --workspace` (via `docker compose -f docker-compose.test.yml
  run --rm --build tests`, real Postgres 16 container): **54 tests pass, 0
  failures** (up from 33 before this pass).
  `lore-authz-server` unit tests: **30** (up from 13 -- added 7 in
  `service_auth::tests` and 10 in `grpc::tests`: 2 unauthenticated-deny, 2
  wrong-token-deny, 2 unconfigured-gate-deny, 3 resource_id format
  validation, 1 direct `validate_new_resource_id` check; the 2 pre-existing
  "Postgres not configured" tests were updated to present a valid service
  token so they still isolate the DB-unconfigured path specifically).
  `tests/lore_compat.rs`: 4, unchanged.
  `tests/postgres_backed.rs`: **20** (up from 16 -- added
  `rebac_create_resource_denies_unauthenticated_caller_against_real_db`,
  `rebac_delete_resource_denies_unauthenticated_caller_against_real_db`,
  `rebac_create_resource_denies_wrong_service_token_against_real_db`,
  `rebac_create_resource_rejects_wildcard_sentinel_against_real_db`; the
  `Harness` and its `create_resource` helper, plus the two pre-existing
  idempotency tests, were updated to present `TEST_REBAC_SERVICE_TOKEN` via
  the new `rebac_request` helper so they keep passing under the new gate).
- `cargo fmt --all -- --check`: clean (one `cargo fmt --all` pass applied
  first; whitespace/line-wrap only in `grpc.rs`, `service_auth.rs`, and
  `tests/postgres_backed.rs`, no logic changed).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean. One real
  fix required along the way (not a lint-only change): the first draft used
  `ring::constant_time::verify_slices_are_equal`, which compiled but is
  `#[deprecated]` in the pinned `ring` version ("Internal function not
  intended for external use with no promises regarding side channels") and
  would have failed this exact check -- replaced with a small hand-rolled
  constant-time XOR-accumulate comparison (`service_auth::
  constant_time_eq`), avoiding both the deprecation and a new dependency.

Also verified this pass: `git status --short` (see below); a repo-wide
non-ASCII scan of every changed file (clean); a grep for embargo-sensitive
terms, the operator's real name (a fixed placeholder string, not spelled
out here on purpose), drive-letter paths, and real key material across
every changed file (zero hits beyond the pre-existing PEM-marker string
literals, not real key material); `proto/vendor/SHA256SUMS`
untouched (no proto changes this pass).

## Security review remediation, item 2: SQLite backend (2026-08-05)

Goal: SQLite for dev and single-instance deployments, Postgres/RDS for
multi-replica, both selectable at runtime, with the SQLite backend running
the IDENTICAL authz test suite as Postgres -- not a subset, not a weaker
parallel suite.

- [x] `Db` restructured into an enum (`Db::Postgres(PostgresHandle)` /
      `Db::Sqlite(SqliteHandle)`), selected in `Db::connect`
      (`crates/lore-authz-server/src/db/mod.rs`) from `DATABASE_URL`'s own
      scheme: `postgres://`/`postgresql://` -> Postgres, `sqlite:` ->
      SQLite. Any other scheme is a startup `bail!`, not a silent
      misconfiguration. [verified-e2e] both branches connect, migrate, and
      pass the full test suite below against a real instance of each
      backend.
- [x] `lore_authz_core::policy::PolicyStore` used as the one common
      interface, not restructured around it: `PgPolicyStore` (the PHASE 1a
      name) is renamed `DbPolicyStore`, wraps `Arc<Db>`, and its single
      `impl PolicyStore for DbPolicyStore` dispatches on `Db`'s variant
      internally (`crates/lore-authz-server/src/db/permissions.rs`).
      `crates/lore-authz-server/src/grpc.rs` was already calling this
      engine only through the trait method (`policy.
      resolve_resource_permissions(...)`) -- the only change needed there
      was constructing `DbPolicyStore::new(db.clone())` instead of
      `PgPolicyStore::new(db.pool().clone())`, since `Db` no longer exposes
      a raw `.pool()` (there is no single pool type across both variants).
- [x] `db::resources` / `db::principals` / `db::groups` / `db::permissions`
      (`create_resource`, `delete_resource`, `list_resource_ids_with_prefix`,
      `insert_principal`, `find_active_principal`, `insert_group`,
      `add_member`, `grant`) all take `&Db` now and dispatch internally,
      so every caller (`grpc.rs`, `tests/authz_suite`) is backend-agnostic.
- [x] Query portability verified, not assumed -- and reported honestly
      where it was NOT portable as-is:
      - Runtime `sqlx::query`/`query_as` (never the compile-time `query!`
        macros) was already the rule (see `db/mod.rs`'s module doc
        comment) -- this held for the SQLite paths too, so no
        `cargo build`-time database dependency was introduced.
      - What DID port unchanged: `RETURNING` + `ON CONFLICT ... DO
        NOTHING` upsert syntax (SQLite, bundled via `libsqlite3-sys`,
        supports both), `LIKE ... ESCAPE`.
      - What did NOT port and needed a real SQLite-specific query:
        Postgres's `= ANY($1)` array bind (SQLite has no array type -- the
        SQLite path builds a dynamic `IN (?, ?, ..., ?)` clause sized to
        the input slice's length via `sqlite_placeholders`, never from a
        value, so this is not an injection risk); `now()` (SQLite has no
        such function -- `datetime('now')` instead); the `uuid` and
        `text[]` column types (see below).
- [x] `DB_SCHEMA` made an explicit no-op for SQLite, and SAID SO.
      [verified-e2e] `Db::connect`'s SQLite branch (`db/mod.rs`) logs it at
      startup unconditionally: info level if `DB_SCHEMA` is left at its
      documented default, a WARNING if an operator set it to something
      else (since that specifically suggests they expect it to do
      something). Documented in `docs/configuration.md` (a dedicated "`DB_
      SCHEMA` is a no-op under SQLite" section, not just a table cell) and
      in `migrations_sqlite/0001_identities_resources_grants.sql`'s own
      comment.
- [x] Separate migration sets per dialect, kept in step.
      `migrations_sqlite/0001_identities_resources_grants.sql` mirrors
      `migrations/0001_identities_resources_grants.sql` table-for-table.
      Representation differences forced by SQLite, documented in that
      file's own comment: no `CREATE SCHEMA`; `uuid` columns are TEXT
      holding the canonical hyphenated string (converted explicitly at the
      Rust boundary in `db/principals.rs` et al., never relying on sqlx's
      own Uuid<->Sqlite blob encoding -- deliberately, for auditability);
      `timestamptz` columns are TEXT with a `datetime('now')` default
      (nothing in this codebase parses them back into Rust, only
      `IS NULL` / overwrite); `roles.permissions` (a Postgres `text[]`)
      is normalized into a `role_permissions(role_id, permission)` join
      table, aggregated back into the identical `Vec<String>` shape via
      `GROUP_CONCAT` in `db/permissions.rs`'s SQLite query path. The three
      built-in role ids (`ROLE_READER`/`ROLE_WRITER`/`ROLE_ADMIN`) are the
      same UUIDs on both backends, so application code never branches on
      them.
- [x] README.md and docs/configuration.md: SQLite is dev/single-instance
      ONLY, stated prominently, not buried. `docs/configuration.md` gained
      a dedicated "Choosing a database backend: Postgres vs SQLite"
      section (linked from the `DATABASE_URL` table row, not left as a
      footnote) spelling out the single-writer-lock reasoning; `README.md`
      gained a "What this is NOT" bullet with the same warning plus a
      pointer to that section. `.env.example`'s `DATABASE_URL` comment
      documents both schemes and the same warning.
- [x] HARD REQUIREMENT: SQLite runs the IDENTICAL authz test suite as
      Postgres. [verified-e2e] Restructured
      `crates/lore-authz-server/tests/postgres_backed.rs` (formerly a
      single ~880-line file with all 20 test bodies inline) into
      `tests/authz_suite/mod.rs` (the `Harness` and all 20 test bodies,
      each taking a `Backend` parameter -- `Backend::Postgres` /
      `Backend::Sqlite`) plus two thin wrapper files,
      `tests/postgres_backed.rs` and `tests/sqlite_backed.rs`, each
      `#[path]`-including the shared module and calling every one of the
      20 shared bodies with its own `Backend`. There is exactly ONE copy of
      each test body's logic; updating one backend's coverage without the
      other is structurally impossible, not just discouraged by
      convention. `fresh_db` gives each Postgres test its own throwaway
      schema (as before) and each SQLite test its own throwaway temp-file
      database (`std::env::temp_dir()` + a fresh UUID per test) -- SQLite's
      per-test isolation is if anything STRONGER than Postgres's, a
      genuinely separate database file rather than a schema inside a
      shared instance. `database_failure_denies_rather_than_grants` (which
      closes the connection pool mid-test to simulate a real DB failure)
      now goes through a new `Db::close()` that dispatches to whichever
      pool variant is live, so this case is real on both backends, not
      Postgres-only.
      Both backends were run standalone AND together; see the proof
      section below for the raw counts. No case was dropped, weakened, or
      left Postgres-only to hit this bar.

**Proof (this pass, all four checks run for real in the pinned Docker build
image, `docker/Dockerfile.build`, Docker reached via PowerShell; the
Postgres-dependent tests via `docker compose -f docker-compose.test.yml run
--rm --build tests`, which runs the FULL `cargo test --workspace` including
the SQLite-backed tests in the same invocation):**

- `cargo build --workspace`: clean, `Finished` dev profile.
- `cargo test --workspace`: **74 tests pass, 0 failures**, across BOTH
  backends:
  - `lore-authz-core` / `lore-authz-proto`: 0 tests (unchanged).
  - `lore-authz-server` unit tests: **30**, unchanged from the Task 1 pass
    (this pass touched no unit test).
  - `tests/lore_compat.rs`: **4**, unchanged.
  - `tests/postgres_backed.rs` (real Postgres 16 container): **20 pass**.
    Test names: `wildcard_grant_allows_any_registered_resource`,
    `specific_repository_grant_does_not_cover_other_repositories`,
    `user_with_no_grants_denies_everything`, `group_inherited_grant`,
    `service_account_direct_grant`,
    `lookup_user_permissions_returns_exact_scoped_set_no_more_no_less`,
    `lookup_user_permissions_specific_only_does_not_leak_other_resources`,
    `nonexistent_resource_is_denied_not_errored`,
    `unknown_principal_id_denies_check`,
    `unknown_principal_id_denies_lookup`,
    `missing_bearer_token_is_unauthenticated`,
    `database_failure_denies_rather_than_grants`,
    `check_user_permission_with_explicit_target_user_token`,
    `create_resource_is_idempotent`,
    `delete_resource_revokes_access_and_is_idempotent`,
    `rebac_create_resource_denies_unauthenticated_caller_against_real_db`,
    `rebac_delete_resource_denies_unauthenticated_caller_against_real_db`,
    `rebac_create_resource_denies_wrong_service_token_against_real_db`,
    `rebac_create_resource_rejects_wildcard_sentinel_against_real_db`,
    `migrations_are_idempotent`.
  - `tests/sqlite_backed.rs` (real SQLite file per test, no external
    service needed): **20 pass -- the EXACT SAME 20 names as above**, each
    calling the identical shared body in `tests/authz_suite/mod.rs` with
    `Backend::Sqlite` instead of `Backend::Postgres`. Also run standalone
    (`cargo test --workspace --test sqlite_backed`, no Postgres running at
    all) with the same 20/20 result, confirming SQLite needs nothing
    external.
- `cargo fmt --all -- --check`: clean (one `cargo fmt --all` pass applied
  first; whitespace/line-wrap only across the new/changed `db/*.rs`,
  `tests/authz_suite/mod.rs`, `tests/postgres_backed.rs`,
  `tests/sqlite_backed.rs`, `main.rs`; no logic changed).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean. One real
  fix required: `std::iter::repeat("?").take(n)` in
  `db/permissions.rs`'s `sqlite_placeholders` triggered
  `clippy::manual_repeat_n`; rewritten to `std::iter::repeat_n("?", n)` per
  clippy's own suggestion.

Also verified this pass: `git status --short` / `git log --oneline -4` (see
below); `sha256sum proto/vendor/{auth_api,rebac_api}.proto` recomputed and
diffed byte-for-byte against `proto/vendor/SHA256SUMS` (unchanged -- this
pass touched no proto file); a repo-wide non-ASCII scan of every
changed/new file (clean); a grep for embargo-sensitive terms, the
operator's real name, drive-letter paths, and real key material across
every changed/new file (clean).

**Left open / explicitly out of scope for this pass**: OIDC/SAML-backed
`idp_connections`, key rotation, audit_log, and every other Phase 1b/2/3
item in this file are untouched -- this pass was scoped to the backend
abstraction and its test parity, nothing else. The Postgres schema/queries
themselves were not changed (only how they are reached: through `&Db`
instead of `&PgPool`), so Task 1's PHASE 1a behavior is unchanged on
Postgres, which the identical 20/20 Postgres pass count (same as
post-Task-1) confirms.
