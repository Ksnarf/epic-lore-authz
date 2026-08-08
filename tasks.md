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

## PHASE 1b, part 1 - auth session store, GetAuthSession, token exchange (2026-08-05)

- [x] `auth_sessions` table and storage layer, both backends.
      [verified-e2e] `crates/lore-authz-server/migrations/
      0002_auth_sessions.sql` + `migrations_sqlite/0002_auth_sessions.sql`
      (kept in step; the SQLite file documents each forced difference), and
      `crates/lore-authz-server/src/db/sessions.rs`. Sessions live in the
      DATABASE, not process memory, because the three legs of one login (CLI
      start, browser login + IdP callback, CLI poll) can each land on a
      different replica behind a load balancer -- an in-memory map would
      fail intermittently rather than loudly. Timestamps are epoch
      MILLISECONDS as plain integers on both backends, so the expiry logic
      has one code path, not two.
      Per-column hashed-vs-raw decision, documented in the migration itself:
      `session_code_hash` / `login_code_hash` / `client_state_hash` are
      SHA-256 fingerprints (they are only ever compared, so a database read
      yields no usable polling credential); `oidc_state` / `oidc_nonce` /
      `pkce_verifier` are raw because the login leg must REPRODUCE them (two
      go into the authorization-request URL, one is sent to the IdP's token
      endpoint) and a hash cannot do that.
- [x] Session codes cryptographically random, single-use, and expiring.
      [verified-e2e] `crates/lore-authz-server/src/secret.rs`:
      `random_url_safe_token` is 32 bytes from `ring`'s `SystemRandom`
      rendered as 43 base64url chars, and FAILS rather than degrading if the
      system CSPRNG is unavailable. Single-use is enforced by the DATABASE,
      not by a Rust check that could be raced: `db::sessions::consume` is a
      conditional `UPDATE ... WHERE status = 'authenticated' AND
      expires_at_ms > ?` and a token is minted only when it reports
      `rows_affected == 1`. Expiry is in the SQL of every state-changing
      statement, not only in Rust.
      TWO separate secrets, not one: the `session_code` the CLI polls with
      never appears in the browser login URL (which carries its own
      `login_code`), so a leaked login URL does not let its holder collect
      the resulting token. Asserted by
      `poll_returns_an_authn_token_once_the_browser_leg_completes`.
- [x] `GetAuthSession` (real logic). [verified-e2e]
      `crates/lore-authz-server/src/login.rs`'s `poll_session`, wired in
      `grpc.rs`. Returns the AuthN token exactly once, on the first poll
      after the browser leg completes.
      NO POLLING ORACLE: unknown session_code, empty session_code, expired
      session, mismatched `client_state`, still-pending session, already
      consumed session, and a session whose principal has since been
      deprovisioned ALL return the identical `Ok(user_token: None)` ("keep
      polling") response, and all of the first four cost exactly one
      database round trip. The single exception is a real database failure,
      which returns `Err` rather than inviting 29 more pointless polls.
      Honest limit stated in the module doc comment: this equalizes the
      RESPONSE and the round-trip count, it does not claim constant-time
      behaviour against a determined timing attacker (the code is 256 bits
      of CSPRNG entropy, so there is nothing useful to narrow down).
      `client_state` is compared as a constant-time hash comparison, never
      in plaintext.
- [x] `ExchangeUserTokenForMultiresourceToken` (real logic). [verified-e2e]
      `grpc.rs`. Verifies the caller's AuthN bearer token
      (`crate::caller`), resolves the effective grants through the SAME
      `DbPolicyStore` engine `CheckUserPermission`/`LookupUserPermissions`
      use (so a wildcard grant is expanded to concrete ids, never emitted as
      the literal `"urc-*"`), and mints the AuthZ token.
      **Settles `docs/open-questions.md` Q13** (`idp` at exchange time): it
      is recovered from the new `principals.idp` column, NOT from the
      caller's AuthN token, which has no such claim. A missing `idp` fails
      SILENTLY at lore-server (the token decodes as the AuthN shape and
      `resources` drops to `None`), so `LoginSettings::default_idp` /
      `TOKEN_IDP` guarantees a non-empty fallback for principals with none,
      and `Config::from_env` refuses to start if `TOKEN_IDP` is empty.
      A caller entitled to nothing gets a well-formed token whose
      `resources` is empty -- never an error, never someone else's access.
      **Security review addition**: an AuthZ-shaped token presented here
      (instead of an AuthN token) is now refused outright
      (`Status::invalid_argument`), rather than silently accepted for
      renewal -- see `docs/protocol-notes.md` #8a and
      `caller::is_authz_shaped_token`. Confirmed not privilege escalation
      (resources are still recomputed fresh and a suspended principal is
      still denied); the concern was unbounded renewal, which is now closed.
      [verified-e2e]
      `exchange_denies_an_authz_shaped_token_presented_for_renewal`
      (both backends).
- [x] 13 new tests, run against BOTH backends (26 test executions), all
      passing. [verified-e2e] Added to the SHARED `tests/authz_suite/mod.rs`
      so Postgres and SQLite cannot drift: `poll_returns_an_authn_token_
      once_the_browser_leg_completes`, `poll_is_single_use_and_never_
      reissues`, `poll_with_an_unknown_session_code_is_indistinguishable_
      from_pending`, `poll_with_a_mismatched_client_state_never_issues_a_
      token`, `expired_sessions_are_denied_at_both_transitions`,
      `poll_denies_when_the_session_principal_is_not_active`,
      `starting_a_session_without_a_public_base_url_fails_closed`,
      `starting_a_session_reaps_expired_ones`,
      `exchange_mints_an_authz_token_with_resources_idp_and_env`,
      `exchange_falls_back_to_the_configured_idp_when_the_principal_has_
      none`, `exchange_omits_resources_the_caller_has_no_grant_for`,
      `exchange_for_a_caller_with_no_grants_yields_an_empty_resources_
      claim`, `exchange_denies_every_unauthenticated_caller`. Plus 4 new
      `grpc::tests` unit cases for the DB-unconfigured fail-closed paths.
      The token assertions decode with real SIGNATURE + issuer + audience
      verification, not an insecure decode, and assert `UserToken.expires_at
      == exp * 1000` (proving the two units are handled as two units, per
      `docs/open-questions.md` Q1).
- [x] Constant-time comparison de-duplicated into
      `crates/lore-authz-server/src/secret.rs` and shared by
      `service_auth.rs` and `login.rs`. [code-says] a security primitive
      with two copies is one that gets fixed once.
- [~] Config surface for the above: `TOKEN_IDP`, `AUTH_SESSION_TTL_SECS`,
      `PUBLIC_BASE_URL`. Documented in `docs/configuration.md` (including a
      dedicated section on the CLI's 150-second login deadline).
      **`.env.example` NOT updated**: the tooling this pass ran under blocks
      all writes to `.env*` paths, including this committed
      placeholders-only template. Nothing was worked around. Whoever picks
      this up next should add the three variables above to `.env.example`
      from the `docs/configuration.md` table.

## PHASE 1b, part 2 - OIDC login (StartAuthSession + the browser leg) (2026-08-05)

- [x] `StartAuthSession` (real logic). [verified-e2e] `grpc.rs` +
      `crates/lore-authz-server/src/oidc_login.rs`'s `start`. Mints this
      session's OIDC `state`, `nonce` and PKCE verifier from the same CSPRNG
      as the session codes (never derived from anything the client sent) and
      returns `{session_code, login_url}`.
      FAILS CLOSED with no identity provider configured: without one nothing
      could ever authenticate the session, so issuing a code would only
      produce a login that times out after 150 seconds with no explanation.
      Proven by `grpc::tests::start_auth_session_without_a_configured_
      provider_fails_closed` and, against a real database,
      `start_auth_session_without_a_provider_denies_against_real_db` (both
      backends).
- [x] Generic OIDC relying party, provider-agnostic by construction.
      [verified-e2e] `crates/lore-authz-server/src/oidc.rs`. Every endpoint,
      the JWKS location, AND the token-endpoint client-authentication method
      come from the provider's own `/.well-known/openid-configuration`;
      there is no per-vendor branch anywhere in the file. Discovery and JWKS
      are cached (1h / 5m) with a single forced JWKS refetch on a `kid` miss
      -- one retry, not a loop, so a `kid` an attacker controls cannot be
      turned into a request amplifier pointed at the provider.
      The discovery document's own `issuer` must equal the configured one
      (OIDC Discovery section 4.3); a mismatch is refused, because accepting
      it turns a hijacked discovery URL into full provider substitution.
- [x] Authorization-code flow with PKCE, `state` and `nonce`.
      [verified-e2e] `state` is the session lookup key (an unrecognized
      value matches no session, so the callback fails closed and the code is
      never presented to the token endpoint); `nonce` is compared in
      constant time and a token with NO nonce is rejected rather than
      treated as "nothing to compare"; PKCE is S256 with the verifier never
      leaving this service. `pkce_challenge_matches_the_rfc_7636_worked_
      example` pins the challenge derivation to RFC 7636 appendix B rather
      than to this implementation's own output.
- [x] ID token verification: signature, `iss`, `aud`, `exp`, `nonce`.
      [verified-e2e] Signature is checked against the key the provider
      publishes under the token's own `kid`, with the ALGORITHM pinned to
      what the JWKS declares and restricted to an ASYMMETRIC allowlist.
      Accepting an `HS*` algorithm here is the classic key-confusion attack
      (forge a token by using the provider's published PUBLIC key as an HMAC
      secret) -- refused explicitly, with unit tests
      (`symmetric_algorithms_are_refused_even_if_the_key_declares_one`,
      `a_header_algorithm_that_disagrees_with_the_key_is_refused`).
- [x] JIT user provisioning. [verified-e2e]
      `oidc_login::resolve_principal`. Identity key is the provider's `sub`
      (`principals.subject`, UNIQUE on `(source, subject)`), NEVER the email
      -- an email can be reassigned to a different human. A JIT-provisioned
      principal holds NO role bindings, so it authenticates and receives an
      AuthZ token whose `resources` is empty: provisioning creates an
      IDENTITY, never an AUTHORIZATION, which is what makes it safe to
      default on (`OIDC_JIT_PROVISIONING`, default true).
      Deliberate omissions, not oversights: a login never changes
      `principals.status`, so a suspended or deprovisioned principal logging
      in again is DENIED rather than silently reactivated; and group-claim
      mapping is NOT implemented (still open under Phase 1 below) -- emitting
      a half-mapped `groups` claim would be worse than emitting none.
- [x] Browser routes. [verified-e2e] `http.rs`: `GET /login/{login_code}`
      redirects to the provider, `GET /oidc/callback` completes the session,
      `GET /login/done` is the "you may close this tab" page. Every failure
      renders the SAME page with the same status (unknown login code,
      expired session, replayed callback, unrecognized `state`, validation
      failure), so neither route can be used to probe which sessions are
      live. The one distinguished case is `ProviderUnavailable`, which is an
      OPERATOR problem and reveals nothing about any session. Pages are
      fully self-contained HTML with `referrer: no-referrer` and no external
      asset of any kind.
- [x] Real IdP in a container, wired for a stranger cloning the repo.
      [verified-e2e] `docker/dex/config.yaml` + a `dex` service in
      `docker-compose.test.yml`. `docker compose -f docker-compose.test.yml
      run --rm --build tests` now brings up a real Postgres AND a real OIDC
      provider and runs everything. Documented in `README.md`'s Testing
      section.
- [x] CI. [code-says] -- not run (this repo is commit-only per the task
      constraints, never pushed). `.github/workflows/ci.yml`'s
      `build-and-test` job starts the same Dex image with the same committed
      config via `docker run` (a GitHub Actions `services:` container cannot
      mount a config file) and adds `127.0.0.1 dex` to `/etc/hosts`. That
      hosts line is load-bearing: Dex bakes its issuer into every discovery
      document and every ID token and does NOT expand environment variables
      in its config (verified for real against v2.44.0 -- it logged the
      literal `${DEX_ISSUER}`), so ONE committed config has to work for both
      compose (service-name DNS) and CI (published port on loopback).
- [x] 16 OIDC tests against a REAL identity provider, all passing.
      [verified-e2e] `crates/lore-authz-server/tests/oidc_flow.rs`. Storage
      cases run against BOTH backends.
      Maximum fidelity: `full_login_flow_end_to_end_through_the_real_http_
      server_{postgres,sqlite}` binds this service's REAL axum router to a
      real socket and walks the entire flow with a redirect-following HTTP
      client exactly as a browser would -- our `/login` route, the
      provider's authorize endpoint, the provider's redirect back to our
      `/oidc/callback`, the success page -- then polls for the AuthN token
      and exchanges it for an AuthZ token, asserting `idp` names the real
      issuer, `env` is present, and `resources` is EMPTY for a
      freshly-provisioned principal.
      Attack paths, each driven with REAL provider responses:
      `callback_with_an_unknown_state_is_rejected_*` (a genuine
      authorization code obtained under a `state` this service never
      issued -- the login-CSRF shape),
      `callback_with_a_mismatched_nonce_is_rejected_*` (the session's own
      `state` and PKCE verifier, so the exchange SUCCEEDS and only the
      replay check can catch it),
      `a_replayed_callback_cannot_complete_a_session_twice_*`,
      `jit_disabled_denies_an_unknown_identity_*`,
      `a_second_login_reuses_the_same_principal_*`.
      Token-level, against a REAL provider-signed RS256 ID token:
      `a_real_provider_signed_id_token_is_accepted` (the positive control --
      without it a verifier that rejected everything would pass the rest),
      `an_id_token_with_a_tampered_signature_is_rejected` (one byte of a real
      signature flipped),
      `an_id_token_signed_by_a_key_the_provider_does_not_publish_is_rejected`,
      `a_real_id_token_with_the_wrong_nonce_is_rejected`.
- [~] Test coverage gaps, stated rather than papered over:
      - **Unconfigured-provider denial is now `[verified-e2e]` through the
        HTTP routes too**, not just at the RPC and unit level. Previously
        proven at the RPC/unit level only
        (`start_auth_session_without_a_provider_denies_against_real_db`,
        `grpc::tests::start_auth_session_without_a_configured_provider_
        fails_closed`, `oidc::tests::a_partially_configured_provider_is_
        refused_at_construction`); the browser routes' `login_not_
        configured_page` path is now actually executed by
        `http::tests::login_page_denies_when_not_configured` and
        `http::tests::oidc_callback_denies_when_not_configured`.
      - **The issuer-mismatch refusal in discovery is now `[verified-e2e]`**:
        the earlier claim here (that it would need a second, deliberately-
        misconfigured *provider*) was wrong -- it only needs a discovery
        *document* whose issuer disagrees with the URL it was fetched from,
        which a trivial in-process mock HTTP server produces with no real
        IdP involved. See `oidc::tests::
        a_discovery_document_whose_issuer_disagrees_with_its_url_is_refused`.
      - **The `ProviderUnavailable` pages are now `[verified-e2e]`**: rather
        than a second real IdP (disproportionate for what is fundamentally
        "the HTTP call to the provider fails"), both browser routes are
        pointed at `http://127.0.0.1:0` -- a port nothing can ever accept a
        connection on -- which drives a REAL connection failure through
        `discovery()`/`exchange_code()`, not a mocked outcome. See
        `http::tests::login_page_renders_provider_unavailable_when_the_idp_
        is_unreachable` and `http::tests::oidc_callback_renders_provider_
        unavailable_when_the_idp_is_unreachable`. Needs no Docker/Postgres/
        Dex: these four new `http::tests` run against a throwaway SQLite
        file, same as any other unit test.

**Left open / explicitly out of scope for this pass**: SAML and SCIM
(untouched by instruction), group-claim mapping, key rotation, `audit_log`,
`GetUserInfo`/`GetUserId`/`GetProviderUserId`,
`ExchangeExternalTokenForUserToken`/`ExchangeAPIKeyForUserToken`, and the
Phase 0 exit gate (a real `lore auth login` against a real `lore-server`),
which still needs TLS on the client-facing endpoint and a running
lore-server -- see `docs/protocol-notes.md` #9 for what remains unproven
client-side.

**PROOF for the whole of PHASE 1b (all four checks run for real in the
pinned build image `docker/Dockerfile.build`; the Postgres- and IdP-backed
tests via `docker compose -f docker-compose.test.yml run --rm --build
tests`, which brings up a real `postgres:16-alpine` AND a real
`ghcr.io/dexidp/dex:v2.44.0` and runs the FULL `cargo test --workspace`):**

- `cargo build --workspace`: clean, `Finished dev profile`, exit 0.
- `cargo fmt --all -- --check`: clean, exit 0 (one `cargo fmt --all` pass
  applied first; whitespace/line-wrap only).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean, exit 0.
  One real fix along the way: `parts.iter().any(|s| *s == "openid")` in
  `oidc.rs`'s `normalize_scopes` tripped `clippy::search_is_some`'s
  `contains` lint; rewritten to `parts.contains(&"openid")`.
- `cargo test --workspace`: **139 passed, 0 failed** (was 74 at the start of
  this session's work), compose exit 0:
  - `lore-authz-core` / `lore-authz-proto`: 0 tests (unchanged).
  - `lore-authz-server` unit tests: **51** (was 30). New: 3 in `signing`
    (the RFC 7638 `kid`), 3 in `secret`, 2 in `config`, 8 in `oidc`, 5 in
    `grpc`.
  - `tests/lore_compat.rs`: **4**, unchanged.
  - `tests/oidc_flow.rs`: **16**, against a REAL OIDC provider container.
  - `tests/postgres_backed.rs`: **34** (was 20), real Postgres 16.
  - `tests/sqlite_backed.rs`: **34** (was 20) -- the EXACT SAME 34 names,
    same shared bodies, `Backend::Sqlite`.

Also verified this pass, raw commands not just claimed: `sha256sum
proto/vendor/{auth_api,rebac_api}.proto` recomputed and compared
byte-for-byte against `proto/vendor/SHA256SUMS` (unchanged -- no proto file
was touched); `git -C <epic-lore fork> status --short` empty (the fork is
untouched, read-only as required); a repo-wide non-ASCII scan of every
tracked AND untracked-but-new file (zero hits); greps across the same file
set for embargo-sensitive terms, the operator's real name, drive-letter /
host-absolute filesystem paths, and real key material -- zero hits, except
the pre-existing `-----BEGIN PRIVATE KEY-----` string literals `signing.rs`
uses to DETECT PEM input, which are markers, not key material.

## Phase 1 - Real IdP, persistence, service accounts

- [ ] Postgres, sqlx migrations, schema-qualified DDL, `DB_SCHEMA` config
      honored (never `public`, never a dedicated database, never
      superuser).
- [~] OIDC authorization code + PKCE against Okta, Entra ID, Auth0,
      Keycloak.
      [verified-e2e] against a real containerized OIDC provider (Dex), and
      built provider-agnostically -- every endpoint comes from the
      provider's own discovery document, with no per-vendor branch anywhere
      (see PHASE 1b part 2 above). Still `[~]` and not `[x]` for an honest
      reason: NO named vendor in this line has actually been run against.
      There is no Okta/Entra/Auth0 tenant available to this project yet, so
      "works against Okta" remains a claim about protocol conformance, not
      an observation. Whoever gets a tenant should run
      `tests/oidc_flow.rs` against it by changing `TEST_OIDC_*` -- no test
      code should need to change, and if it does, that is the finding.
- [~] JIT user provisioning, group claim to `groups` mapping.
      JIT provisioning: [verified-e2e], see PHASE 1b part 2 above
      (`OIDC_JIT_PROVISIONING`, identity keyed on the provider's `sub`,
      provisioned principals hold no grants).
      Group claim mapping: [not-built], deliberately. The exchange RPC emits
      `groups: None` rather than a partially-mapped list.
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
- [~] Admin REST API `/admin/v1` for users, groups, roles, bindings, api
      keys, idp connections.
      [verified-e2e] for users (principals), groups + membership, resources,
      roles (list only) and role bindings -- see the "ADMIN SURFACE" section
      below for the full writeup, the proof, and the explicit list of what
      it does NOT do. Still `[~]`, not `[x]`: **api keys and idp connections
      are not covered**, because neither exists yet in this product (there
      is no `api_keys` table and no `idp_connections` table -- IdPs are
      configured through `OIDC_*` env vars, and
      `ExchangeAPIKeyForUserToken` is still `Status::unimplemented`).
      Exposing CRUD for tables nothing reads would be worse than not
      exposing it.
- [x] Minimal admin web UI (optional, can slip to a later phase).
      [verified-e2e] `/admin/ui`, server-rendered from
      `crates/lore-authz-server/src/admin/panel.rs`. See below.

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
      [correction, 2026-08-06]: the line above conflated the gRPC channel's
      own interceptors (correlation id only, no bearer token, no client TLS
      identity -- true of the CHANNEL) with what the call sites send on it.
      `repository_create_auth_resource` / `repository_delete_auth_resource`
      build their requests through `create_request_with_authorization`, so a
      real bearer token -- the END USER's own, forwarded verbatim -- DOES
      arrive on this hop. The gap this gate closes is the credential's KIND
      (a user token, not a service one), not its absence. See
      `crates/lore-authz-server/src/service_auth.rs` and
      `docs/open-questions.md` Q6 for the corrected writeup. The decision
      itself (shared secret, not a JWT check) is unaffected.
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

## ADMIN SURFACE - provisioning without a database client (2026-08-08)

The one structural hole in an otherwise working product: every RPC READ
`principals` / `groups` / `group_members` / `role_bindings`, and nothing
could WRITE them. `RebacApi::CreateResource` populated `resources` and the
OIDC login leg could JIT-provision a principal, but a JIT-provisioned
principal holds no grants -- so the only way to make any of this useful was
to insert rows by hand with `psql` or the `sqlite3` CLI. This pass closes
that. Additive only: no existing RPC, no OIDC/session logic, and no existing
claim/JWKS behaviour was changed.

- [x] `ADMIN_API_TOKEN` gate on the ENTIRE `/admin/**` surface, failing
      closed. [verified-e2e]
      `crates/lore-authz-server/src/admin/auth.rs`, built on the primitives
      that were already here rather than new ones: `crate::secret::
      constant_time_eq` and `crate::secret::strip_bearer`, the same pair
      `crate::service_auth` uses for `REBAC_SERVICE_TOKEN`. Applied as an
      axum middleware with `Router::layer` (NOT `route_layer`) so it also
      covers the admin router's own 404 fallback -- an unauthenticated
      caller cannot map which admin paths exist by probing 404 vs 401.
      FAIL CLOSED, no bypass: unset token, empty token, missing header,
      empty header and wrong value ALL deny with an identical `401` (same
      body, same `www-authenticate: Bearer`), and there is deliberately no
      dev-mode flag and no way to enable the routes without a token. The
      distinction an OPERATOR needs (is the surface configured?) is in the
      startup log in `main.rs`, not in a response an attacker can read.
      The token is never logged, never echoed, and never rendered into the
      panel. Header only -- never a URL, never a query parameter, never a
      cookie.
- [x] Secrets kept out of any settings dump. [verified-e2e]
      `Config` no longer `#[derive(Debug)]`: `crates/lore-authz-server/src/
      config.rs` has a hand-written `Debug` that renders `admin_api_token`,
      `rebac_service_token` and `oidc_client_secret` as
      `Some("<redacted>")` / `None`, and `database_url` (which carries a
      password) as `"<redacted>"`. Nothing in this crate `{:?}`-prints a
      `Config` today; this exists so that the day something does, it cannot
      leak. Guarded by `config::tests::
      config_debug_never_reveals_a_secret_value`, which builds a config with
      a sentinel in every secret field and asserts the sentinel does not
      appear.
- [x] JSON provisioning API under `/admin/v1`. [verified-e2e]
      `crates/lore-authz-server/src/admin/api.rs`.
      Principals: `GET|POST /admin/v1/principals`,
      `GET /admin/v1/principals/{id}`,
      `POST /admin/v1/principals/{id}/status` (`active`/`suspended`).
      Create accepts `external_id` / `source` / `subject` so an operator can
      PRE-PROVISION the identity their IdP or a later SCIM sync will assert,
      rather than having SCIM create a duplicate.
      Groups: `GET|POST /admin/v1/groups`,
      `GET|POST /admin/v1/groups/{id}/members`,
      `DELETE /admin/v1/groups/{id}/members/{principal_id}`.
      Resources: `GET|POST /admin/v1/resources`,
      `DELETE /admin/v1/resources/{resource_id}` (soft delete, same
      `db::resources::delete_resource` `RebacApi::DeleteResource` calls).
      Roles: `GET /admin/v1/roles`, list ONLY -- the three advisory roles are
      seeded by both migration sets and there is no role CRUD.
      Grants: `GET|POST /admin/v1/grants`, `DELETE /admin/v1/grants/{id}`,
      supporting both a specific `urc-{id}` pattern and the wildcard
      `urc-*`. `role` accepts a name or a uuid.
      Wire shapes are declared explicitly rather than serializing
      `lore_authz_core::model::Principal`, because that type's `status`
      serializes as `"Active"` while the value this API ACCEPTS and the
      database stores is `"active"` -- an API whose output cannot be fed
      back into its own input is a bug generator. Asserted by a round trip
      in `admin_creates_and_reads_back_every_entity`.
- [x] Server-rendered HTML panel at `/admin/ui`, in the same binary.
      [verified-e2e] `crates/lore-authz-server/src/admin/panel.rs`. Lists
      principals, groups (with members), resources, roles and grants, with
      forms to create each and to grant/revoke, plus per-row
      suspend/activate, remove-member, delete-resource and revoke-grant
      buttons. No SPA, no JavaScript, no node toolchain, no separate build
      step, no external asset of any kind -- `format!`-ed HTML with a small
      inline stylesheet, for the same reason the login pages are
      self-contained. Every interpolated value is HTML-escaped; a principal
      whose display name is a `<script>` tag is created through the real API
      and the rendered page is asserted to carry it escaped, on both
      backends (`the_admin_panel_renders_what_it_manages_and_escapes_
      operator_text`). That matters more here than on a public page: the
      panel is opened by exactly the person holding the admin token.
      Successful form POSTs answer `303` to `/admin/ui?msg=<code>` where the
      code is looked up in a FIXED table (an unknown code renders nothing),
      so nothing typed by anyone is ever reflected out of a query string
      into the page, and a refresh re-runs a GET rather than the create. A
      FAILED POST re-renders in place with the error and the error's own
      status code.
- [x] Reused the existing data layer, extended in the same style.
      [verified-e2e] New functions live beside the ones already there, with
      the same `Db`-variant dispatch and the same SQLite conventions
      (canonical-string uuids, plain `?` placeholders, explicit
      `Uuid::parse_str` at the boundary): `db::principals::
      {insert_admin_principal, list_principals, find_principal,
      set_principal_status}`, `db::groups::{insert_group_with_description,
      list_groups, list_group_members, group_exists, remove_member}`,
      `db::resources::list_resources`, `db::permissions::{create_grant,
      delete_grant, list_grants, list_roles}`.
      Deduplications rather than parallel copies: the existing
      `db::permissions::grant` now delegates to `create_grant`, so there is
      ONE role-binding insert statement in this codebase; the admin surface
      validates a resource id with `grpc::validate_new_resource_id` (made
      `pub`, body unchanged), the exact function `RebacApi::CreateResource`
      uses; and `strip_bearer`, which had two byte-identical private copies
      (`caller.rs`, `service_auth.rs`), moved to `crate::secret` and is now
      shared by all three call sites -- the same reasoning the earlier pass
      applied to `constant_time_eq`.
      `db::resources::list_resource_ids_with_prefix` was deliberately NOT
      given an "include deleted" flag: it is an AUTHORIZATION input, and a
      boolean between an authorization path and the rows it may consider is
      exactly the parameter that gets passed wrong once.
- [x] Validation that prevents SILENTLY WRONG grants, not just malformed
      ones. [verified-e2e] `crates/lore-authz-server/src/admin/ops.rs`, and
      this is the part that earns its tests:
      1. `principal_kind` must agree with the principal's own
         `is_service_account`. `resolve_resource_permissions` derives the
         kind it matches on from the PRINCIPAL ROW, so a binding recorded as
         `user` against a service account matches nothing, ever, while
         looking perfectly correct in a listing.
      2. `resource_pattern` must be the exact literal `urc-*` or a
         well-formed `urc-<id>`. The policy engine treats only the exact
         sentinel as a wildcard, so a plausible `urc-abc*` is not a prefix
         glob -- it is a binding to a resource id that cannot exist.
      3. The principal or group must EXIST.
         `role_bindings.principal_id` is polymorphic and cannot carry a
         foreign key (the migration says so in as many words: "validated at
         the application layer"). This is that layer.
      None of the three can be enforced by a database constraint, which is
      why each is tested against a real database on both backends.
- [x] Creates that change nothing are REPORTED, not swallowed.
      [verified-e2e] A duplicate group name, a resource id already
      registered, and a second principal with the same `(source, subject)`
      all answer `409`; a re-grant answers `200` (with the existing binding's
      id) instead of `201`, so an operator can tell "already there" from
      "created" without diffing a list. An admin API that silently no-ops
      leaves an operator believing they provisioned something they did not.
- [x] 15 new shared test bodies, run against BOTH backends (30 executions),
      all passing. [verified-e2e] Added to the SHARED
      `tests/authz_suite/mod.rs` so Postgres and SQLite cannot drift, with
      one-line wrappers in `tests/postgres_backed.rs` and
      `tests/sqlite_backed.rs`. They drive the REAL axum router bound to a
      REAL ephemeral socket with a REAL HTTP client against a REAL database
      -- no handler is called directly, because the thing most worth proving
      about an admin surface is that its gate is on the wire.
      `admin_denies_every_route_without_a_bearer_token`,
      `admin_denies_every_route_with_a_wrong_bearer_token` (including a
      strict PREFIX of the real token, which a naive `starts_with` would
      accept),
      `admin_denies_every_route_when_no_admin_token_is_configured` (the
      fail-closed case: `None` AND `Some("")` configured, crossed with
      no/right/empty token presented -- 3 x 28 routes x 2 configurations),
      `admin_creates_and_reads_back_every_entity`,
      `a_grant_created_through_the_admin_api_is_honoured_by_check_user_
      permission`,
      `a_wildcard_grant_created_through_the_admin_api_is_expanded_by_lookup_
      user_permissions`,
      `revoking_a_grant_through_the_admin_api_denies_the_next_check`,
      `admin_group_membership_grants_and_revokes_inherited_access`,
      `admin_suspending_a_principal_denies_the_next_check`,
      `admin_deleting_a_resource_denies_the_next_check`,
      `admin_refuses_a_grant_whose_principal_kind_disagrees_with_the_
      principal`,
      `admin_refuses_an_unsupported_resource_pattern_and_an_unknown_
      principal`,
      `admin_reports_duplicates_instead_of_silently_doing_nothing`,
      `the_admin_panel_renders_what_it_manages_and_escapes_operator_text`,
      `admin_forms_create_and_revoke_through_the_same_operations_as_the_api`.
      Plus 17 new unit tests: 9 in `admin::auth`, 4 in `admin::ops`, 2 in
      `admin::panel`, 1 in `config` (the secret-redaction guard) and 1 in
      `secret` (the shared `strip_bearer`).
      **The one that matters most**: everything in
      `a_grant_created_through_the_admin_api_is_honoured_by_check_user_
      permission` is provisioned over HTTP through the admin API, and the
      assertion is made through the real gRPC `CheckUserPermission` and
      `LookupUserPermissions` handlers. A parallel universe -- a second
      table, a second connection, a stale cache -- fails there and nowhere
      else. It also asserts the NEGATIVE first (principal exists, resource
      exists, no grant -> denied), so a check that always allowed could not
      pass it.

**What the admin surface does NOT do** (stated rather than discovered
later):

- **No api-key or IdP-connection management**, despite the Phase 2 task line
  naming both. Neither exists in this product: there is no `api_keys` table,
  `ExchangeAPIKeyForUserToken` is still `Status::unimplemented`, and IdPs are
  configured through `OIDC_*` environment variables, not a table. CRUD over
  tables nothing reads would be theatre.
- **No pagination and no filtering/search.** Every list is capped at 500 rows
  with an explicit `truncated` flag in the JSON and a visible note in the
  panel. Honest, but a deployment with more than 500 principals cannot page
  past the first 500 through this surface.
- **No hard delete** of a principal or a group, and `deprovisioned` cannot be
  SET (only `active`/`suspended`). Suspension is reversible and leaves the
  row; a delete cascading `group_members` and `role_bindings` out of
  existence is not, and nothing in this product distinguishes
  `deprovisioned` from `suspended` yet.
- **No audit log.** Who created which grant, and when, is not recorded
  anywhere -- `audit_log` is still Phase 1/3 and does not exist. For a
  surface that mints authority this is the most significant gap on this
  list.
- **No admin identity.** Everyone who holds `ADMIN_API_TOKEN` is the same
  anonymous caller, with all of it. There is no per-operator credential, no
  scoping (read-only vs write), and no rotation mechanism beyond changing
  the setting and restarting. This is the same trade `REBAC_SERVICE_TOKEN`
  makes, for the same reason (the caller has no `principals` row to resolve
  to), but the blast radius here is larger.
- **No rate limiting or brute-force lockout** on the gate. The token is
  expected to be high-entropy and the path is expected to be restricted at a
  reverse proxy; neither is enforced by this service.
- **The panel needs a header-injecting proxy to be usable in a browser.**
  Every `/admin` route requires the `Authorization` header and there is no
  cookie or login form, deliberately -- adding a second, weaker credential
  path into a surface that can mint authority is not worth saving a line of
  proxy configuration. A worked nginx example is in
  `docs/configuration.md`. Any client that can set a header (curl, a script)
  needs nothing extra.
- **`.env.example` NOT updated** with `ADMIN_API_TOKEN`: the tooling this
  pass ran under blocks all writes to `.env*` paths, including this
  committed placeholders-only template (the same block the PHASE 1b pass
  hit). Nothing was worked around. Whoever picks this up next should add
  `ADMIN_API_TOKEN=CHANGE_ME` with the fail-closed note from
  `docs/configuration.md`'s `ADMIN_API_TOKEN` row.
- **No `lore` CLI or `lore-server` involvement.** This surface was proven
  against this service's own gRPC handlers and its own HTTP router, not
  against a running lore-server. The Phase 0 exit gate is unchanged by this
  work.

**Documentation updated**: `docs/configuration.md` (the `ADMIN_API_TOKEN`
row plus a dedicated section: what the surface is, why the token is a root
credential, the fail-closed rule, a worked reverse-proxy example, `curl`
recipes, and what the surface refuses and why), `docs/data-model.md` (a new
"Who writes these tables" section, since reading them was implemented long
before writing them), `README.md` (a "Provisioning" section naming the admin
surface as the only supported way to create a grant), and this file.

**On `README.md`'s bootstrap procedure**: there is none to retire. The task
that commissioned this work expected `README.md` to document bootstrapping
by direct SQLite inserts; it does not, and never did -- a repo-wide grep for
`INSERT INTO` / `sqlite3` across every `.md` file in the repository finds
exactly one hit, and it is the crate name `libsqlite3-sys` in this file. The hack was real but undocumented (it
lived in operators' shell history, not in the repo), so nothing was deleted.
What CAN now be stated: creating a principal, a group, a membership, a
resource and a grant, and revoking each, all work through the admin API and
are proven end to end against both backends -- so direct SQL is no longer
needed for any provisioning operation this product supports.

**PROOF (all four checks run for real in the pinned build image
`docker/Dockerfile.build`; the Postgres- and IdP-backed tests via `docker
compose -f docker-compose.test.yml run --rm --build tests`, which brings up
a real `postgres:16-alpine` AND a real `ghcr.io/dexidp/dex:v2.44.0` and runs
the FULL `cargo test --workspace`):**

- `cargo build --workspace`: clean, 0 warnings, `Finished dev profile`,
  exit 0.
- `cargo fmt --all -- --check`: clean, exit 0 (one `cargo fmt --all` pass
  applied first; line-wrap only, no logic changed).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean, exit 0.
  One real fix along the way: `verify_admin_caller` originally returned
  `Result<(), ()>`, which trips `clippy::result_unit_err`; it now returns a
  dedicated field-less `Denied` type -- which reads better anyway, since the
  point is that the denial carries no detail.
- `cargo test --workspace`: **197 passed, 0 failed** (was 150 before this
  pass), compose exit 0:
  - `lore-authz-core` / `lore-authz-proto`: 0 tests (unchanged).
  - `lore-authz-server` unit tests: **77** (was 60).
  - `tests/lore_compat.rs`: **4**, unchanged.
  - `tests/oidc_flow.rs`: **16**, unchanged, against a REAL OIDC provider.
  - `tests/postgres_backed.rs`: **50** (was 35), real Postgres 16.
  - `tests/sqlite_backed.rs`: **50** (was 35) -- the EXACT SAME 50 names,
    same shared bodies, `Backend::Sqlite`.

## SECURITY: CSRF on the admin panel, closed by same-origin enforcement (2026-08-08)

**The finding.** `crates/lore-authz-server/src/admin/panel.rs`'s module doc
argued that CSRF does not apply to this surface, because a browser cannot
attach an `Authorization` header to an address-bar navigation. That is true of
the header in isolation and FALSE of the deployment this project's own
`docs/configuration.md` recommends two paragraphs later: an nginx example that
injects the admin bearer into every request from an allowlisted IP range. A
proxy that does that turns the credential into AMBIENT AUTHORITY -- earned by
network position rather than possessed by the caller -- which is precisely the
property that makes cookie-authenticated sites CSRF-able. mTLS is not a fix
either: a client certificate is presented ambiently on a cross-origin
navigation too.

Every `/admin/ui/*` mutation route takes an `axum::Form`, so it accepts
`application/x-www-form-urlencoded` -- one of the three enctypes a `<form>` can
submit, none of which trigger a CORS preflight. **Exploit, plain HTML, no
JavaScript**: an operator whose browser sits on the allowlisted network loads
any hostile page; the page auto-submits a form to `/admin/ui/grants` with
`role=admin&resource_pattern=urc-*&principal_kind=user&principal_id=<the
attacker's own principal>`; the proxy authenticates by source IP and injects
the real token; the attacker now holds `admin` over every repository.

**This was not theoretical, and it was measured rather than argued.** With the
fix's middleware temporarily deleted from the router and nothing else changed,
`a_cross_origin_form_post_cannot_create_an_admin_grant` fails on its FIRST
effect assertion -- `CheckUserPermission` reports a non-empty permission set
for the attacker's principal on `urc-victim-one`. The cross-origin form POST
really does mint the grant, and the authorization path really does honour it.
Raw output in this session's PROOF block below. With the fix the same request
is `403` and no binding exists.

- [x] Same-origin gate on every state-changing admin request. [verified-e2e]
      New `crates/lore-authz-server/src/admin/origin.rs`. On any method that is
      not `GET`/`HEAD`, anywhere under `/admin`:
      1. `Origin` present -> must equal this service's own origin, or DENY.
      2. No `Origin`, `Referer` present -> its scheme+host+port must equal this
         service's own origin, or DENY.
      3. NEITHER header -> DENY under `/admin/ui` (the HTML form routes);
         ALLOW under the rest of `/admin` (the JSON API). See the scoping
         decision below -- this is the one deliberate asymmetry.
      `GET`/`HEAD` are exempt: reading the panel changes nothing.
      Both sides of every comparison go through the SAME normalizer
      (`config::origin_of`, made `pub(crate)`, body unchanged), so
      `https://x.example.com:443`, `https://x.example.com/` and
      `https://X.EXAMPLE.COM` all compare equal to `https://x.example.com`,
      while `https://x.example.com:8443`, `http://x.example.com` and
      `https://x.example.com.hostile.example.com` do not. `Origin: null`
      (sandboxed iframe, some redirect chains) is not a parseable URL and is
      therefore REFUSED, not treated as "no origin declared".
- [x] Scoping decision: strict rule 3 on `/admin/ui` only. [verified-e2e]
      Verified from the code before scoping it, not assumed: every mutating
      `/admin/v1` route takes `axum::Json` (POST) or carries no body on a
      `DELETE` (`admin/api.rs`). A `<form>` cannot send
      `content-type: application/json` and cannot issue a `DELETE`, so neither
      shape is reachable from a cross-origin form. A cross-origin `fetch`
      could set either, but only after a CORS preflight -- and a repo-wide
      grep confirms this workspace mounts NO CORS layer anywhere (no
      `CorsLayer`, no `tower-http` `cors` feature, no `OPTIONS` handler, no
      `access-control-allow-origin` on any response), so the browser refuses
      the real request. Applying rule 3 to `/admin/v1` would therefore have
      cost every documented `curl` recipe and every deployment script (none of
      which send `Origin` or `Referer`) in exchange for closing an attack a
      browser cannot mount. Rules 1 and 2 DO still apply to `/admin/v1`: that
      costs automation nothing, since it declares no origin, and keeps the
      defence in place if a route there ever becomes form-reachable.
- [x] `PUBLIC_BASE_URL` reused, not duplicated. [code-says]
      `crate::http::AppState` gained `public_base_url: Option<Arc<String>>`,
      fed in `main.rs` from the SAME `config.public_base_url` the OIDC login
      flow already uses (which itself falls back to the origin of
      `OIDC_REDIRECT_URL` -- see `Config::from_env`). No second setting, and
      no second derivation, so the two notions of "our origin" cannot drift
      apart.
      **Unset (or empty) -> DENY, never allow**: with nothing to compare
      against, the gate refuses every state-changing request that declares an
      origin (INCLUDING one that would have matched -- unverifiable is not
      verified) and every `/admin/ui` form POST. Header-less JSON automation
      is unaffected, so an unset value costs the panel, not the API. The
      startup warning in `main.rs` now names BOTH consequences (login URL and
      admin panel) instead of only the first.
- [x] Gate ORDER is deliberate and documented. [verified-e2e]
      `.layer()` applies outward, so the LAST call is outermost:
      `auth::require_admin` runs FIRST and `origin::require_same_origin` runs
      inside it. Bearer-first means an unauthenticated caller still sees only
      the existing uniform `401` whatever origin it declares, so this check
      adds no new oracle to an unauthenticated probe -- proven by the
      unchanged `admin_denies_every_route_*` cases, which still expect `401`
      on all 28 routes. Same-origin-second means it still fires for the case
      it exists to stop: a request that DID authenticate, because a proxy
      injected the token for it.
- [x] Denials leak nothing. [verified-e2e] One `403`, one fixed body, for all
      four causes (foreign origin, unparseable origin, no origin declared,
      no `PUBLIC_BASE_URL`). Applied with `Router::layer` like the bearer
      gate, so it covers the admin router's 404 fallback too: a cross-origin
      POST to `/admin/v1/does-not-exist` is refused identically to one aimed
      at `/admin/v1/grants`, and cannot be used to map the surface. Only the
      NORMALIZED origin is logged, never the raw header, so attacker-supplied
      text cannot carry a newline or control character into a log line. The
      admin token is asserted absent from every denial body.
- [x] 7 new shared test bodies x BOTH backends (14 executions) + 12 new unit
      tests. [verified-e2e] Added to the SHARED
      `tests/authz_suite/mod.rs` with one-line wrappers in
      `tests/postgres_backed.rs` and `tests/sqlite_backed.rs`, so the two
      backends cannot drift. They drive the REAL axum router on a REAL
      ephemeral socket with a REAL HTTP client against a REAL database.
      `admin_refuses_a_state_changing_request_from_a_foreign_origin`,
      `admin_allows_a_state_changing_request_from_its_own_origin`,
      `admin_falls_back_to_the_referer_when_no_origin_is_present` (both
      directions),
      `admin_refuses_a_form_post_that_declares_no_origin_at_all` (which also
      proves header-less JSON automation still works),
      `admin_get_routes_are_unaffected_by_the_same_origin_check`,
      `admin_refuses_form_posts_when_no_public_base_url_is_configured`,
      `a_cross_origin_form_post_cannot_create_an_admin_grant`.
      Plus 12 unit tests in `admin::origin`.
      **The one that matters most**:
      `a_cross_origin_form_post_cannot_create_an_admin_grant` reproduces the
      exact attacker-shaped request and then asserts the ABSENCE of the role
      binding through the REAL authorization read path -- `CheckUserPermission`
      on each registered resource AND `LookupUserPermissions` (lore-server's
      only candidate list) AND the admin grants listing -- not merely from the
      status code. "403 returned, row written anyway" is the failure mode a
      status assertion cannot see, and only that assertion catches it. It then
      replays the IDENTICAL form same-origin and asserts it DOES create the
      grant, so what was rejected was the origin and not the request.
      The `AdminHarness` now binds its listener BEFORE building `AppState`, so
      the configured `PUBLIC_BASE_URL` is the origin the test server genuinely
      answers on rather than a constant handed to both sides.
- [x] Documentation corrected where it was wrong, not just extended.
      [code-says]
      `admin/panel.rs`: the module doc's CSRF reasoning is now marked as a
      CORRECTION and states plainly that header-only auth does NOT prevent
      CSRF under a header-injecting proxy, and that same-origin enforcement is
      what closes it. `admin/mod.rs`: a second gate section, plus the layer-
      ordering rationale on `router`. `docs/configuration.md`: a new
      "Same-origin enforcement (CSRF)" section, a prominent WARNING block on
      the nginx example stating that an IP allowlist injecting the header is
      NOT a substitute for per-request CSRF protection (and that mTLS is not
      either), `proxy_set_header Origin/Referer/Host` lines in that example
      with a note that stripping them turns every panel form into a 403, and
      updated `PUBLIC_BASE_URL` / `ADMIN_API_TOKEN` table rows.
      `README.md`: the provisioning section now says the token alone is not
      CSRF protection.

**Additive only.** The bearer gate, `verify_admin_caller`, `strip_bearer`,
`constant_time_eq`, every `ops`/`db` function, every gRPC handler, the OIDC
login flow and the JWKS/claims behaviour are untouched. The only changes to
existing behaviour are (a) state-changing `/admin` requests are now
origin-checked, and (b) `AppState` carries one more field.

**Behaviour change existing operators must know about**: a `/admin/ui` form
POST that carries neither `Origin` nor `Referer` now gets `403` where it
previously succeeded. A browser always sends one, so this only affects a
script that was POSTing to the HTML form routes by hand -- which should be
using `/admin/v1` (unchanged). The existing test helper `post_form` was
updated to attach the same-origin `Origin` header a browser attaches, which is
why the pre-existing panel-form tests still pass.

**Not done, deliberately**: no CORS layer was added (adding a permissive one
to `/admin` would re-open exactly this hole); no `SameSite` cookie work,
because there is still no cookie; no CSRF token, because that would make the
panel stateful and the origin check is sufficient without it;
`.env.example` still lacks `PUBLIC_BASE_URL` and `ADMIN_API_TOKEN` (the same
`.env*` write block earlier passes hit -- nothing was worked around).

**PROOF (all four checks run for real in the pinned build image
`docker/Dockerfile.build`; the Postgres- and IdP-backed tests via `docker
compose -f docker-compose.test.yml run --rm --build tests`, which brings up a
real `postgres:16-alpine` AND a real `ghcr.io/dexidp/dex:v2.44.0` and runs the
FULL `cargo test --workspace`):**

- `cargo build --workspace`: clean, `Finished dev profile`, exit 0.
- `cargo fmt --all -- --check`: clean, exit 0.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean, exit 0.
- `cargo test --workspace`: **223 passed, 0 failed** (was 197), compose exit 0:
  - `lore-authz-core` / `lore-authz-proto`: 0 tests (unchanged).
  - `lore-authz-server` unit tests: **89** (was 77) -- the 12 new
    `admin::origin` cases.
  - `tests/lore_compat.rs`: **4**, unchanged.
  - `tests/oidc_flow.rs`: **16**, unchanged, against a REAL OIDC provider.
  - `tests/postgres_backed.rs`: **57** (was 50), real Postgres 16.
  - `tests/sqlite_backed.rs`: **57** (was 50) -- the EXACT SAME 57 names.
- **Negative control** (the proof the tests are load-bearing, and the proof
  the vulnerability was real): with the `origin::require_same_origin` layer
  temporarily deleted from `admin::router` and nothing else changed,
  `cargo test --test sqlite_backed` reports
  `a_cross_origin_form_post_cannot_create_an_admin_grant ... FAILED`,
  panicking on `a refused cross-origin POST must leave NO permission on
  urc-victim-one -- a 403 with the role binding written anyway is the failure
  this test exists to catch`. That assertion reads `CheckUserPermission`, so
  the failure is direct evidence that the cross-origin form POST minted the
  `admin` grant and the authorization path honoured it -- not an inference
  from a status code. An earlier run of the same control (with the status
  assertion still first) also failed
  `admin_falls_back_to_the_referer_when_no_origin_is_present` and
  `admin_refuses_a_form_post_that_declares_no_origin_at_all` with
  `left: 200, right: 403`. The layer was restored and the full suite re-run
  green afterwards.
  This is also why the headline test asserts the ABSENCE of the binding
  BEFORE it asserts the status: a status assertion in front would panic first
  and hide whether the row was written, which is the failure that matters.
