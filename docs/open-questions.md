# Open questions (UNVERIFIED)

Everything on this list was UNVERIFIED at scaffold time (2026-08-03) because
it required either running the real `lore` CLI / `lore-server` against a
real epic-lore-authz instance, or reading source this project's author did
not have time to read in full. Resolve these during Phase 0 unless noted
otherwise. Do not treat any of these as settled until there is a passing
integration test proving the answer.

## Q1. `UserToken.expires_at` units: seconds or milliseconds? (SETTLED)

**SETTLED (this pass, by reading source, not by running the CLI): milliseconds.**

`lore-transport/src/auth/ucs_auth.rs` assigns the proto's `expires_at`
straight into a field literally named `expires_ms` with no `* 1000` scaling
(`expires_ms: token.expires_at.max(0) as u64`, three call sites).
`lore-transport/src/types.rs` documents that field as "Expiry as
milliseconds since UNIX epoch". `lore-transport/src/connection.rs`'s own
tests use millisecond-shaped literals for it (`1_700_000_000_000` -- a
plausible 2023 date in milliseconds, a nonsense year-55919 date in
seconds). By contrast, `lore-credential/src/jwt.rs`'s `user_info_from_token`
explicitly multiplies the JWT's own `exp` claim by 1000 to get this same
"milliseconds like all other timestamps in Lore" convention, confirming the
JWT `exp` claim itself is ordinary seconds and `UserToken.expires_at` is a
separate, already-millisecond field.

This is source-level evidence, not an end-to-end run of the real `lore`
CLI against a real `expires_at` value -- the tasks.md Phase 0 exit gate
(a real `lore auth login` / `lore push` / `lore pull` against unmodified
upstream binaries) is still the authoritative confirmation and has not run
yet. Note that the 2026-08-03 integration run does **not** close this: it
mints tokens directly rather than fetching them through
`StartAuthSession`/`GetAuthSession`, so no `UserToken.expires_at`
value ever crosses the wire in that test. See `docs/protocol-notes.md` #9. `crates/lore-authz-core/src/claims.rs`'s `SignedToken.expires_at` doc
comment and `crates/lore-authz-server/src/minting.rs` (`signed_token`) now
implement and cite this finding. See docs/protocol-notes.md #7a.

## Q2. The exact `lore-server` config key for `Endpoint.auth_url`

The lore CLI learns the auth service address from
`EnvironmentService.Get`'s `Endpoint.auth_url`. The likely config key path
on the `lore-server` side is `environment.endpoint.auth_url`, but this was
not confirmed by reading the settings loader that actually binds it.
Needed before `docs/lore-server-setup.md` (not yet written) can be trusted.

## Q3. The correlation-id gRPC metadata key (SETTLED)

**SETTLED 2026-08-03, verified at runtime: `x-epic-correlation-id`.**

The guess recorded here (`x-correlation-id`) was **wrong**. The constant is
`lore_transport::grpc::CORRELATION_ID_HEADER = "x-epic-correlation-id"`
(`lore-transport/src/grpc/mod.rs`), read server-side by
`lore-server/src/correlation/layer.rs`. Proven end to end (integration tooling held locally) by sending the
header on a real gRPC call and observing `lore-server` log
`"Found existing correlation ID"` and then stamp the supplied value on
every log line for that request. Without the header lore-server logs
`"Generated correlation ID"` and invents a UUID.

Caveat worth knowing: `lore-transport`'s `inject_correlation_id` is
currently a no-op ("The correlation ID injection is now a no-op at this
layer"), so the real CLI does not appear to send it today. See
`docs/protocol-notes.md` #7d.

## Q4. Does `lore-server` ever actually call `CheckUserPermission` or `LookupUserPermissions`?

No call sites were found in the `lore-server` source read while designing
this project. `lore-server/src/authnz/auth.rs` has client helper wrappers
for both, but whether anything in `lore-server` actually invokes them is
unconfirmed. Affects Phase 1 prioritization only -- implement both
correctly regardless, but do not block Phase 0 on their exact semantics.

## Q5. `resource_filter` / `context_filter` semantics in `LookupUserPermissions`

Undocumented in the proto. Proposal (not yet implemented): support exact
match, a trailing-`*` prefix match, and `urc-*` meaning "all resources."
Whatever is implemented, document the chosen interpretation here and in
user-facing docs, since callers cannot infer it from the proto alone.

## Q6. Does `lore-server` send an authorization header on `RebacApi` calls?

`lore-server/src/authnz/common.rs`'s
`create_request_with_authorization` appends an *empty* `authorization`
header when no token is supplied, rather than omitting the header, per an
upstream test (`can_create_request_without_authorization`). This suggests
`RebacApi.CreateResource` / `DeleteResource` calls from `lore-server` may
carry no real bearer token at all. This determines how the
server-to-sidecar hop is authenticated: an empty `authorization` value
must be treated as **absent, not malformed**, and the design plan
recommends gating this hop with mTLS or a shared secret rather than
expecting a user token.

## Q7. Expected `permission` string vocabulary

Not enforced by the OSS `lore-server` (see `docs/protocol-notes.md` #6).
This project has chosen `read` / `write` / `admin` as a reasonable default,
but a future upstream server or Epic-internal UI might expect specific
strings we have not seen. Low risk, documented so it can be revisited.

## Q8. `VerifyUser` / `VerifyCompliance` semantics

The proto references a "Product Name as registered in `ucs-auth-api`
config." No call sites were found while designing this project. Proposal:
implement `VerifyUser` as plain identity validation, and treat compliance
requirements as satisfied unless explicitly configured otherwise. Tracked
as Phase 2 in `tasks.md`.

## Q9. `GetProviderUserId` semantics

Presumably maps an internal principal id back to the identity provider's
subject claim. The domain model (`Principal.subject`) supports this, but
the mapping semantics are assumed, not verified against any real caller.

## Q10. `token_type` string vocabulary for `ExchangeExternalTokenForUserToken`

The lore CLI passes `--token-type` through from its own command line
verbatim, so this project effectively defines the vocabulary
(`api-key`, `github-actions`, etc. are proposed, not confirmed against any
CLI-side allowlist). Confirm there is no client-side allowlist in the CLI
before assuming arbitrary values are accepted.

## Q11. Concurrent AuthZ tokens for different resource sets

The CLI appears to cache AuthZ tokens per `(auth_url, identity,
resource_id)`, which suggests concurrent tokens for different resource sets
do not interfere in the CLI's token store, but this was inferred from
reading the caching code, not from a running test.

## Q12. Does `lore-server` need its own service identity to call this sidecar?

Related to Q6. If `lore-server` never sends a bearer token on `RebacApi`
calls, it may need some other credential (mTLS client cert, shared secret)
to be trusted at all. Not yet decided; tracked for Phase 0/1 design.

## Q13. Where does `ExchangeUserTokenForMultiresourceToken` get `idp` from?

Not a wire-format question -- a design question for whoever wires that RPC
(still `Status::unimplemented`, tasks.md). `AuthzClaims`/lore-server's
`AuthorizationToken` require `idp` (docs/protocol-notes.md #2), but
`AuthnClaims`/lore-server's `JWTUserInfo` (the AuthN token the RPC receives
as its bearer token) has no `idp` field to decode it back out of. Proposed:
look `idp` up from the `Principal` row `sub` identifies, via
`Principal.idp_connection_id` (`crates/lore-authz-core/src/model.rs`) --
requires Phase 1 persistence to exist first, so tracked here rather than
solved in this Phase 0 pass. See docs/protocol-notes.md #7b and
`crates/lore-authz-server/src/minting.rs`.

Whatever design answers this question must make it structurally impossible
to mint an AuthZ token without `idp` -- which is why `AuthzTokenInput::idp`
is a mandatory `String` today, not an `Option`.

## Q14. `kid` is randomly regenerated on every key load (NEW, needs fixing)

Found while building the Phase 0 integration test.
`crates/lore-authz-server/src/signing.rs`'s `key_from_pkcs8_der` assigns a
fresh `Uuid::new_v4()` as the `kid` each time it runs, so two processes
loading the SAME `SIGNING_KEY_SOURCE` file publish different `kid` values
for the same key. Single-process Phase 0 is unaffected (it is why
`dev-mint-token` takes an explicit `--kid`), but any multi-replica
deployment breaks: a token minted by replica A carries A's `kid`, and a
lore-server that fetched its JWKS from replica B rejects it with
`KeyNotFound` after one wasted refetch.

Proposed fix: derive `kid` deterministically from the public key material
(RFC 7638 JWK thumbprint). That also makes `kid` stable across restarts,
which key rotation (Phase 1) needs anyway -- a `Pending` key has to be
published under the `kid` it will later sign with. Settle before Phase 1
rotation work starts. See `docs/protocol-notes.md` #7e.
