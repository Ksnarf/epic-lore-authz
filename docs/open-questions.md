# Open questions (UNVERIFIED)

Everything on this list was UNVERIFIED at scaffold time (2026-08-03) because
it required either running the real `lore` CLI / `lore-server` against a
real epic-lore-authz instance, or reading source this project's author did
not have time to read in full. Resolve these during Phase 0 unless noted
otherwise. Do not treat any of these as settled until there is a passing
integration test proving the answer.

## Q1. `UserToken.expires_at` units: seconds or milliseconds? (HIGH PRIORITY)

The proto comment on `epic_urc.UserToken.expires_at` just says "Epoch."
Evidence from reading the lore CLI's transport and credential handling
leans **milliseconds**, but this was not confirmed by running real code.
Getting this wrong by a factor of 1000 means either every minted token
expires instantly (CLI immediately re-logs-in / fails), or tokens that
effectively never expire (a real security issue given the stateless-token
revocation window noted in `docs/protocol-notes.md`).

**How to settle it**: mint a token with a known real-world expiry, feed it
to the real unmodified `lore` CLI, and observe whether the CLI treats it as
expired at the boundary you expect. `crates/lore-authz-core/src/claims.rs`
has a `SignedToken.expires_at` field flagged with this same open question.

## Q2. The exact `lore-server` config key for `Endpoint.auth_url`

The lore CLI learns the auth service address from
`EnvironmentService.Get`'s `Endpoint.auth_url`. The likely config key path
on the `lore-server` side is `environment.endpoint.auth_url`, but this was
not confirmed by reading the settings loader that actually binds it.
Needed before `docs/lore-server-setup.md` (not yet written) can be trusted.

## Q3. The correlation-id gRPC metadata key

`lore`'s `CorrelationInterceptor` injects a correlation id into gRPC
metadata under a key name that is likely `x-correlation-id` but was not
confirmed by reading the interceptor's source. Needed for log correlation
between epic-lore-authz and `lore-server`/CLI logs, not for correctness.

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
