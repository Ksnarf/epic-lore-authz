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

## Q4. Does `lore-server` ever actually call `CheckUserPermission` or `LookupUserPermissions`? (SETTLED)

**SETTLED, by reading the fork's real call sites (PHASE 1a, see
tasks.md): yes, both, unconditionally whenever `auth_url` is configured.**
`lore-server/src/grpc/handlers/repository_list.rs`'s
`lookup_authorized_repositories` calls `LookupUserPermissions` to build the
candidate list for `RepositoryList`; `lore-server/src/grpc/handlers/
repository_query.rs`'s `check_repository_query_authorization` calls
`CheckUserPermission` to authorize `RepositoryQuery` (used by both
`RepositoryGet` and repository-by-name lookups). Neither caller treats
either RPC as optional or best-effort: both map a `PermissionDenied` /
`Unauthenticated` response specially, and any other error becomes an
`Internal` failure of the whole request. This is source-level confirmation
(the exact request/response shapes each call site sends and reads), not a
runtime trace against a live `lore-server` process.

## Q5. `resource_filter` / `context_filter` semantics in `LookupUserPermissions` (SETTLED for `resource_filter`)

**SETTLED (PHASE 1a): `resource_filter` is a plain prefix match.** The real
call site (`repository_list::lookup_authorized_repositories`) always sends
the literal string `"urc"` (not `"urc-"`, not `"urc-*"`), constructed as
`LookupUserPermissionsRequest { resource_filter: "urc".to_string(),
..Default::default() }`. This project's implementation
(`crates/lore-authz-server/src/grpc.rs`'s `normalize_resource_filter`)
strips a trailing `*` if present and then does a plain prefix match against
`resources.resource_id` (`db::resources::list_resource_ids_with_prefix`),
so `"urc"` and `"urc-*"` behave identically and an empty filter matches
everything -- since every resource this project ever registers is named
`urc-{repository_id}`, a prefix of `"urc"` matches all of them, exactly
satisfying the observed call site.

A separate, non-obvious finding from implementing this: a wildcard grant
(see `db::permissions::WILDCARD_RESOURCE_PATTERN`) is always EXPANDED to
the concrete, currently-registered resource ids it matches before being
returned -- never returned as the literal string `"urc-*"` itself. The real
call site strips the `"urc-"` prefix off each returned `resource_id` and
parses the remainder directly as a repository id; a literal `"urc-*"` entry
would fail that parse and simply be dropped, silently returning ZERO
repositories to a user who should see all of them. See
`crates/lore-authz-server/src/db/permissions.rs`'s module doc comment.

`context_filter` remains UNVERIFIED -- no call site was found that sets it
(the real caller always uses `..Default::default()` for it), so this
project's implementation does not yet do anything with it.

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

**Implementation status (security review remediation pass, after PHASE
1a):** RESOLVED on this project's own side, with an honest caveat about the
other side of the hop. `RebacApiService::create_resource` /
`delete_resource` (`crates/lore-authz-server/src/grpc.rs`) now require
`authorization: Bearer <REBAC_SERVICE_TOKEN>` on every call
(`crates/lore-authz-server/src/service_auth.rs`), fail closed
(`Status::unauthenticated`) when the header is missing, wrong, OR when
`REBAC_SERVICE_TOKEN` itself is not configured, and this is proven by tests
at both the unit level (`grpc.rs`'s `tests` module, `db: None`) and end to
end against a real Postgres-backed service
(`tests/postgres_backed.rs`'s `rebac_*_against_real_db` tests).

The caveat: the pinned/unmodified upstream `lore-server` binary confirmed
above to send no authorization header on this hop also has no config
surface to send `REBAC_SERVICE_TOKEN` specifically -- that is a fact about
`lore-server`, not something this project's remediation could change
without modifying a different repository (`epic-lore`), which is out of
scope here. So: anything that can reach the gRPC port WITHOUT the secret is
now denied (the vulnerability this closes), but making the REAL
`lore-server` present that secret in a live deployment requires an
operator-controlled piece on the network path (a sidecar/proxy that injects
the header) -- see `docs/configuration.md`'s `REBAC_SERVICE_TOKEN` section
for the full writeup of this boundary.

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
to be trusted at all.

**Decided (security review remediation pass):** yes, a shared secret
(`REBAC_SERVICE_TOKEN`), not mTLS -- see Q6 for the full decision writeup.
mTLS was considered and rejected for this pass: the pinned `lore-server`'s
own TLS config for this hop (`ClientTlsConfig::new().with_native_roots()`
in `lore-server/src/authnz/rebac.rs`) only verifies THIS service's server
certificate; it configures no client identity/certificate of its own, so
there is nothing for real mTLS (mutual auth) to check on `lore-server`'s
side without a change to that other repository. A shared secret is the
mechanism that can actually be enforced entirely on this project's own
side of the hop today.

## Q13. Where does `ExchangeUserTokenForMultiresourceToken` get `idp` from? (SETTLED)

Not a wire-format question -- a design question for whoever wired that RPC.
`AuthzClaims`/lore-server's `AuthorizationToken` require `idp`
(docs/protocol-notes.md #2), but `AuthnClaims`/lore-server's `JWTUserInfo`
(the AuthN token the RPC receives as its bearer token) has no `idp` field to
decode it back out of.

**SETTLED (PHASE 1b): from the principal row, via a new `principals.idp`
column** (`migrations/0002_auth_sessions.sql`,
`lore_authz_core::model::Principal::idp`). The OIDC login leg records which
identity provider proved a principal's identity -- the issuer URL, which is
stable, meaningful to an operator reading a raw token, and needs no separate
configuration to stay in sync with the provider it names. The exchange RPC
reads it back off that row.

The `idp_connection_id` route originally proposed here was not taken: it
would only add a join to reach a value the login leg already knows, and a
`Principal` can be provisioned without any IdP connection row at all (the
Phase 1a manual/test path).

Two guarantees make "an AuthZ token with no `idp`" unrepresentable rather
than merely unlikely:

- `AuthzTokenInput::idp` is a mandatory `String`, not an `Option`, so there
  is no call that compiles and omits it.
- Principals with no recorded IdP fall back to `TOKEN_IDP`, which
  `Config::from_env` refuses to let be empty (an EMPTY `idp` fails exactly
  as silently as an absent one). Proven by
  `exchange_falls_back_to_the_configured_idp_when_the_principal_has_none`,
  run against both backends.

## Q14. `kid` is randomly regenerated on every key load (SETTLED, FIXED)

Found while building the Phase 0 integration test.
`crates/lore-authz-server/src/signing.rs`'s `key_from_pkcs8_der` used to
assign a fresh `Uuid::new_v4()` as the `kid` each time it ran, so two
processes loading the SAME `SIGNING_KEY_SOURCE` file published different
`kid` values for the same key. Single-process Phase 0 was unaffected (it is
why `dev-mint-token` takes an explicit `--kid`), but any multi-replica
deployment broke: a token minted by replica A carries A's `kid`, and a
lore-server that fetched its JWKS from replica B rejects it with
`KeyNotFound` after one wasted refetch.

**SETTLED (Phase 1b): fixed by deriving `kid` from an RFC 7638 JWK
thumbprint** -- `base64url(SHA-256(canonical JWK JSON))` over exactly the
members RFC 7638 section 3.2 requires for an EC key (`crv`, `kty`, `x`,
`y`), lexicographically ordered, no whitespace. See
`rfc7638_p256_thumbprint` in `crates/lore-authz-server/src/signing.rs` and
`docs/protocol-notes.md` #7e.

Proven, not asserted: `signing::tests::
same_key_material_yields_an_identical_kid_across_two_independent_loads`
loads one real on-disk PKCS#8 key file through two INDEPENDENT
`SigningKeyStore::load` calls (the multi-replica scenario in miniature) and
asserts both the in-memory `kid` and the published JWKS `kid` match;
`different_key_material_yields_a_different_kid` proves a trivially-constant
`kid` could not pass that test; and
`thumbprint_is_a_43_char_base64url_sha256_over_the_canonical_member_order`
pins the algorithm shape itself so a later refactor cannot silently
redefine `kid` for already-issued tokens.

Note the shape change: `kid` is now 43 base64url characters, not a
36-character UUID. That also unblocks Phase 1 key rotation, which has to
publish a `Pending` key under the exact `kid` it will later sign with.
