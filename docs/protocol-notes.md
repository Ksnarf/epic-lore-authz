# Protocol notes: what will burn a day if you skip this

This document captures the hard-won, verified-against-source gotchas of the
`lore` auth contract. Read it before touching `crates/lore-authz-core/src/claims.rs`,
`crates/lore-authz-server/src/grpc.rs`, or the JWKS handler in
`crates/lore-authz-server/src/http.rs`.

Everything below was verified by reading `lore-server`'s actual source at the
pinned commit (`f205899adf24b13b2d28e5c08d9256ac99c69f0c`, see
`proto/vendor/UPSTREAM.md`), specifically `lore-server/src/auth/jwt.rs` and
`lore-server/src/auth/jwk.rs`.

As of 2026-08-03, sections 2 and 4 have additionally been confirmed
**at runtime** against an unmodified `lore-server` binary built from that
pinned commit, running in Docker with `server.auth.jwk.endpoint` pointed at
this project's live JWKS endpoint (integration tooling held locally).
Findings that came out of that run are marked **(RUNTIME-VERIFIED)**;
sections still resting on source reading alone are marked **(SOURCE
ONLY)**.

## 1. The two-token model

`lore` uses two distinct JWTs. Confusing them means nothing works.

1. **AuthN token** ("user token"). Issued by `StartAuthSession` /
   `GetAuthSession`, `ExchangeExternalTokenForUserToken`, or
   `ExchangeAPIKeyForUserToken`. Identity only. Carries **no** `resources`
   claim. Stored by the CLI in its encrypted token store keyed by
   `(auth_url, user_id)`.
2. **AuthZ token**. Issued by `ExchangeUserTokenForMultiresourceToken`,
   which the CLI calls with the AuthN token in the `authorization` metadata
   as `Bearer <authn_token>`. Carries the `resources` claim. **This** is the
   token sent to `lore-server` on every repository RPC, and the one
   `lore-server`'s JWT interceptor validates.

The CLI caches AuthZ tokens per `(auth_url, identity, resource_id)` and
re-exchanges on expiry.

## 2. The exact claim contract

`lore-server` tries to deserialize the JWT as `AuthorizationToken`
(our `AuthzClaims`) first; on failure it falls back to `JWTUserInfo`
(our `AuthnClaims`). Non-`Option` fields are mandatory for that struct to
deserialize successfully.

**AuthorizationToken (AuthZ token) required claims:** `sub`, `iss`, `iat`,
`exp`, `aud`, `env`, `name`, `preferred_username`, `idp`.
**Optional:** `resources`, `groups`, `is_service_account`.

**JWTUserInfo (AuthN token, fallback shape) required claims:** `sub`,
`iss`, `iat`, `aud`, `env`, `name`, `preferred_username`, `exp`.
**Optional:** `is_service_account`.

### The two traps

- **Omit `env`**: BOTH decode attempts fail. `lore-server` returns a hard
  `permission_denied`. Loud, easy to debug.
- **Omit `idp`**: the `AuthorizationToken` decode fails, `JWTUserInfo`
  decode succeeds, `resources` is silently dropped to `None`, and
  `verify_authorization` then returns `NotAuthorized`. **This looks exactly
  like a permissions bug.** It is the single highest-value gotcha in this
  document -- if a customer reports "my token has the right resources but
  I still get denied," check for a missing `idp` claim first.

**(RUNTIME-VERIFIED)** The missing-`idp` fallback is worse than "silent" in
the logging sense: at `RUST_LOG=debug` a real `lore-server` logs
`"Decoding JWT token"` and then **nothing at all** for that request's auth
decision. There is no warning, no error, and none of the
`"Decoded user info: AuthorizationToken { .. }"` line a correctly-shaped
token produces. The only externally visible signal is the eventual
`PermissionDenied` on a data-plane RPC. Diagnostic rule: if lore-server logs
`"Decoding JWT token"` for a request but never the matching
`"Decoded user info"` line, the token fell back to the AuthN shape -- check
`idp` first. (`lore-server/src/auth/jwt.rs`'s `verify_token_internal` only
logs inside the `if let Ok(..)` AuthorizationToken branch and on the
fallback's *error* path; the fallback's success path is unlogged.)

`aud` accepts either a single string or an array on the wire (the upstream
struct uses `serde_with`'s `OneOrMany<_, PreferMany>`; our `AuthzClaims` and
`AuthnClaims` mirror this exactly). Always emit an array when minting.

## 3. `aud` is a list of ROOT DOMAINS, not opaque audiences

The lore CLI's own client-side JWT handling treats `aud` (concatenated with
`iss`) as "the Auth Service defines audiences as a list of root domains,"
per the upstream source comment. The CLI rejects a token client-side unless
the lore SERVER's domain matches `iss` or one entry in `aud`, using a
label-boundary check (`domain == apex`, or `domain` ends with `.` + apex).

So `aud` **must** contain the lore server's root domain (e.g.
`lore.example.com`). Simultaneously, `lore-server`'s own
`auth.jwt_audience` config must contain a matching value, because
`jsonwebtoken` does a set-intersection audience check. **Simplest correct
configuration: set both to the lore server's root domain.**

This is enforced **client-side**, before the token is ever stored. A token
that is perfectly valid to `lore-server` will still be rejected by the CLI
if `aud` does not contain the remote domain it is about to be used against.

## 4. Every JWKS key needs both `kid` AND `alg`

- JWKS is served as a plain HTTP GET on a configured URL -- **not** OIDC
  discovery. The path is arbitrary (our default: `/.well-known/jwks.json`,
  configurable via `JWKS_PATH`).
- A `file://` scheme is also supported by `lore-server` for airgapped
  deploys and tests.
- The response must be a standard JWKS document (`{"keys": [...]}`).
- **Every key must have both `kid` and `alg`.** `lore-server` unwraps
  `jwk.common.key_algorithm` with `.ok_or(InternalError)` -- a JWKS missing
  `alg` on even ONE key fails the load of the **entire** key set. Many JWKS
  generators omit `alg` by default. This silently breaks every token
  verification, not just the one key.
- Cache behavior is replace-all on refresh. A `kid` cache miss triggers
  exactly one refetch, then fails. **Publish the NEXT signing key in the
  JWKS before you ever sign anything with it** (this is why signing keys
  have a `Pending` status in the data model -- see `docs/architecture.md`).
- Algorithms exercised in upstream tests: ES256 and HS256. Recommend ES256
  or RS256 for anything beyond local dev/tests.

**(RUNTIME-VERIFIED)** Confirmed against a running `lore-server`:

- The JWKS document this project serves at `/.well-known/jwks.json` is
  fetched and accepted as-is. `lore-server/src/server.rs` calls
  `jwk_service.fetch_new_keys(None).await?` during boot, so **a JWKS
  endpoint that is unreachable, non-200, or malformed aborts lore-server
  startup entirely** -- it is not a lazy or degraded path. Order of
  operations in any deployment: the auth sidecar must be serving JWKS
  before lore-server starts, or lore-server will not come up. Any
  automation that brings both up together must poll the sidecar for a
  ready JWKS response before starting lore-server, for exactly this
  reason.
- The `kid` cache-miss refetch is real and observable: presenting a token
  whose `kid` is not in the cached set produces a second, in-request
  `reqwest::connect` to the JWKS URL, then `PermissionDenied` with
  `Not allowed (KeyNotFound(NotFound))` when the refetch still does not
  supply it.
- A token signed by a key that is not the published one, but stamped with a
  `kid` that IS published, is rejected as
  `PermissionDenied: Not allowed (ValidationFailed(Error(InvalidSignature)))`
  and logs a `WARN "Unexpected error decoding JWT AuthN token"`. Signature
  verification is genuinely enforced; the `kid` is a lookup key, not a
  trust decision.

## 5. TLS is mandatory on the client-facing auth endpoint

The lore CLI rewrites *any* scheme to `https` before dialing the auth
service (`ucs-auth://authz.example.com` and `authz.example.com` both become
`https://authz.example.com`). There is no plaintext path for the CLI. The
advertised `auth_url` must terminate TLS with a certificate the client's
native root store trusts.

By contrast, `lore-server`'s own connection to the auth service only enables
TLS if the configured `auth_url` literally starts with `https`, so the
server-to-sidecar hop **may** be plaintext h2c on an internal network. These
are two separate config values on the `lore-server` side; a split (external
TLS, internal plaintext) is a supported deployment shape.

## 6. What `lore-server` actually enforces (and it is coarse)

Per gRPC call, `lore-server`'s JWT interceptor:
1. Extracts the bearer token from `authorization` metadata.
2. Verifies the JWKS signature, issuer, audience, and expiry.
3. Reads the repository id from request metadata.
4. Calls `verify_authorization(token, repository)`.

`verify_authorization` **only** checks that `resources` contains an entry
whose `resource_id` equals `urc-{repository_id}` or `urc-*`. **It never
reads the `permission` string array inside `ResourcePermission`.**

Consequences:

- Native enforcement in OSS `lore` is **binary per repository** -- you have
  access, or you do not.
- The `read`/`write`/`admin` permission vocabulary is advisory as far as the
  OSS server is concerned. This project models and emits it (for a future
  server, or for operator visibility), but must not market fine-grained
  enforcement that does not exist server-side.

## 7a. `SignedToken.expires_at` is milliseconds (Q1 SETTLED)

`docs/open-questions.md` Q1 asked whether `epic_urc.UserToken.expires_at`
(proto comment just says "Epoch") is seconds or milliseconds. Settled by
reading `lore-transport/src/auth/ucs_auth.rs`: it assigns the proto's
`expires_at` straight into a field literally named `expires_ms` with **no**
`* 1000` scaling (`expires_ms: token.expires_at.max(0) as u64`, at all three
call sites in that file). `lore-transport/src/types.rs` documents that
`expires_ms` field as "Expiry as milliseconds since UNIX epoch", and
`lore-transport/src/connection.rs`'s own tests use millisecond-shaped
literals for it (`1_700_000_000_000`, a plausible date in ms, nonsense in
seconds). By contrast `lore-credential/src/jwt.rs` DOES multiply the JWT's
own `exp` claim by 1000 to get milliseconds ("JWT has number of seconds
since UNIX epoch ... we want milliseconds like all other timestamps in
Lore") -- confirming the JWT `exp` claim itself is ordinary JWT-spec
seconds, and `UserToken.expires_at` is a separately-tracked millisecond
value, not a restatement of `exp`. **Do not conflate the two when minting**:
see `crates/lore-authz-server/src/minting.rs`.

## 7b. Minting `idp` for an AuthZ token cannot come from the AuthN token

`AuthzClaims`/lore-server's `AuthorizationToken` require `idp` (see section
2 above). But `AuthnClaims`/lore-server's `JWTUserInfo` (the AuthN "user"
token shape) has **no** `idp` field at all -- confirmed from
`lore-server/src/auth/jwt.rs`'s `JWTUserInfo` struct. Since
`ExchangeUserTokenForMultiresourceToken` receives only the caller's AuthN
token (decoded as `JWTUserInfo`) plus requested resource ids, a real
implementation cannot recover `idp` by decoding that token -- it must look
it up some other way (e.g. from the `Principal` row `sub` identifies, via
`Principal.idp_connection_id`; see `crates/lore-authz-core/src/model.rs`).
This is a real constraint on whoever wires that RPC (still open in
tasks.md), not a documentation gap: flagged here, in
`crates/lore-authz-server/src/minting.rs`, and in
`docs/open-questions.md` so it is not missed when that RPC is implemented.

## 7c. `SIGNING_KEY_SOURCE` cannot point at a private-key JWK

This repo's own scaffold originally documented `SIGNING_KEY_SOURCE` as
pointing at "a single ES256 JWK". That is not achievable with this
project's pinned `jsonwebtoken` 9.3.1: `jsonwebtoken::jwk::Jwk` (see that
crate's own module doc, "only meant to be used to deal with public JWK, not
generate ones") has no private-key ("d") variant in
`AlgorithmParameters::EllipticCurve` -- it can only represent a PUBLIC key.
`.env.example` and `docs/configuration.md` now describe `SIGNING_KEY_SOURCE`
as pointing at an unencrypted PKCS#8 EC P-256 private key file (PEM or raw
DER) instead. See `crates/lore-authz-server/src/signing.rs`.

## 7d. Correlation-id metadata key is `x-epic-correlation-id` (Q3 SETTLED)

**(RUNTIME-VERIFIED)** `docs/open-questions.md` Q3 guessed
`x-correlation-id`. That guess was **wrong**. The real constant is
`lore_transport::grpc::CORRELATION_ID_HEADER = "x-epic-correlation-id"`
(`lore-transport/src/grpc/mod.rs`), consumed server-side by
`lore-server/src/correlation/{layer,service}.rs`.

Confirmed end to end rather than only by reading the constant: sending
`-H "x-epic-correlation-id: e2e-correlation-probe-0001"` on a gRPC call
makes lore-server log `"Found existing correlation ID"` and then carry
`"correlation_id":"e2e-correlation-probe-0001"` on every subsequent log line
for that request, including the auth lines. Without the header it logs
`"Generated correlation ID"` and invents a UUID. This is the join key for
correlating epic-lore-authz logs with lore-server logs.

Note for anyone reading upstream client code: `lore-transport`'s
`inject_correlation_id` is currently a **no-op** with the comment "The
correlation ID injection is now a no-op at this layer", so the real `lore`
CLI does not appear to set this header today -- the server generates one.
The header is honoured when present regardless of who sets it.

## 7e. `kid` is an RFC 7638 JWK thumbprint (FIXED in Phase 1b)

Not a lore-protocol fact, a fact about this project that the Phase 0
integration test forced into the open, and fixed in Phase 1b.

**The bug (historical):** `signing.rs`'s `key_from_pkcs8_der` used to assign
`Uuid::new_v4()` as the `kid` every time a key was loaded. Two processes
loading the SAME private key file therefore published DIFFERENT `kid` values
for the same key. Harmless for a single Phase 0 process (and why
`dev-mint-token` has to be handed the running server's `kid` explicitly),
but a real bug for any multi-replica deployment: a token minted by replica A
carries A's `kid`, lore-server fetches the JWKS from whichever replica the
load balancer picks, and a miss costs one refetch and then a hard
`KeyNotFound` rejection of a perfectly valid token.

**The fix:** `kid` is now the RFC 7638 JWK thumbprint of the public key --
`base64url(SHA-256(canonical JWK JSON))`, where the canonical JSON contains
only the members RFC 7638 section 3.2 requires for `"kty":"EC"` (`crv`,
`kty`, `x`, `y`), in lexicographic order with no whitespace. The same key
material therefore always produces the same `kid`, in every replica and
across restarts. Proven by
`signing::tests::same_key_material_yields_an_identical_kid_across_two_independent_loads`
(two independent `SigningKeyStore::load` calls against one real on-disk key
file) plus `different_key_material_yields_a_different_kid` (so a constant
`kid` could not pass the first test).

Consequences worth knowing:

- `kid` changed shape: 43 base64url characters, not a 36-character UUID.
  Anything that hardcoded a UUID-shaped `kid` (nothing in this repo does)
  breaks.
- Key rotation (Phase 1) can now publish a `Pending` key under the exact
  `kid` it will later sign with, which is the whole point of pre-publishing
  it (see section 4).
- The thumbprint is over PUBLIC key material only, so publishing it in the
  JWKS and in every JWT header leaks nothing the JWKS did not already
  publish.

## 7f. The CLI's login deadline is 150 seconds, and it is client-side

`lore-revision/src/auth/login.rs` polls `GetAuthSession` every
`POLLING_INTERVAL_SECS` (5) up to `POLLING_MAX_RETRIES` (30) times and then
returns a timeout. That is a hard **150-second budget for the entire browser
login**, set in the CLI, and no server-side setting extends it.

It matters because enterprise MFA can exceed it: a push notification to a
phone in another room, a hardware-token PIN, or a first-time IdP consent
screen can all take longer than two and a half minutes.

This project does not try to work around it. `AUTH_SESSION_TTL_SECS`
defaults to 300 -- deliberately double the CLI's budget -- so a user who
finishes MFA late still lands on a success page and simply re-runs the
login, which is fast the second time because the IdP session now exists. The
only server-side alternatives would be long-polling (which
`GetAuthSessionResponse`'s request/response shape does not support) or
reporting progress this service does not have. See `docs/configuration.md`.

## 7g. Nothing in the login flow is provider-specific

`StartAuthSession` -> browser -> `GetAuthSession` is implemented on top of a
generic OIDC relying party (`crates/lore-authz-server/src/oidc.rs`): every
endpoint, the JWKS location, and the token-endpoint client-authentication
method all come from the provider's own
`/.well-known/openid-configuration`. There is no per-vendor branch, and
adding one would be a bug.

Two consequences worth writing down:

- The identity key is the provider's `sub` claim, never the email address --
  an email can be reassigned to a different human, a `sub` cannot. `sub` is
  stored on `principals.subject` with a UNIQUE `(source, subject)` index, so
  one IdP subject can never resolve to two principals.
- The `idp` claim on minted AuthZ tokens is the provider's ISSUER URL. That
  makes a raw token self-describing about which provider authenticated its
  subject, and it is one fewer setting to keep in sync (see
  `docs/open-questions.md` Q13, now SETTLED).

## 8. Stateless token revocation window

Revoking a `role_binding` does not invalidate already-issued AuthZ tokens.
This is mitigated only by keeping AuthZ token TTL short (recommended: 1
hour default, see `.env.example`). Document this window explicitly to
operators -- it is the main security caveat of a stateless-token design. A
`jti` denylist is possible later but requires `lore-server` support it does
not currently have.

## 8a. `ExchangeUserTokenForMultiresourceToken` refuses an AuthZ-shaped input token

Security review finding: `caller::caller_principal_id` decodes ONLY the
`sub` claim, which is present on both claim shapes (`AuthzClaims` and
`AuthnClaims`, see section 2). On its own that means a caller's own
previously-minted AuthZ token verifies at this endpoint just as well as a
real AuthN token would -- nothing forced the input to be AuthN-shaped.

Confirmed NOT to be privilege escalation: `resources` is recomputed fresh
from real grants on every exchange, and `resolve_caller` still denies a
principal whose status is no longer `active`. What it WOULD allow, if left
unfixed, is unbounded AuthZ-token renewal for the entire life of the
original AuthN token -- re-exchanging an AuthZ token for a fresh one
indefinitely, well past the AuthZ token's own short TTL (see section 8).
That is undesirable on its own even without being an authorization bug, so
the decision made here is to REFUSE an AuthZ-shaped token at this endpoint
outright (`Status::invalid_argument`) rather than accept it deliberately.

Detection is `caller::is_authz_shaped_token`: `idp` is mandatory on
`AuthzClaims` and absent from `AuthnClaims`, so its presence on an
already-would-be-valid token is the shape signal, without needing two
different decode targets. Enforced in `grpc.rs`'s
`exchange_user_token_for_multiresource_token`, before `resolve_caller` runs.
Pinned by `exchange_denies_an_authz_shaped_token_presented_for_renewal`
(`tests/authz_suite/mod.rs`, both backends) so this choice cannot regress
back to silent acceptance.

## 9. What the integration test still does NOT cover

The integration test drives `lore-server` with `grpcurl`, not with the real
`lore` CLI. So everything above about **client-side** behaviour is still
**(SOURCE ONLY)** and unproven at runtime:

- Section 3's `acceptable_root_domains()` check. `grpcurl` does not perform
  it, so an `aud` that would be rejected by the CLI still passes this test
  suite. Section 3 remains the authority on what `aud` must contain.
- Section 5's "the CLI rewrites any scheme to https". The test suite talks
  plaintext h2c to `lore-server`'s gRPC port, which works because
  `[server.grpc.certificate]` is unset. It says nothing about the CLI path.
- `docs/open-questions.md` Q1 (`UserToken.expires_at` units). Nothing in
  this test exercises `UserToken` on the wire at all -- the tokens are
  minted directly rather than fetched through
  `StartAuthSession`/`GetAuthSession`. **Partly closed since PHASE 1b**:
  those RPCs now exist and produce a real `UserToken`, and the login suite
  asserts `UserToken.expires_at == exp * 1000` (milliseconds, not seconds),
  which is the same relationship `lore-credential/src/jwt.rs` implements on
  the client side. What is still unproven is that the real CLI is HAPPY with
  that value -- only a real `lore auth login` shows that.
- QUIC. Only the gRPC/TCP listener was exercised. `lore-server` also serves
  QUIC on the same port number over UDP with its own auth path
  (`lore-server/src/quic/storage_service.rs` takes the same `JwtVerifier`),
  which this suite does not touch.

The tasks.md Phase 0 exit gate (real `lore auth login` / `clone` / `push` /
`pull`) is what closes those gaps, and it needs the still-stubbed gRPC RPCs
to exist first.
