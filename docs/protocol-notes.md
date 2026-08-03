# Protocol notes: what will burn a day if you skip this

This document captures the hard-won, verified-against-source gotchas of the
`lore` auth contract. Read it before touching `crates/lore-authz-core/src/claims.rs`,
`crates/lore-authz-server/src/grpc.rs`, or the JWKS handler in
`crates/lore-authz-server/src/http.rs`.

Everything below was verified by reading `lore-server`'s actual source at the
pinned commit (`f205899adf24b13b2d28e5c08d9256ac99c69f0c`, see
`proto/vendor/UPSTREAM.md`), specifically `lore-server/src/auth/jwt.rs` and
`lore-server/src/auth/jwk.rs`.

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

## 7. Stateless token revocation window

Revoking a `role_binding` does not invalidate already-issued AuthZ tokens.
This is mitigated only by keeping AuthZ token TTL short (recommended: 1
hour default, see `.env.example`). Document this window explicitly to
operators -- it is the main security caveat of a stateless-token design. A
`jti` denylist is possible later but requires `lore-server` support it does
not currently have.
