# Configuration

epic-lore-authz is configured entirely through environment variables. See
`.env.example` at the repo root for the canonical, always-up-to-date list
with inline documentation -- this page is the narrative version. The env
vars are read in `crates/lore-authz-server/src/config.rs`; if you add a new
setting, add it in both places.

Every value in `.env.example` is a placeholder. Never commit a real `.env`
(see `.gitignore`).

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | PHASE 1a | (none) | A Postgres (`postgres://`/`postgresql://`) OR SQLite (`sqlite:`) connection string -- the backend is selected from this scheme at runtime, see the dedicated "Choosing a backend" section below. **Read that section before picking SQLite for anything but local dev.** Required for `LookupUserPermissions`, `CheckUserPermission`, and `RebacApi::CreateResource`/`DeleteResource` to do anything but fail closed with `Status::failed_precondition` (see `main.rs`); everything else in this scaffold has no database dependency. |
| `DB_SCHEMA` | no | `loreauth` | **Postgres only.** This product owns exactly one schema; never `public`, never a dedicated database, never superuser. See `docs/data-model.md`. Migrations run automatically at startup against this schema (connecting IS migrating -- there is no separate migrate command). **Under the `sqlite:` backend this is an explicit NO-OP** (SQLite has no schema concept) -- logged at startup, not silently ignored; see the "Choosing a backend" section below. |
| `JWT_ISSUER` | yes | (none) | `iss` claim on every minted token. |
| `JWT_AUDIENCE` | yes | (none) | Comma-separated root domains. Must include the lore server's own root domain -- see `docs/protocol-notes.md` section 3. |
| `TOKEN_ENV` | no | `dev` | Value placed in the `env` claim of every minted token. Required by lore-server on both claim shapes -- see `docs/protocol-notes.md` section 2. |
| `AUTHN_TOKEN_TTL_SECS` | no | `36000` (10h) | AuthN token lifetime. |
| `AUTHZ_TOKEN_TTL_SECS` | no | `3600` (1h) | AuthZ token lifetime. Keep short: see the stateless-revocation-window note in `docs/protocol-notes.md`. |
| `TOKEN_IDP` | no | `local` | `idp` claim fallback for principals with no recorded identity provider (`Principal.idp` unset -- the manual/test provisioning path). **Must not be empty**, and the process refuses to start if it is: an AuthZ token with an empty or absent `idp` is ACCEPTED by lore-server and then silently stripped of its `resources` claim, surfacing as a permissions bug rather than a claims error. See `docs/protocol-notes.md` section 2 and `docs/open-questions.md` Q13. Principals provisioned through OIDC record their own `idp` and ignore this. |
| `AUTH_SESSION_TTL_SECS` | no | `300` (5m) | How long a browser login session (`StartAuthSession` -> `GetAuthSession`) stays usable. Deliberately longer than the lore CLI's own hard 150-second polling budget -- see the "The 150-second client login deadline" section below. |
| `PUBLIC_BASE_URL` | **yes for login, and for the admin panel** | (none) | Origin this service is reachable at IN A BROWSER (scheme + host + optional port, no path), e.g. `https://authz.example.com`. `StartAuthSession` builds the `login_url` it hands the CLI as `<PUBLIC_BASE_URL>/login/<login_code>`, and the admin surface's same-origin (CSRF) gate compares every state-changing request's `Origin`/`Referer` against it -- see "Same-origin enforcement" below. **Unset means `StartAuthSession` denies with `Status::failed_precondition`** rather than issuing a login URL that goes nowhere, **and every `/admin/ui` form POST is refused with `403`** because there is no origin to check it against; a warning naming both is logged at startup. Behind a reverse proxy this must be the origin the OPERATOR's browser sees (the proxy's), not this process's listen address. If unset, this falls back to the origin of `OIDC_REDIRECT_URL`, which is usually the same host. |
| `SIGNING_KEY_SOURCE` | no | `file:///CHANGE_ME/signing-key.der` | Phase 0: a `file://` unencrypted PKCS#8 EC P-256 private key, PEM or raw DER (NOT a JWK -- see `crates/lore-authz-server/src/signing.rs`). If the file does not exist, an ephemeral dev key is generated in memory and a warning is logged. Phase 1+: real key management. |
| `JWKS_PATH` | no | `/.well-known/jwks.json` | Path on the HTTP listener to serve this service's own JWKS on. |
| `REBAC_SERVICE_TOKEN` | **yes, effectively** | (none) | Shared secret gating `RebacApi::CreateResource`/`DeleteResource` (security review remediation -- see `docs/open-questions.md` Q6). Present as `authorization: Bearer <value>` on those two RPCs only; unrelated to `JWT_ISSUER`/`JWT_AUDIENCE` and not a JWT. **Unset means both RPCs deny every caller** with `Status::unauthenticated` (`crates/lore-authz-server/src/service_auth.rs`) -- a deliberate fail-closed default, not a bug. See the dedicated section below for the honest gap this does and does not close. |
| `ADMIN_API_TOKEN` | **yes to provision anything** | (none) | Shared secret gating the ENTIRE admin surface: the `/admin/v1` provisioning API and the `/admin/ui` panel, both on the HTTP listener. Present as `authorization: Bearer <value>`; a static secret, not a JWT. **Unset (or empty) means every `/admin` request is denied with 401**, including one presenting a token -- a deliberate fail-closed default with no bypass flag. See the dedicated section below: this setting can mint authority over every repository, so treat it as a root credential and restrict `/admin` at your reverse proxy too. This token is NOT by itself CSRF protection when a proxy injects it for an IP range -- see "Same-origin enforcement" below. |
| `GRPC_LISTEN_ADDR` | no | `0.0.0.0:8443` | `UrcAuthApi` + `RebacApi`. Must be reachable over TLS trusted by the lore CLI's native roots in any real deployment. |
| `HTTP_LISTEN_ADDR` | no | `0.0.0.0:8080` | JWKS, login, OIDC/SAML callbacks, health, metrics. |
| `OIDC_ISSUER_URL` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` / `OIDC_REDIRECT_URL` | **yes for login** | (none) | The identity provider browser login runs against. **All four are required together** -- a partially configured provider is treated as UNCONFIGURED and every login denies. See the dedicated section below. Multi-IdP deployments will configure `idp_connections` in the database instead (Phase 2+); these env vars are the single-tenant bring-up. |
| `OIDC_SCOPES` | no | `openid profile email` | Space-separated. `openid` is added automatically if you leave it out. |
| `OIDC_JIT_PROVISIONING` | no | `true` | Create a principal on first login for an identity that has none. Safe as a default because it creates an IDENTITY, never an AUTHORIZATION: a just-provisioned principal holds no role bindings, so its AuthZ token's `resources` claim is empty and it can see nothing until an operator grants it something. Set `false` for a closed deployment where every principal is pre-provisioned. Accepts `true/false/1/0/yes/no/on/off`; anything else is a startup failure, not a silent default. |
| `SAML_SP_ENTITY_ID` / `SAML_IDP_METADATA_URL` | Phase 2 | (none) | Behind the `saml` cargo feature. |
| `RUST_LOG` | no | `info` | Standard `tracing_subscriber::EnvFilter` syntax. |

## Choosing a database backend: Postgres vs SQLite

`DATABASE_URL`'s scheme selects the backend at runtime (`crates/
lore-authz-server/src/db/mod.rs`'s `Db::connect`): `postgres://` /
`postgresql://` for Postgres, `sqlite:` for SQLite. No other config
distinguishes them.

**SQLite is dev / single-instance ONLY. Do not put it behind a load
balancer or run more than one replica against it.** SQLite uses a
single-writer file lock: a second process (a second replica of this
service) opening the same database file will serialize behind that lock at
best, and can hit "database is locked" errors under real concurrent write
load at worst -- this product does nothing to coordinate writers across
processes, and SQLite itself has no multi-writer story to lean on. If you
are running more than one instance of this service, or expect to, **use
Postgres/RDS**, which is what multi-replica deployments require.

Where SQLite is a good fit: local development, a single-instance bring-up,
CI, or any deployment that is genuinely one process talking to one file.

Both backends run the IDENTICAL authorization logic and the IDENTICAL test
suite (`crates/lore-authz-server/tests/authz_suite/`, run against both via
`tests/postgres_backed.rs` and `tests/sqlite_backed.rs` -- see
`docker-compose.test.yml`). Choosing SQLite is not choosing a lesser-tested
path; it is choosing a backend that does not scale past one writer.

Separate migration sets are kept in step by hand: `migrations/` (Postgres)
and `migrations_sqlite/` (SQLite), both applied automatically by `Db::
connect` for whichever backend is live. See `migrations_sqlite/0001_
identities_resources_grants.sql`'s own comment for the handful of
SQLite-forced representation differences (no schema, `uuid` columns as
TEXT, `roles.permissions` normalized into a join table instead of a Postgres
array column) -- none of them change the authorization semantics, only how
they are stored.

## `DB_SCHEMA` is a no-op under SQLite -- said explicitly, not left implicit

SQLite has no schema concept at all, so `DB_SCHEMA` does nothing when
`DATABASE_URL` uses the `sqlite:` scheme. This is NOT silently swallowed:
`Db::connect`'s SQLite path logs it at startup every time (info level if
`DB_SCHEMA` is left at its documented default `loreauth`, a warning if an
operator explicitly set it to something else, since that specifically
suggests they expect it to do something here). If you are configuring
SQLite, you can leave `DB_SCHEMA` unset; it is inert either way.

## Why `JWT_AUDIENCE` is a list, and why it matters more than it looks

This is the setting most likely to produce a confusing failure if
misconfigured. See `docs/protocol-notes.md` section 3 in full before
setting it in any real deployment: the lore CLI validates `aud` against the
lore SERVER's own domain **client-side**, independently of whatever
`lore-server`'s own `auth.jwt_audience` config accepts. The simplest correct
configuration sets both to the lore server's root domain.

## Setting up the identity provider (OIDC)

Browser login runs an OpenID Connect authorization-code flow with PKCE
against whatever provider you configure. There is no per-vendor code in this
project: every endpoint is read from the provider's own
`/.well-known/openid-configuration`, so any IdP implementing OIDC Discovery
and the authorization-code grant works.

Register an application with your provider and set:

| Setting | Value |
|---|---|
| `OIDC_ISSUER_URL` | The provider's issuer identifier, e.g. `https://idp.example.com`. Must match the `issuer` in its own discovery document exactly -- a mismatch is refused (OIDC Discovery section 4.3), because accepting one would let a hijacked discovery URL substitute a different provider entirely. |
| `OIDC_CLIENT_ID` | The client id the provider issued. |
| `OIDC_CLIENT_SECRET` | The client secret the provider issued. Comes from configuration ONLY. There is no default and none is committed anywhere in this repository. |
| `OIDC_REDIRECT_URL` | `<PUBLIC_BASE_URL>/oidc/callback`, registered verbatim with the provider. |

**All four are required together.** A partially configured provider is
treated as unconfigured: `StartAuthSession` denies with
`FailedPrecondition`, and both browser login routes deny. There is no
degraded mode in which a login half-works.

A provider that is configured but temporarily unreachable is NOT a startup
failure -- discovery is lazy and cached, so an IdP that is briefly down (or
that comes up after this process) costs a failed login, not a crash loop.
That is the opposite trade-off from `DATABASE_URL`, and deliberately so:
`lore-server` blocks on THIS service at its own boot (see
`docs/protocol-notes.md` section 4), so this service refusing to start
because someone else's service is down would take the whole deployment with
it.

What is validated on every login, and what each check is for:

- **`state`**: the only thing tying the provider's redirect back to the
  session that started it. An unrecognized value matches no session and the
  callback fails closed. Without it, an attacker could deliver their own
  authorization code to a victim's callback.
- **`nonce`**: compared in constant time against the value bound to the
  session. Without it, an ID token obtained elsewhere for the same client
  could be replayed.
- **PKCE (S256)**: the code verifier never leaves this service, so an
  intercepted authorization code is useless.
- **Signature**: verified against the key the provider publishes under the
  ID token's own `kid`, with the algorithm pinned to what the JWKS declares
  and restricted to asymmetric algorithms. Accepting an `HS*` algorithm here
  is the classic key-confusion attack, where a forged token is signed using
  the provider's own PUBLIC key as an HMAC secret.
- **`iss` / `aud` / `exp`**: exact issuer, our client id in the audience,
  and expiry.

Users are identified by the provider's `sub` claim, never by email address
(an email can be reassigned to a different person; a `sub` cannot). The
issuer is recorded as the principal's `idp` and becomes the `idp` claim on
that user's AuthZ tokens.

## The 150-second client login deadline (a client-side limit, documented not worked around)

The lore CLI polls `GetAuthSession` every 5 seconds up to 30 times and then
gives up with a timeout. That is a hard **150-second budget for the entire
browser login**, set in the CLI's own source, and nothing this service can
configure extends it.

Enterprise MFA can exceed it. A push notification to a phone in another
room, a hardware-token PIN prompt, or a first-time IdP consent screen can
all take longer than two and a half minutes.

What happens when it is exceeded, and why it is survivable:

- The CLI gives up and reports a timeout.
- `AUTH_SESSION_TTL_SECS` (default **300**, deliberately double the CLI's
  budget) means the session is still alive, so the user who finishes MFA at
  the three-minute mark still lands on a success page rather than a
  confusing error.
- They re-run the login. The second attempt is fast, because the IdP session
  is now established and the IdP redirects straight through.

Why it is not "fixed" server-side: the only levers would be to hold the poll
open (long-polling, which `GetAuthSessionResponse`'s request/response shape
does not support) or to report progress this service does not have. Neither
is available, and pretending otherwise would be worse than documenting the
limit. Operators running IdPs with slow interactive MFA should expect the
occasional "run `lore auth login` twice" and can raise
`AUTH_SESSION_TTL_SECS` to make the second attempt reliably land.

Do not lower `AUTH_SESSION_TTL_SECS` below ~180: a session that expires
INSIDE the CLI's own polling window turns a slow login into a silent
failure, which is the one outcome worse than a timeout.

## `ADMIN_API_TOKEN`: the admin surface, and how to expose it safely

Until this setting exists in a deployment, there is no way to create a
principal, a group, or a grant except by connecting to the database and
writing SQL by hand. That was the one structural hole in an otherwise
working product: `RebacApi::CreateResource` populates `resources` (called by
lore-server), and OIDC login can JIT-provision a principal -- but a
JIT-provisioned principal holds NO grants, so it authenticates and can see
nothing until an operator grants it something, and nothing but `psql` could
do that.

`ADMIN_API_TOKEN` opens the surface that closes it:

| Path | What it is |
|---|---|
| `/admin/v1/...` | A JSON API for scripting and automation: principals (list/get/create/set status), groups (list/create/add member/remove member), resources (list/create/soft-delete), grants (list/create/delete) and roles (list only). |
| `/admin/ui` | A server-rendered HTML panel with the same lists and forms to create and to grant/revoke. No JavaScript, no separate build step; it ships inside the existing binary. |

Both live under the single `/admin` path prefix, deliberately apart from the
public `/.well-known/jwks.json`, `/login/*` and `/oidc/callback` routes, so a
reverse proxy can restrict this deployment's whole administrative surface by
path alone.

### Treat this token as a root credential

The admin surface can create a principal and bind it to `urc-*` with the
`admin` role -- that is authority over every repository lore-server knows
about. Generate a high-entropy value (for example
`openssl rand -base64 32`), keep it in the same place as your other
deployment secrets, and rotate it by changing this setting and restarting.

It is never logged, never echoed in an error, and `Config`'s `Debug`
implementation renders it (and every other secret-valued setting) as
`Some("<redacted>")`.

### Fail closed, with no bypass

If `ADMIN_API_TOKEN` is unset or empty, EVERY request under `/admin` is
denied with `401`, including one presenting a token, and including paths
that do not exist. There is no development mode, no insecure flag, and no
way to enable these routes without a token. Every denial is the identical
response whatever the cause, so a probe cannot learn from the error whether
a deployment has an admin token configured at all; the operator learns it
from a warning in the startup log instead.

### Same-origin enforcement (CSRF)

**Every state-changing request under `/admin` -- `POST`, `DELETE`, and any
method that is not `GET`/`HEAD` -- must come from this service's own origin,
which is `PUBLIC_BASE_URL`.** The rule, applied in
`crates/lore-authz-server/src/admin/origin.rs`:

1. `Origin` present -> it must name `PUBLIC_BASE_URL`'s scheme + host + port,
   or the request is refused with `403`.
2. No `Origin` -> `Referer` is used the same way, on its scheme + host + port.
3. Neither header -> the HTML form routes under `/admin/ui` are **refused**;
   the rest of `/admin` (the JSON API) is allowed. A browser always sends
   `Origin` on a cross-origin form POST, so a form submission carrying
   neither header is not a browser; `curl` and every other non-browser client
   send neither, and the JSON API is the interface they are meant to use.
   Rules 1 and 2 still apply to `/admin/v1`, so a request that DOES declare
   a foreign origin is refused there too.

`GET`/`HEAD` are exempt: reading the panel changes nothing.

**If `PUBLIC_BASE_URL` is unset there is nothing to compare against, so this
gate refuses every state-changing request that declares an origin -- including
one that would have matched -- and every `/admin/ui` form POST.** It never
falls back to allowing. In practice: **the panel's forms do not work until
`PUBLIC_BASE_URL` is set** (a startup warning says so), while header-less JSON
automation is unaffected. This is the same value the browser login flow uses;
there is deliberately no second setting for "our origin" that could disagree
with it.

### Reaching the panel from a browser

Every `/admin` route requires the `Authorization` header -- there is no
cookie and no login form, because adding a second, weaker credential path
into a surface that can mint authority is not worth saving a line of proxy
configuration. A browser cannot attach that header to an address-bar
navigation on its own, so front the path with the same reverse proxy that
should already be restricting it:

> **WARNING -- an IP allowlist that injects the header is NOT a substitute for
> per-request CSRF protection.** The moment a proxy adds the admin bearer to
> every request from a trusted network, that credential stops being something
> the caller must hold and becomes something the caller's NETWORK POSITION
> earns. That is ambient authority, exactly like a cookie, and it is
> CSRF-able in exactly the same way: an operator whose browser sits on the
> allowlisted network, visiting any hostile page, is one auto-submitting
> `<form>` away from that page creating an `admin` grant over `urc-*` in their
> name -- no JavaScript, no CORS involvement, no preflight. **mTLS does not
> fix this either**: a client certificate is also presented ambiently on a
> cross-origin navigation. What closes it is the same-origin rule documented
> in the section above, which this service now enforces on every
> state-changing `/admin` request. Configure `PUBLIC_BASE_URL` to the origin
> operators actually type into the address bar (the PROXY's origin, not
> `127.0.0.1:8080`), or the panel's forms will be refused with `403`.

```nginx
location /admin/ {
    allow 10.0.0.0/8;               # or mTLS, or a VPN-only listener
    deny  all;
    proxy_set_header Authorization "Bearer $ADMIN_TOKEN_FROM_YOUR_SECRETS";

    # nginx forwards these unchanged by default; they are spelled out because
    # they are exactly what the same-origin check reads, and a proxy that
    # clears or rewrites them turns every panel form into a 403.
    proxy_set_header Origin  $http_origin;
    proxy_set_header Referer $http_referer;

    proxy_pass http://127.0.0.1:8080;
}
```

Any client that can set a header works without a proxy. The JSON API is the
intended interface for automation, and it is unaffected by the same-origin
rule as long as it declares no origin (which `curl` does not):

```sh
curl -H "authorization: Bearer $ADMIN_API_TOKEN" \
     https://authz.example.com/admin/v1/principals

curl -H "authorization: Bearer $ADMIN_API_TOKEN" \
     -H 'content-type: application/json' \
     -d '{"display_name":"Ada Lovelace","email":"ada@example.com"}' \
     https://authz.example.com/admin/v1/principals

curl -H "authorization: Bearer $ADMIN_API_TOKEN" \
     -H 'content-type: application/json' \
     -d '{"role":"writer","resource_pattern":"urc-*","principal_kind":"user","principal_id":"<id>"}' \
     https://authz.example.com/admin/v1/grants
```

### What the surface refuses, and why it matters

Three checks exist to stop a grant that would look correct in a listing and
authorize nothing, forever:

- **`principal_kind` must match the principal.** The policy engine derives
  the kind it matches on from the principal row's own
  `is_service_account`, so a binding recorded as `user` against a service
  account is inert. Refused with 400.
- **`resource_pattern` is the literal `urc-*` or one specific `urc-<id>`.**
  Nothing else is a pattern. `urc-abc*` would be stored as a resource id
  that can never exist, so it is refused rather than accepted as a prefix
  glob this product does not implement.
- **The principal or group must exist.** `role_bindings.principal_id` is
  polymorphic and cannot carry a foreign key, so this is checked here.

Creates that change nothing are reported (`409`) rather than swallowed, and
every list response is bounded (500 rows) with an explicit `truncated` flag.
See `tasks.md` for what this surface deliberately does not do.

## `REBAC_SERVICE_TOKEN`: what it closes, and what it honestly does not

A security review found `RebacApi::CreateResource`/`DeleteResource`
performed NO caller-identity check at all: anything that could reach the
gRPC port could create or delete resource rows, including mass-revoking
every repository's authorization by iterating the predictable
`urc-{repository_id}` convention with `DeleteResource` and zero credentials.
`REBAC_SERVICE_TOKEN` closes that: both RPCs now require
`authorization: Bearer <REBAC_SERVICE_TOKEN>` and fail closed
(`Status::unauthenticated`) on anything else, INCLUDING the value being
unset -- see `crates/lore-authz-server/src/service_auth.rs` for the
mechanism and full reasoning.

Why a shared secret and not the same bearer-JWT check
`crates/lore-authz-server/src/caller.rs` uses for `LookupUserPermissions`/
`CheckUserPermission`: `lore-server` is the caller on this hop, not an end
user, and it has no `principals` row of its own to resolve to. Reading the
pinned fork's actual client code (`lore-server/src/authnz/rebac.rs`'s
`RebacClientHelper`) shows it builds its gRPC channel with only a
`CorrelationInterceptor` (tracing correlation id) -- but the call sites
that use that channel (`repository_create_auth_resource` /
`repository_delete_auth_resource`) build their requests through
`create_request_with_authorization`, so what actually arrives on this hop
is the END USER's own bearer token, forwarded verbatim. That is a real,
verifiable credential, just the wrong KIND: verifying it the way
`caller.rs` does would authenticate the human, not `lore-server`, and would
let any user who can reach `RepositoryCreate` call `CreateResource`
directly with that same token. A shared secret matches what the design
plan itself recommends for this hop (mTLS or a shared secret, not a user
token) and is the smaller, more auditable surface of the two.

**The honest gap**: by default, the pinned/unmodified upstream
`lore-server` binary this project integrates against forwards the end
user's own bearer token on this hop rather than a service credential, and
has no config surface to send `REBAC_SERVICE_TOKEN` (or any other
service-specific credential) instead. Setting this variable on THIS
service is therefore a real deployment requirement, not a config flip you
do in isolation: something has to replace the forwarded caller token with
the shared secret before it reaches this service's gRPC port.

An optional `[server.auth] rebac_service_token` setting closes that gap on
`lore-server`'s own side. It exists as a not-yet-upstreamed patch on the
`epic-lore` repository's `feat/rebac-service-token` branch (commit
`4185ed4`, based on upstream commit
`f205899adf24b13b2d28e5c08d9256ac99c69f0c`; `epic-lore` is `lore-server`'s
own, separate repository, not part of this project). When configured, it
makes `lore-server`'s rebac client replace the forwarded caller token with
`authorization: Bearer <token>` on this hop only, matching whatever value
you also set for `REBAC_SERVICE_TOKEN` here; when absent, `lore-server`
keeps forwarding the caller's own token as described above. Proven end to
end on 2026-08-06: the correct token lets `RepositoryCreate` succeed and
creates a row in this service's `resources` table; a wrong token is
rejected; leaving the setting unset leaves behavior unchanged
(non-breaking).

Deployments running a stock, unpatched `lore-server` binary are still
affected: they have no config surface to send a service credential at all,
so the caller's own token still lands here, and something else on the
network path -- e.g. a sidecar or reverse proxy the operator controls --
is still needed to attach a real header before `REBAC_SERVICE_TOKEN` here
does anything for them. Making `lore-server` itself send this header
without the patch above is a change to a different repository
(`epic-lore`), out of scope for this project. See
`docs/open-questions.md` Q6 for the full writeup.
