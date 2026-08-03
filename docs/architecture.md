# Architecture

## Why this project exists

[`EpicGames/lore`](https://github.com/EpicGames/lore) is an open source
version control system. Its server (`lore-server`) and CLI already implement
a full enterprise-auth *client*: browser SSO login, service-account token
exchange, and per-repository authorization checks on every RPC. What they do
not ship is the *server* side of that contract -- `lore-proto/build.rs`
compiles `auth_api.proto` and `rebac_api.proto` with `.build_server(false)`,
because Epic's own auth service is not open source.

epic-lore-authz is that missing server: a single sidecar binary that
implements `UrcAuthApi` (`auth_api.proto`) and `RebacApi` (`rebac_api.proto`)
against real enterprise identity providers (OIDC, SAML), so that an
unmodified `lore-server` and unmodified `lore` CLI can be pointed at real SSO
without either of them being patched.

This is currently a **scaffold**: structure, contracts, config surface, CI,
and stubbed handlers. See `tasks.md` for what is actually implemented.

## Component diagram

```
+-------------------------------------------------------------------+
|  epic-lore-authz  (single Rust binary, single container)          |
|                                                                    |
|  Listener 1: gRPC / tonic  (TLS, h2)            [port 8443]       |
|    - UrcAuthApi   server impl of auth_api.proto                   |
|    - RebacApi     server impl of rebac_api.proto                  |
|                                                                    |
|  Listener 2: HTTP / axum                        [port 8080]       |
|    - GET  /.well-known/jwks.json     <-- lore-server fetches this |
|    - GET  /login/{session_code}      browser entry, redirect to IdP|
|    - GET  /oidc/callback             OIDC authorization code cb   |
|    - POST /saml/acs                  SAML 2.0 assertion consumer  |
|    - GET  /saml/metadata             SP metadata for the IdP      |
|    - GET  /login/done                "you may close this tab"    |
|    - /admin/v1/*                     admin REST API (phase 2)    |
|    - /scim/v2/*                      SCIM 2.0 (phase 3)          |
|    - GET  /healthz /readyz /metrics                                |
|                                                                    |
|  Core: session mgr | token minter | key mgr | policy engine       |
+-------------------------------------------------------------------+
          |                          |
          | sqlx                     | OIDC / SAML
          v                          v
    +-----------+           +--------------------+
    | Postgres  |           | Enterprise IdP      |
    | (shared,  |           | Okta / Entra ID /   |
    |  provided |           | Auth0 / Keycloak /  |
    |  DB URL)  |           | ADFS                |
    +-----------+           +--------------------+

+--------------------+
| lore-server        |  -- gRPC to auth_url (may be h2c) --> epic-lore-authz
| (UNMODIFIED)       |  -- HTTP GET JWKS ------------------> epic-lore-authz
+--------------------+
    ^            |
    | repo RPCs  | EnvironmentService.Get returns endpoint.auth_url
    |            v
+--------------------+
| lore CLI / client  |  -- gRPC (MUST be https) ----------> epic-lore-authz UrcAuthApi
+--------------------+
```

Talks-to summary:
- lore CLI -> epic-lore-authz gRPC: `StartAuthSession`, `GetAuthSession`,
  `ExchangeExternalTokenForUserToken`,
  `ExchangeUserTokenForMultiresourceToken`, `GetUserInfo`, `GetUserId`.
- lore CLI -> lore-server: `EnvironmentService.Get` to learn `auth_url`, then
  all repo RPCs bearing the AuthZ token.
- lore-server -> epic-lore-authz gRPC: `CreateResource`, `DeleteResource`,
  possibly `CheckUserPermission` and `LookupUserPermissions`.
- lore-server -> epic-lore-authz HTTP: `GET /.well-known/jwks.json`.
- Browser -> epic-lore-authz HTTP: `/login/{session_code}` -> IdP ->
  `/oidc/callback` or `/saml/acs`.
- epic-lore-authz -> Postgres, epic-lore-authz -> IdP.

**lore-server never talks to the IdP.** epic-lore-authz is the only
IdP-aware component in the system. That is the entire point of the sidecar
design: `lore-server`'s `auth.jwk.endpoint` setting points at epic-lore-authz's
JWKS endpoint, and nothing else about `lore-server` needs to change.

## Human login flow (OIDC), end to end

1. User runs `lore auth login` (optionally `--no-browser`).
2. CLI calls `lore-server`'s `EnvironmentService.Get`, reads
   `endpoint.auth_url` (e.g. `ucs-auth://authz.example.com`).
3. CLI generates `client_state` (a UUIDv4) and calls
   `StartAuthSession{client_state}` over gRPC against epic-lore-authz.
4. epic-lore-authz creates a pending session: random `session_code`,
   `hash(client_state)`, PKCE verifier, nonce, expiry. Returns
   `{session_code, login_url}`.
5. CLI opens `login_url` in the system browser (or prints it with
   `--no-browser`).
6. Browser hits `/login/{session_code}`. epic-lore-authz selects the IdP
   connection and redirects to the IdP authorization endpoint with PKCE,
   nonce, and state bound to `session_code`.
7. User authenticates at the IdP.
8. IdP redirects to `/oidc/callback?code&state`. epic-lore-authz exchanges
   the code, validates the `id_token`, resolves or JIT-creates the local
   user, and mints the AuthN JWT (see `docs/protocol-notes.md` for the exact
   claim shape). Session becomes `approved`.
9. Meanwhile the CLI polls `GetAuthSession{session_code, client_state}`
   every 5 seconds. **Hard deadline: the CLI gives up after 150 seconds.**
   The entire browser round trip, including any IdP MFA step, must finish
   inside that window. See `docs/open-questions.md`.
10. On approval, `GetAuthSession` returns the AuthN token and the session is
    marked `consumed` (single use).
11. CLI validates the token client-side (see `aud` note in
    `docs/protocol-notes.md`) and stores it.
12. On the first repository operation, the CLI calls
    `ExchangeUserTokenForMultiresourceToken{resource_id:["urc-<repoid>"]}`
    with `authorization: Bearer <authn_token>`. epic-lore-authz mints the
    AuthZ JWT containing the `resources` claim.
13. CLI sends the AuthZ token to `lore-server` on every repository RPC.
    `lore-server`'s interceptor validates it via epic-lore-authz's JWKS and
    checks `resources` for the requested repository.

No device-code flow needs to be invented: `lore` already implements a
poll-based browser flow functionally equivalent to one. epic-lore-authz only
implements the server half of an existing, unmodified client contract.

## Service accounts / CI

Three paths, see `docs/ci-oidc-federation.md` for the workload-identity one
in detail once it exists (not yet written -- tracked in `tasks.md`):

1. **API key** (default for CI): `lore auth login --token <key> --token-type
   api-key` calls `ExchangeExternalTokenForUserToken`.
2. **OIDC workload identity federation** (secret-less): CI presents its own
   OIDC ID token (GitHub Actions, GitLab, Buildkite) via
   `ExchangeExternalTokenForUserToken{token_type: "github-actions", ...}`.
   epic-lore-authz validates it against that provider's JWKS and matches a
   configured trust rule.
3. **Direct token** (`token_type == "lore"`): the CLI stores the JWT as-is,
   no exchange. Useful for break-glass and tests; minted via the admin API
   (phase 2).

`RefreshAuthSession` is intentionally dead -- the upstream CLI's own
`refresh_authentication` returns `NotSupported`. Expiry means re-login.

## Tech stack

Rust: `tonic` + `axum` + `sqlx` (postgres, rustls) + `jsonwebtoken` +
`openidconnect` + `tokio` + `argon2`. Versions are pinned to match
`EpicGames/lore` at the commit this project vendors its protos from -- see
the root `Cargo.toml` comment and `proto/vendor/UPSTREAM.md`. The decisive
reason is `jsonwebtoken`: minting with the exact crate and version
`lore-server` validates with removes an entire class of "my token is valid
but lore rejects it" bugs (JWK `alg`/`kid` handling, `aud` one-or-many
shape, EC curve encoding).

SAML in Rust is the one real risk in this stack (`samael` links
libxmlsec1/OpenSSL natively). Mitigation: implement it behind a `saml`
cargo feature, and document pointing epic-lore-authz's OIDC front end at
Dex or Keycloak as a supported fallback for SAML-only IdPs.

## What this project deliberately does NOT do

- It does not patch `lore-server` or the `lore` CLI. Both are unmodified
  clients of the contract this project implements.
- It does not enforce fine-grained (per-permission) authorization on
  `lore-server`'s behalf beyond what `lore-server` itself checks. See
  `docs/protocol-notes.md` -- `verify_authorization` only checks resource
  membership, never the `permission` array. Per-repository access is
  binary in the OSS server today.
- It does not implement SCIM in the initial phases (see `tasks.md` Phase 3).
