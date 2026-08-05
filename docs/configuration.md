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
| `DATABASE_URL` | PHASE 1a | (none) | Standard Postgres connection string. Required for `LookupUserPermissions`, `CheckUserPermission`, and `RebacApi::CreateResource`/`DeleteResource` to do anything but fail closed with `Status::failed_precondition` (see `main.rs`); everything else in this scaffold has no Postgres dependency. |
| `DB_SCHEMA` | no | `loreauth` | This product owns exactly one schema; never `public`, never a dedicated database, never superuser. See `docs/data-model.md`. Migrations run automatically at startup against this schema (connecting IS migrating -- there is no separate migrate command). |
| `JWT_ISSUER` | yes | (none) | `iss` claim on every minted token. |
| `JWT_AUDIENCE` | yes | (none) | Comma-separated root domains. Must include the lore server's own root domain -- see `docs/protocol-notes.md` section 3. |
| `TOKEN_ENV` | no | `dev` | Value placed in the `env` claim of every minted token. Required by lore-server on both claim shapes -- see `docs/protocol-notes.md` section 2. |
| `AUTHN_TOKEN_TTL_SECS` | no | `36000` (10h) | AuthN token lifetime. |
| `AUTHZ_TOKEN_TTL_SECS` | no | `3600` (1h) | AuthZ token lifetime. Keep short: see the stateless-revocation-window note in `docs/protocol-notes.md`. |
| `SIGNING_KEY_SOURCE` | no | `file:///CHANGE_ME/signing-key.der` | Phase 0: a `file://` unencrypted PKCS#8 EC P-256 private key, PEM or raw DER (NOT a JWK -- see `crates/lore-authz-server/src/signing.rs`). If the file does not exist, an ephemeral dev key is generated in memory and a warning is logged. Phase 1+: real key management. |
| `JWKS_PATH` | no | `/.well-known/jwks.json` | Path on the HTTP listener to serve this service's own JWKS on. |
| `REBAC_SERVICE_TOKEN` | **yes, effectively** | (none) | Shared secret gating `RebacApi::CreateResource`/`DeleteResource` (security review remediation -- see `docs/open-questions.md` Q6). Present as `authorization: Bearer <value>` on those two RPCs only; unrelated to `JWT_ISSUER`/`JWT_AUDIENCE` and not a JWT. **Unset means both RPCs deny every caller** with `Status::unauthenticated` (`crates/lore-authz-server/src/service_auth.rs`) -- a deliberate fail-closed default, not a bug. See the dedicated section below for the honest gap this does and does not close. |
| `GRPC_LISTEN_ADDR` | no | `0.0.0.0:8443` | `UrcAuthApi` + `RebacApi`. Must be reachable over TLS trusted by the lore CLI's native roots in any real deployment. |
| `HTTP_LISTEN_ADDR` | no | `0.0.0.0:8080` | JWKS, login, OIDC/SAML callbacks, health, metrics. |
| `OIDC_ISSUER_URL` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` / `OIDC_REDIRECT_URL` | Phase 1 | (none) | Single-tenant local-dev bring-up. Multi-IdP deployments configure `idp_connections` in the database instead. |
| `SAML_SP_ENTITY_ID` / `SAML_IDP_METADATA_URL` | Phase 2 | (none) | Behind the `saml` cargo feature. |
| `RUST_LOG` | no | `info` | Standard `tracing_subscriber::EnvFilter` syntax. |

## Why `JWT_AUDIENCE` is a list, and why it matters more than it looks

This is the setting most likely to produce a confusing failure if
misconfigured. See `docs/protocol-notes.md` section 3 in full before
setting it in any real deployment: the lore CLI validates `aud` against the
lore SERVER's own domain **client-side**, independently of whatever
`lore-server`'s own `auth.jwt_audience` config accepts. The simplest correct
configuration sets both to the lore server's root domain.

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
user, and reading the pinned fork's actual client code
(`lore-server/src/authnz/rebac.rs`'s `RebacClientHelper`) confirms it
attaches no bearer token, and no client TLS identity, to these calls --
only a correlation-id interceptor for tracing. There is nothing for a
JWT-verification check to verify here; a shared secret matches what the
design plan itself recommends for this hop (mTLS or a shared secret, not a
user token) and is the smaller, more auditable surface of the two.

**The honest gap**: the pinned/unmodified upstream `lore-server` binary this
project integrates against does not send `REBAC_SERVICE_TOKEN` (or any
credential) on this hop today, because it has no config surface to do so.
Setting this variable is therefore a real deployment requirement, not a
config flip you do in isolation: something on the network path between
`lore-server` and this service's gRPC port has to attach the header --
typically a sidecar or reverse proxy the operator controls, since
`lore-server`'s own `auth_url` does not have to point directly at this
service's raw listener. Making `lore-server` itself send this header is a
change to a different repository (`epic-lore`), out of scope for this
project. See `docs/open-questions.md` Q6 for the full writeup.
