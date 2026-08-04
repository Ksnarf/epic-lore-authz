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
| `DATABASE_URL` | Phase 1+ | (none) | Standard Postgres connection string. Not read in the Phase 0 in-memory bring-up. |
| `DB_SCHEMA` | no | `loreauth` | This product owns exactly one schema; never `public`, never a dedicated database, never superuser. |
| `JWT_ISSUER` | yes | (none) | `iss` claim on every minted token. |
| `JWT_AUDIENCE` | yes | (none) | Comma-separated root domains. Must include the lore server's own root domain -- see `docs/protocol-notes.md` section 3. |
| `TOKEN_ENV` | no | `dev` | Value placed in the `env` claim of every minted token. Required by lore-server on both claim shapes -- see `docs/protocol-notes.md` section 2. |
| `AUTHN_TOKEN_TTL_SECS` | no | `36000` (10h) | AuthN token lifetime. |
| `AUTHZ_TOKEN_TTL_SECS` | no | `3600` (1h) | AuthZ token lifetime. Keep short: see the stateless-revocation-window note in `docs/protocol-notes.md`. |
| `SIGNING_KEY_SOURCE` | no | `file:///CHANGE_ME/signing-key.der` | Phase 0: a `file://` unencrypted PKCS#8 EC P-256 private key, PEM or raw DER (NOT a JWK -- see `crates/lore-authz-server/src/signing.rs`). If the file does not exist, an ephemeral dev key is generated in memory and a warning is logged. Phase 1+: real key management. |
| `JWKS_PATH` | no | `/.well-known/jwks.json` | Path on the HTTP listener to serve this service's own JWKS on. |
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
