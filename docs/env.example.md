# Canonical `.env.example` content (root `.env.example` is stale)

**Why this file exists:** the repo-root `.env.example` is missing six
config keys added in Phase 1b and in the admin-surface work (`TOKEN_IDP`,
`AUTH_SESSION_TTL_SECS`, `PUBLIC_BASE_URL`, `OIDC_SCOPES`,
`OIDC_JIT_PROVISIONING`, `ADMIN_API_TOKEN`) and it also still carries one
factually wrong line about `REBAC_SERVICE_TOKEN` (it says lore-server
"sends no bearer token of its own", which `docs/configuration.md`'s own
`REBAC_SERVICE_TOKEN` section already corrects: lore-server DOES forward
the end user's own bearer token on that hop -- the defect was the
credential KIND, not its absence). Repeated attempts to edit the real
`.env.example` in place are refused by an editing-tool guardrail that
blocks all writes to any `.env*` path, including this placeholders-only
template, so the corrected, complete content is captured here instead
until an operator with write access to that path applies it directly.
`docs/configuration.md` is unaffected by this gap -- it already documents
every one of the six keys below with its default and its fail-closed
behavior; this page exists only to fix the copy-pasteable template file
itself.

Every value below is a PLACEHOLDER, exactly like the file it replaces.
This content is safe to commit as-is; do not fill in a real value
anywhere on this page.

```env
# epic-lore-authz configuration surface.
#
# Every value below is a PLACEHOLDER. This file is safe to commit; a real
# .env with real values is not (see .gitignore) and must never be committed.
# Copy this file to .env and fill in real values for local development, or
# set these as real environment variables / secrets in your deployment.
#
# See docs/configuration.md for the long-form explanation of each setting,
# and docs/protocol-notes.md before touching JWT_ISSUER / JWT_AUDIENCE --
# they interact with lore-server's own auth.jwt_issuer / auth.jwt_audience
# config and with client-side checks the lore CLI performs independently.

# --- Database -------------------------------------------------------------
# The backend is selected at runtime from this URL's own scheme -- see
# docs/configuration.md's "Choosing a database backend" section before
# picking SQLite for anything but local dev:
#
#   postgres://... or postgresql://...  -> Postgres. Required for any
#     multi-replica deployment (behind a load balancer). This product owns
#     exactly ONE schema inside whatever database it is pointed at (see
#     DB_SCHEMA below) -- it never CREATEs a database, never requires
#     superuser, and never touches the `public` schema.
#
#   sqlite://path/to/file.db (or sqlite::memory: for a throwaway one) ->
#     SQLite. DEV / SINGLE-INSTANCE ONLY: SQLite's single-writer file lock
#     makes it the wrong choice behind a load balancer. DB_SCHEMA (below)
#     has NO EFFECT under this backend -- SQLite has no schema concept; see
#     docs/configuration.md.
#
# Example below is Postgres; swap for a sqlite: URL for local dev if you
# want to skip standing up Postgres entirely.
DATABASE_URL=postgres://CHANGE_ME:CHANGE_ME@localhost:5432/CHANGE_ME
DB_SCHEMA=loreauth

# --- JWT issuer / audience ------------------------------------------------
# JWT_ISSUER: the `iss` claim on every token this service mints.
JWT_ISSUER=https://authz.example.com
# JWT_AUDIENCE: comma-separated list of ROOT DOMAINS, not opaque audience
# strings. Per the lore client contract, `aud` must contain the root domain
# of the lore SERVER this token will be presented to (e.g. lore.example.com),
# because the lore CLI validates this itself before ever storing the token,
# independently of what lore-server's own auth.jwt_audience accepts.
JWT_AUDIENCE=lore.example.com

# TOKEN_ENV: value placed in the `env` claim of every minted token (e.g.
# dev/staging/prod). Required by lore-server on BOTH the AuthZ and AuthN
# claim shapes -- omitting it fails both decode attempts loudly. See
# docs/protocol-notes.md section 2.
TOKEN_ENV=dev

# TOKEN_IDP: `idp` claim fallback for principals with no recorded identity
# provider (the manual/test provisioning path -- Principal.idp unset).
# MUST NOT be empty -- the process refuses to start if it is. An AuthZ
# token with an empty or absent `idp` is ACCEPTED by lore-server and then
# silently stripped of its `resources` claim, surfacing as a permissions
# bug rather than a claims error. Principals provisioned through OIDC
# record their own `idp` and ignore this setting. See
# docs/protocol-notes.md section 2 and docs/open-questions.md Q13.
TOKEN_IDP=local

AUTHN_TOKEN_TTL_SECS=36000
AUTHZ_TOKEN_TTL_SECS=3600

# AUTH_SESSION_TTL_SECS: how long a browser login session
# (StartAuthSession -> GetAuthSession) stays usable. Default 300 (5m),
# deliberately double the lore CLI's own hard 150-second polling budget --
# see docs/configuration.md's "The 150-second client login deadline"
# section for why this matters for enterprise MFA / slow IdP consent
# screens. Do not lower below ~180: a session that expires INSIDE the
# CLI's own polling window turns a slow login into a silent failure.
AUTH_SESSION_TTL_SECS=300

# --- Signing keys ----------------------------------------------------------
# Where the active signing key material comes from. Phase 0: a file:// URL
# to an unencrypted PKCS#8 EC P-256 private key, PEM or raw DER. This is
# NOT a JWK: this project pinned jsonwebtoken crate can only represent
# PUBLIC keys as a JWK (see crates/lore-authz-server/src/signing.rs), so a
# private signing key cannot be loaded that way. If this file does not
# exist, an ephemeral EC key is generated in memory at startup instead (a
# clear warning is logged) -- fine for local dev, but every previously
# minted token stops validating on the next restart. Phase 1+: a real
# KMS/HSM-backed source.
SIGNING_KEY_SOURCE=file:///CHANGE_ME/signing-key.der

# --- JWKS --------------------------------------------------------------
# Path (on the HTTP listener below) this service serves its own JWKS
# document on. Point lore-server's auth.jwk.endpoint at
# http(s)://<this-host>:<HTTP port><JWKS_PATH>.
JWKS_PATH=/.well-known/jwks.json

# --- Public origin (login URLs + admin panel CSRF gate) -------------------
# PUBLIC_BASE_URL: the origin this service is reachable at IN A BROWSER
# (scheme + host + optional port, no path), e.g. https://authz.example.com.
# StartAuthSession builds the login_url it hands the CLI as
# <PUBLIC_BASE_URL>/login/<login_code>, and the admin surface's
# same-origin (CSRF) gate compares every state-changing /admin request's
# Origin/Referer against it -- see docs/configuration.md's "Same-origin
# enforcement" section.
#
# UNSET means StartAuthSession denies with Status::failed_precondition
# (no login URL that goes nowhere), AND every /admin/ui form POST is
# refused with 403 (nothing to compare against) -- the header-only
# /admin/v1 JSON API is unaffected. A startup warning names both
# consequences. If unset, this falls back to the origin of
# OIDC_REDIRECT_URL, usually the same host.
#
# Behind a reverse proxy this must be the origin the OPERATOR's browser
# sees (the proxy's), never this process's own listen address.
PUBLIC_BASE_URL=https://authz.example.com

# --- RebacApi caller identity (security review remediation) --------------
# Shared secret gating RebacApi::CreateResource/DeleteResource (see
# docs/configuration.md and docs/open-questions.md Q6). This is NOT a user
# token: lore-server is the caller on this hop, not an end user, and has no
# principals row of its own to resolve to -- so a shared secret gates it
# instead of the same bearer-JWT check LookupUserPermissions/
# CheckUserPermission use. See crates/lore-authz-server/src/service_auth.rs
# for the mechanism. Present as `authorization: Bearer <this value>` on
# those two RPCs.
#
# FAIL CLOSED: if this is unset, both RPCs deny EVERY caller. That is
# deliberate, not a bug -- an unconfigured gate defaulting to allow would
# reproduce the exact vulnerability this setting closes. See
# docs/open-questions.md Q6 for the full writeup, including the honest
# caveat that a stock, unpatched lore-server forwards the calling user's
# own bearer token on this hop rather than a service credential (a real
# credential, just the wrong kind) and has no config surface to send this
# value instead -- something on the network path (a patched lore-server
# build, a sidecar, or a reverse proxy) must attach it for this setting to
# do anything.
REBAC_SERVICE_TOKEN=CHANGE_ME

# --- Listeners -----------------------------------------------------------
# gRPC: UrcAuthApi + RebacApi. The lore CLI rewrites any scheme to https
# before dialing, so any real deployment must terminate TLS here with a
# certificate the CLI's native root store trusts.
GRPC_LISTEN_ADDR=0.0.0.0:8443
# HTTP: JWKS, login, OIDC/SAML callbacks, health, metrics, and (since the
# admin surface shipped) /admin/v1 + /admin/ui.
HTTP_LISTEN_ADDR=0.0.0.0:8080

# --- OIDC provider (single-tenant local dev / minimal bring-up) -----------
# Real multi-IdP deployments configure idp_connections in the database
# (Phase 1). These env vars are for local dev and the smallest possible
# single-IdP bring-up.
OIDC_ISSUER_URL=https://idp.example.com/
OIDC_CLIENT_ID=CHANGE_ME
OIDC_CLIENT_SECRET=CHANGE_ME
OIDC_REDIRECT_URL=https://authz.example.com/oidc/callback

# OIDC_SCOPES: space-separated. `openid` is added automatically if you
# leave it out. Default shown below.
OIDC_SCOPES=openid profile email

# OIDC_JIT_PROVISIONING: create a principal on first login for an identity
# that has none. Safe as a default because it creates an IDENTITY, never
# an AUTHORIZATION -- a just-provisioned principal holds no role bindings,
# so its AuthZ token's `resources` claim is empty and it can see nothing
# until an operator grants it something. Set false for a closed deployment
# where every principal is pre-provisioned. Accepts
# true/false/1/0/yes/no/on/off; anything else is a startup failure, not a
# silent default. Default true.
OIDC_JIT_PROVISIONING=true

# --- SAML SP (Phase 2, behind the `saml` cargo feature) -------------------
SAML_SP_ENTITY_ID=https://authz.example.com/saml/metadata
SAML_IDP_METADATA_URL=https://idp.example.com/saml/metadata

# --- Admin surface (provisioning API + HTML panel) ------------------------
# ADMIN_API_TOKEN: shared secret gating the ENTIRE admin surface -- the
# /admin/v1 JSON provisioning API and the /admin/ui HTML panel, both on
# the HTTP listener above. Present as `authorization: Bearer <value>`; a
# static secret, not a JWT.
#
# TREAT THIS AS A ROOT CREDENTIAL: a caller holding it can create a
# principal and bind it to `urc-*` with the built-in `admin` role --
# authority over EVERY repository this deployment knows about. There is
# no narrower scope this token can be issued with. Generate a high-entropy
# value (e.g. `openssl rand -base64 32`), store it with your other
# deployment secrets, and rotate it by changing this setting and
# restarting.
#
# FAIL CLOSED, NO BYPASS: unset (or empty) means every /admin request is
# denied with 401, including one presenting a token, and including paths
# that do not exist -- there is no development mode and no insecure flag.
# See docs/configuration.md's "ADMIN_API_TOKEN: the admin surface, and how
# to expose it safely" section before setting this, including the
# same-origin (CSRF) rule that also gates every state-changing /admin
# request via PUBLIC_BASE_URL above.
ADMIN_API_TOKEN=CHANGE_ME

# --- Logging -------------------------------------------------------------
RUST_LOG=info
```
