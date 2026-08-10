# epic-lore-authz demo

A complete, self-contained stack you can start in one command and then verify
for yourself: this project's authorization sidecar, a mock identity provider,
Postgres, an unmodified-except-for-one-patch `lore-server`, and a reverse
proxy in front of the admin panel.

Everything it runs is either a published release artifact of this project or a
stock upstream image. Nothing is built from source, and nothing here needs a
Rust toolchain.

## What this is NOT

Read this part first.

- **Not a production deployment, and not a template for one.** Plaintext HTTP
  everywhere, no TLS, no network restriction on the admin path, a database
  with a published password, and an authorization service whose signing key is
  regenerated on every restart.
- **Every credential in this directory is a committed, deliberately non-secret
  dev value**, and each one says so in its own name:
  `demo-admin-token-not-a-real-secret`, `demo-rebac-service-token-not-a-real-secret`,
  `demo-oidc-client-secret-not-a-real-secret`,
  `demo-postgres-password-not-a-real-secret`. They exist so a reader can never
  mistake one for a real value. Never copy one into anything.
- **No key material is committed anywhere in this directory.** The sidecar is
  pointed at a signing-key path that deliberately does not exist, so it
  generates an ephemeral P-256 key in memory at startup and logs a warning
  saying exactly that. Restarting the sidecar invalidates every token it has
  minted, which is fine for a demo and unacceptable anywhere else.
- **The only user is a mock.** The identity provider is Dex with its built-in
  `mockCallback` connector: one fixed test identity, no password, no account
  anywhere.
- `docs/configuration.md` is what a real deployment follows. This directory
  mirrors its deployment shape, not its security posture.

## Requirements

- Docker with Compose v2 (`docker compose version`).
- Network access on first run: the image builds download the release binaries
  from GitHub and two upstream proto files. Both downloads are verified
  against checksums committed in `release/`; a mismatch fails the build.
- About 1 GB of disk for the images.
- The release binaries are `linux/amd64`. On an arm64 host (Apple Silicon)
  they run under emulation, which works but is slower.

## Start it

```sh
cd demo
./demo.sh            # or: .\demo.ps1 on Windows PowerShell
```

That builds the images, starts the stack, waits for it to be healthy, and then
runs the verification script. The same thing by hand:

```sh
docker compose up -d --build --wait
docker compose exec -T tools sh /scripts/verify.sh
```

Every host port is a variable, so nothing has to collide with what you already
run:

```sh
DEMO_PANEL_PORT=18081 DEMO_DEX_PORT=15556 DEMO_AUTHZ_HTTP_PORT=18082 \
DEMO_AUTHZ_GRPC_PORT=18443 DEMO_LORE_GRPC_PORT=41437 \
DEMO_LORE_HTTP_PORT=41439 DEMO_POSTGRES_PORT=15432 \
./demo.sh
```

Everything derived from those ports (the token issuer, the OIDC redirect URL,
the same-origin rule, Dex's issuer, lore-server's expected issuer) follows
automatically.

## What to open in a browser

| URL | What it is |
| --- | --- |
| `http://localhost:8080/admin/ui` | The admin panel: principals, groups, resources, roles, grants, with forms that create and revoke live. |
| `http://localhost:8080/.well-known/jwks.json` | The public signing key the sidecar minted at startup. |
| `http://localhost:18080/admin/ui` | The SAME panel path on the sidecar's own port, with no proxy: `401`. This is the product's default. |
| `http://localhost:5556/dex/.well-known/openid-configuration` | The mock identity provider. |

(Substitute your own ports if you overrode them.)

Try this, because it is the whole point: run the verify script, then open the
panel, revoke the grant it created, and run the verify script again. The
deny-then-allow section flips back to denied.

## Why there is a proxy in front of the panel

Every `/admin` route is gated on `authorization: Bearer <ADMIN_API_TOKEN>`.
**A browser cannot attach that header to an address-bar navigation**, and this
project deliberately does not add a cookie or a login form to the admin
surface -- a second, weaker credential path into a surface that can mint
authority is not worth saving a line of proxy config. So the documented
deployment model (`docs/configuration.md`, "Reaching the panel from a
browser") is a reverse proxy that restricts the `/admin` path and injects the
token for callers already inside that restriction. The `panel` service here is
exactly that proxy, minus the restriction, because this is a demo on a
throwaway network.

That is also why `PUBLIC_BASE_URL` exists and why the demo runs a same-origin
check. Once a proxy injects the token, the credential is no longer something
the caller holds -- it is something the caller's network position earns. That
is ambient authority, CSRF-able exactly like a cookie: an operator inside the
allowlist visiting a hostile page is one auto-submitting `<form>` away from
that page creating an `admin` grant in their name. So every state-changing
`/admin` request must additionally be same-origin with `PUBLIC_BASE_URL`. The
verify script demonstrates both halves of that: an identical form POST is
refused cross-origin and accepted same-origin.

The sidecar's own port is published too (`18080` by default) with no proxy in
front of it, so you can see the un-proxied behaviour: fail-closed, present the
bearer yourself.

## What the verify script proves

`scripts/verify.sh` runs inside the stack's own network and prints a numbered
CLAIM, the raw output that decides it, and a `[PASS]`/`[FAIL]` line for each.
It exits non-zero if any claim fails, and it is re-runnable.

| Claim | What it proves |
| --- | --- |
| 1 | The sidecar serves a JWKS carrying a `kid` and `alg: ES256`, from a key it generated at startup (none is shipped). |
| 2 | `lore-server` loaded its config with auth ENABLED: this sidecar's JWKS endpoint, issuer, audience, and the service credential for the rebac hop. |
| 3 | The admin gate: unauthenticated on the raw sidecar port is `401`; the same request with the bearer, or through the injecting proxy, is `200`. |
| 4 | Before any grant, `CheckUserPermission` **DENIES**. Logging in creates an identity, never an authorization. |
| 5 | The admin API provisions: create a principal, register a resource, list the seeded roles. |
| 6 | The CSRF gate: an identical form POST is `403` cross-origin and `303` same-origin. The same-origin one creates the grant. |
| 7 | After the grant, the SAME call with the SAME token **ALLOWS**, and names the permissions. |
| 8 | `lore-server` rejects an unauthenticated gRPC call (`Unauthenticated`) and serves one carrying a token this service minted. |

Between claims 4 and 7 nothing changes except the grant, and the token is not
re-minted -- that is what makes the pair meaningful rather than two unrelated
calls.

## How it is put together

| File | What it does |
| --- | --- |
| `docker-compose.yml` | The whole stack. Every credential, port and URL is defined here, once. |
| `Dockerfile.runtime` | Downloads the `lore-authz-server` and `loreserver` binaries from a published release and verifies them against `release/SHA256SUMS`. |
| `Dockerfile.tools` | `curl` + `jq` + `grpcurl`, plus the two lore protos fetched at the pinned upstream commit and checksum-verified. |
| `dex/config.yaml.template` | Mock identity provider. Rendered at start because Dex does not expand environment variables in its own config. |
| `panel/nginx` template | The token-injecting reverse proxy described above. Rendered by the nginx image's own `envsubst` step. |
| `lore-config/local.toml.template` | lore-server's config. Rendered at start so the issuer and service token are defined in one place and cannot drift. |
| `scripts/verify.sh` | The verification above. |
| `release/` | Pinned checksums, and where they came from. No secrets, no key material. |

The two protos the demo speaks to the SIDECAR with are the ones this
repository already vendors, bind-mounted straight from `proto/vendor/` -- not
a second copy. See `proto/vendor/UPSTREAM.md` for their provenance.

The protos LORE-SERVER speaks are not part of this repository and are not
vendored here. `Dockerfile.tools` fetches the two that are needed from
`EpicGames/lore` at the same pinned commit `proto/vendor/UPSTREAM.md` records
(which is also the commit the released `loreserver` binary is built from), and
verifies them against `release/lore-protos.sha256`. **This means the demo
cannot be built with no network access**, and it is why the demo does not
redistribute those files.

## Moving the demo to a newer release

The binaries come from a published release on purpose: the demo runs the same
bytes the project ships, not a local build. To move to a later release, change
`LORE_AUTHZ_RELEASE` in `docker-compose.yml` and replace
`release/SHA256SUMS` with that release's own `SHA256SUMS` asset. If they
disagree, the image build fails rather than running unverified bytes.

## Linux note

An OIDC issuer has to be ONE string that resolves both inside the containers
and in the browser on your host, which is what `host.docker.internal` is for.
The containers get it from Compose (`extra_hosts: host-gateway`) on every
platform, so `./demo.sh` and the verify script work as-is on Linux.

A browser on a Linux host does not resolve that name by default. Everything
above still works except manually walking the login flow in a browser; for
that, add `127.0.0.1  host.docker.internal` to `/etc/hosts`.

## Logs

```sh
docker compose logs -f authz        # the authorization service
docker compose logs -f loreserver
docker compose logs -f dex
docker compose logs -f panel
docker compose logs -f postgres
```

The sidecar's startup log is worth reading once: it names the signing key it
generated, and states that the admin surface is enabled and same-origin
enforced.

## Tear it down

```sh
docker compose down -v
```

`-v` removes the Postgres volume, lore-server's data volume and the captured
startup log, so the next start is a genuinely clean one.
