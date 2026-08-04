# epic-lore-authz

An enterprise SSO / authorization sidecar for
[`EpicGames/lore`](https://github.com/EpicGames/lore) (Epic's open source
version control system).

## What this is

`lore-server` and the `lore` CLI already implement a complete enterprise-auth
**client**: browser SSO login, service-account token exchange, and
per-repository authorization checks on every RPC. The two proto files that
define that contract (`auth_api.proto`, `rebac_api.proto`) are MIT licensed
and public. What is not public is a **server** implementation of them --
upstream's own build (`lore-proto/build.rs`) compiles both with
`.build_server(false)`, i.e. it generates gRPC client stubs only, because
Epic's own auth service is closed source.

epic-lore-authz vendors those two proto files (see `proto/vendor/`,
provenance in `proto/vendor/UPSTREAM.md`) and compiles them with
`.build_server(true)` to provide a real, open source server implementation:
a single sidecar binary that speaks OIDC and SAML to a real enterprise
identity provider, so an **unmodified** `lore-server` and **unmodified**
`lore` CLI can be pointed at real SSO.

See `docs/architecture.md` for the full design, and `docs/protocol-notes.md`
before touching anything claim- or JWKS-shaped -- the claim contract has
several gotchas that fail silently rather than loudly.

## What this is NOT

- Not a fork or a patch of `lore-server` or the `lore` CLI. Both are used
  unmodified; this project only implements the server side of a contract
  they already speak.
- Not affiliated with or endorsed by Epic Games, Inc.
- Not a fine-grained permission enforcement layer. `lore-server`'s own
  authorization check only checks repository membership, never a
  permission string (see `docs/protocol-notes.md`). This project does not
  promise enforcement `lore-server` itself does not perform.
- Not (yet) a finished product. See `tasks.md` -- this repository is
  currently a **scaffold**: structure, contracts, config surface, CI, and
  stubbed handlers. Every RPC and HTTP handler beyond health/readiness
  currently returns "not implemented."

## License and attribution

This project is licensed MIT (see `LICENSE`, Copyright (c) 2026 Ksnarf).

`proto/vendor/auth_api.proto` and `proto/vendor/rebac_api.proto` are vendored
verbatim from `EpicGames/lore` (also MIT licensed, Copyright (c) 2026 Epic
Games, Inc.) at the pinned commit `f205899adf24b13b2d28e5c08d9256ac99c69f0c`.
Full attribution and license text: `proto/vendor/UPSTREAM.md`.

## Quickstart (placeholder -- Phase 0 in progress, see tasks.md)

Prerequisites: a Rust stable toolchain (`rustup`), and `protoc` on `PATH` or
pointed to via the `PROTOC` env var (required at build time to generate the
gRPC server code from the vendored protos -- see
`crates/lore-authz-proto/build.rs`).

```sh
git clone https://github.com/Ksnarf/epic-lore-authz.git
cd epic-lore-authz
cp .env.example .env   # then fill in real values -- see docs/configuration.md
cargo build --workspace
```

Running the binary (once Phase 0 lands -- see `tasks.md`):

```sh
cargo run -p lore-authz-server
```

Then point an unmodified `lore-server` at it:
- `auth.jwk.endpoint` -> `http(s)://<this-host>:<HTTP_LISTEN_ADDR port><JWKS_PATH>`
- `environment.endpoint.auth_url` -> `https://<this-host>:<GRPC_LISTEN_ADDR port>`
  (see `docs/open-questions.md` Q2 -- the exact config key is unconfirmed)
- `auth.jwt_issuer` / `auth.jwt_audience` -> matching `JWT_ISSUER` /
  `JWT_AUDIENCE` in this project's config (see `docs/configuration.md`)

## Repository layout

```
epic-lore-authz/
  Cargo.toml                    workspace
  proto/vendor/                 vendored auth_api.proto + rebac_api.proto, provenance, hashes
  crates/
    lore-authz-proto/           tonic-build with build_server(true) -- the crux of the project
    lore-authz-core/            domain types + I/O-free traits, no business logic implemented yet
    lore-authz-server/          the binary: gRPC + HTTP listeners, config, stubbed RPC handlers
  docs/                         architecture, protocol gotchas, open questions, config reference
  .github/workflows/            ci.yml (fmt/build/test/clippy), proto-drift.yml (upstream drift guard)
  tasks.md                      phased delivery plan with pass/fail proof criteria per phase
```

## Status

Scaffold only. See `tasks.md` for the phased delivery plan and current
status of each phase.
