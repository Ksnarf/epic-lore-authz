# Pinned checksums used by the demo build

Nothing in this directory is a secret and nothing here is key material. These
are integrity pins, committed so that a fresh clone downloads exactly the
bytes this demo was tested against, and fails the image build if it does not.

## `SHA256SUMS`

The `SHA256SUMS` asset of the `v0.2.0` epic-lore-authz release, committed
verbatim. It covers the two binaries `Dockerfile.runtime` downloads:

- `lore-authz-server-linux-amd64` -- this repository's sidecar.
- `loreserver-linux-amd64` -- a PATCHED build of Epic's `lore-server` (see the
  release notes and `.github/workflows/release.yml`; it is not an official
  Epic build).

To move the demo to a later release: change `LORE_AUTHZ_RELEASE` in
`demo/docker-compose.yml` and replace this file with that release's own
`SHA256SUMS` asset.

## `lore-protos.sha256`

SHA-256 of the two upstream `EpicGames/lore` proto files `Dockerfile.tools`
downloads so `grpcurl` can call `lore-server`, taken at commit
`f205899adf24b13b2d28e5c08d9256ac99c69f0c` -- the same commit
`proto/vendor/UPSTREAM.md` pins, and the commit the released `loreserver`
binary was built from. Paths are relative to the image's `/loreprotos`.

These two files are NOT vendored into this repository. They are fetched at
image-build time and verified against these hashes.
