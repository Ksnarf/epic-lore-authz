# Vendored protos: provenance

These two proto files are vendored verbatim (byte-for-byte, no edits) from the
upstream open source project they define the contract for. We do not depend on
the upstream crate that owns them; we compile our own server implementation
from these copies. See docs/protocol-notes.md and docs/architecture.md for why.

## Source

- Upstream repo: `EpicGames/lore` (github.com/EpicGames/lore)
- Pinned commit: `f205899adf24b13b2d28e5c08d9256ac99c69f0c`
- Vendored on: 2026-08-03

## Files

| Vendored file        | Upstream path                              | SHA256 (this copy)                                              |
|-----------------------|---------------------------------------------|------------------------------------------------------------------|
| `auth_api.proto`      | `lore-proto/proto/auth_api.proto`           | `9c155eef922998aa75a402cd0353f9d0704561eba772fe8297c67083d33d02aa` |
| `rebac_api.proto`     | `lore-proto/proto/rebac_api.proto`          | `d848bd840a052e0e311941ecf7ca5de54d403ace5f9b571f82b6b68972a93793` |

Hashes are recorded in `SHA256SUMS` in this directory and are recomputed and
checked by `.github/workflows/proto-drift.yml` on a schedule and can be
recomputed locally with:

```powershell
Get-FileHash -Algorithm SHA256 proto\vendor\auth_api.proto, proto\vendor\rebac_api.proto
```

Neither file has an `import` statement (checked in the pinned commit), so no
other upstream proto (e.g. `environment.proto`, `model.proto`) needs to be
vendored alongside them. If a future upstream revision adds an import to
either file, that import's target must be vendored too and this file updated.

## License and attribution

Both files are part of the `EpicGames/lore` repository, which is licensed MIT.
Upstream `LICENSE` (verbatim):

```
MIT License

Copyright (c) 2026 Epic Games, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.
```

This repository (`epic-lore-authz`) is a separate, independently maintained
project. It is not affiliated with or endorsed by Epic Games, Inc. It exists
because the upstream `lore-server` compiles `auth_api.proto` and
`rebac_api.proto` with `.build_server(false)` (see `lore-proto/build.rs`),
i.e. upstream ships only the gRPC *client* stubs for these two services and
does not open source a server implementation of them. This project vendors
the two proto files under the terms above and generates a server
implementation against them.

## Drift policy

`.github/workflows/proto-drift.yml` runs on a schedule and:
1. Fetches these two files from upstream at the pinned commit and fails the
   build if they no longer match `SHA256SUMS` (this would mean our local copy
   was edited by mistake, or the pin needs updating).
2. Fetches the same two files from upstream `main` and warns (does not fail)
   if they differ from our pinned copies, so a human can review and decide
   whether to re-vendor.
