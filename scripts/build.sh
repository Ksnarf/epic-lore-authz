#!/bin/sh
# Build/check/test/lint epic-lore-authz inside the pinned Docker image
# (docker/Dockerfile.build), so nobody needs a local Rust toolchain or protoc.
#
# Usage:
#   scripts/build.sh                      # cargo check --workspace (default)
#   scripts/build.sh cargo build --workspace
#   scripts/build.sh cargo fmt --all -- --check
#   scripts/build.sh cargo clippy --workspace --all-targets -- -D warnings
#
# Run from anywhere; the repo root is resolved relative to this script, not
# the caller's current directory.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
image_tag="epic-lore-authz-build:local"

docker build -f "$repo_root/docker/Dockerfile.build" -t "$image_tag" "$repo_root"

if [ "$#" -eq 0 ]; then
    set -- cargo check --workspace
fi

exec docker run --rm -v "$repo_root:/work" -w /work "$image_tag" "$@"
