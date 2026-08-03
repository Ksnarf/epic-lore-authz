# Build/check/test/lint epic-lore-authz inside the pinned Docker image
# (docker/Dockerfile.build), so nobody needs a local Rust toolchain or protoc.
#
# Usage:
#   .\scripts\build.ps1                                     # cargo check --workspace (default)
#   .\scripts\build.ps1 cargo build --workspace
#   .\scripts\build.ps1 cargo fmt --all -- --check
#   .\scripts\build.ps1 cargo clippy --workspace --all-targets -- -D warnings
#
# Run from anywhere; the repo root is resolved relative to this script, not
# the caller's current directory. Requires Docker Desktop / a working Docker
# daemon reachable from PowerShell.

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoArgs
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$imageTag = "epic-lore-authz-build:local"

docker build -f (Join-Path $repoRoot "docker/Dockerfile.build") -t $imageTag $repoRoot
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not $CargoArgs -or $CargoArgs.Count -eq 0) {
    $CargoArgs = @("cargo", "check", "--workspace")
}

docker run --rm -v "${repoRoot}:/work" -w /work $imageTag @CargoArgs
exit $LASTEXITCODE
