# Start the demo and prove it works, in one command.
#
#   .\demo.ps1
#
# Override any host port that collides with something you already run:
#
#   $env:DEMO_PANEL_PORT = "18081"; .\demo.ps1
#
# Tear down with:  docker compose down -v   (from this directory)
$ErrorActionPreference = "Stop"

Set-Location -Path $PSScriptRoot

Write-Output "==> building images and starting the stack"
docker compose up -d --build --wait
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed with exit code $LASTEXITCODE" }

Write-Output ""
Write-Output "==> running the verification script inside the demo network"
docker compose exec -T tools sh /scripts/verify.sh
if ($LASTEXITCODE -ne 0) { throw "verification failed with exit code $LASTEXITCODE" }
