#!/bin/sh
# Start the demo and prove it works, in one command.
#
#   ./demo.sh
#
# Override any host port that collides with something you already run:
#
#   DEMO_PANEL_PORT=18081 DEMO_DEX_PORT=15556 ./demo.sh
#
# Tear down with:  docker compose down -v   (from this directory)
set -eu

cd "$(dirname "$0")"

echo "==> building images and starting the stack"
docker compose up -d --build --wait

echo
echo "==> running the verification script inside the demo network"
docker compose exec -T tools sh /scripts/verify.sh
