#!/usr/bin/env bash
# Build and start the honeypot container. data/ must be writable by the container user (uid 10001).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data && sudo chown -R 10001 data
sudo docker compose -p genno -f deploy/docker-compose.yml up -d --build
sleep 1; sudo docker compose -p genno logs --tail 5
