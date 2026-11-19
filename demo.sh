#!/usr/bin/env bash
# One-shot demo: server (host-run, with allowlisted creds) -> simulated attackers -> classify -> cluster.
set -euo pipefail
cd "$(dirname "$0")"
PORT=${PORT:-2299}; D=data/demo
rm -rf "$D"; mkdir -p "$D" reports
python -m genno.ssh.server --host 0.0.0.0 --port "$PORT" --log "$D/events.jsonl" --key "$D/host_key" \
  --allow root:123456 --allow admin:admin123 --allow ubuntu:ubuntu >"$D/server.out" 2>&1 &
SRV=$!; trap 'kill $SRV 2>/dev/null || true' EXIT
for _ in $(seq 30); do grep -q listening "$D/server.out" 2>/dev/null && break; sleep 0.2; done
grep -q listening "$D/server.out" || { echo "server failed to start:"; cat "$D/server.out"; exit 1; }
python -m tools.simulate --port "$PORT" --scale 0.3 --truth "$D/sim_truth.json"
python -m analysis.run --log "$D/events.jsonl" --db "$D/genno.db" --truth "$D/sim_truth.json" --human-gap 0.3 --layer reports/attack-layer.json
echo; echo "== clustering"; python -m analysis.cluster --db "$D/genno.db"
