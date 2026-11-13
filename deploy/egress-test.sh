#!/usr/bin/env bash
# Evidence for the README: outbound works without rules (control), is blocked with them.
cd "$(dirname "$0")/.."
C="sudo docker compose -p genno -f deploy/docker-compose.yml exec -T genno"
EG="import urllib.request as u;print(u.urlopen('http://1.1.1.1',timeout=5).status)"
sudo nft delete table inet genno 2>/dev/null
echo "== control (no rules): expect a status code"
$C python -c "$EG" 2>&1 | tail -1 || true
sudo nft -f deploy/nftables.rules
echo "== with rules: expect timeout"
$C python -c "$EG" 2>&1 | tail -1
echo "== drop counter"
sudo nft list ruleset | grep -A1 genno-egress
echo "== inbound still works"
timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2222; head -c 40 <&3'; echo
