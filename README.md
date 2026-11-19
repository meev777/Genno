# Genno

A medium-interaction SSH honeypot written from scratch in Python, with a telemetry pipeline, a rule-based session classifier, MITRE ATT&CK mapping and unsupervised clustering.

Genno does not wrap an existing honeypot. The protocol handling, the shell emulation, the filesystem, the containment and the analysis are all implemented here. The goal was to understand how deception systems work, where they leak, and how to turn raw attacker activity into intelligence.

![python](https://img.shields.io/badge/python-3.12%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![tests](https://img.shields.io/badge/tests-43%20passing-brightgreen)

> **Research and educational use only.** Run it on an isolated machine you own. See [Safety and legal](#safety-and-legal).

## What it does

```
 attacker ──ssh──▶ asyncssh server ──▶ emulated bash ──▶ per-connection copy-on-write VFS
                        │                    │                    (nothing real is ever executed)
                        └──── events (JSONL) ◀┘
                                  │
                       ingest ──▶ SQLite (events, sessions)
                                  │
              rule classifier ──▶ labels + reasons ──▶ ATT&CK mapping ──▶ Navigator layer
                                  └─▶ TF-IDF + DBSCAN clustering (unsupervised cross-check)
```

- **SSH engine** (`asyncssh`): spoofed OpenSSH banner, logs every password attempt, and a policy decides when to let the attacker in (an allowlist, or after N failed attempts on a connection).
- **Emulated shell**: a hand-written bash-subset parser (quotes, escapes, `$VAR`, `~`, `; && || |`, redirects `> >> < 2>/dev/null 2>&1`) feeding 25+ emulated commands (`ls cd cat echo grep wc head tail uname id ps free uptime wget curl chmod rm mkdir ...`), plus `sh`/`bash -c`/`./script` so dropper scripts actually "run" inside the emulator and their downloads get logged.
- **Virtual filesystem**: a shared read-only base tree loaded from a YAML persona (`genno/profiles/ubuntu-web.yaml`) plus a copy-on-write overlay per SSH connection. Paths are normalized lexically and clamp at `/`, so traversal cannot leave the virtual tree. Size, node-count and total-bytes caps apply.
- **Downloads are logged, never fetched.** `wget`/`curl` record the URL and fail with the same resolver error a real host without internet access would give, which also matches the egress-blocked container.
- **Telemetry**: one flat JSON event per line, then ingested into SQLite with one summary row per session.
- **Analysis**: an explainable rule-based classifier, ATT&CK technique mapping with Navigator layer export, and a clustering layer that does not use the rules at all.

## Quick start

Requires Python 3.12+.

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
pytest -q                                   # 43 tests
./demo.sh                                   # simulated attackers -> classify -> cluster

python -m genno.ssh.server --port 2222      # run it yourself
ssh -p 2222 root@127.0.0.1                  # rejected 3 times, then accepted
```

Run it in a container with egress locked down (needs Docker and nftables, uses `sudo`):

```bash
./deploy/run.sh                             # build, fix data/ ownership, start
./deploy/egress-test.sh | tee docs/egress-evidence.txt
```

## Containment

A honeypot that can be abused to attack others is worse than no honeypot, so containment is part of the design and is tested rather than assumed.

| Control | Where |
|---|---|
| Nothing is executed: every command is emulated in-process, no subprocess is ever spawned | `genno/shell/` |
| Non-root user (uid 10001), read-only root filesystem, all capabilities dropped, `no-new-privileges`, pid/memory/cpu limits | `deploy/docker-compose.yml` |
| Egress default-deny on the honeypot subnet (pinned to `172.30.50.0/24`) | `deploy/nftables.rules` |
| Idle sessions are closed after 120 s; shell output is capped; script recursion is depth-limited | `genno/ssh/server.py`, `genno/shell/shell.py` |
| Attacker-controlled regexes (in the emulated `grep`) are guarded against catastrophic backtracking | `genno/shell/commands.py` |
| A failing log disk never breaks sessions; the error is reported once on stderr | `genno/telemetry/sink.py` |

**Egress test** (`deploy/egress-test.sh`): the same outbound request is made from inside the container twice. Without rules it succeeds (control). With the rules loaded it times out, the nftables drop counter increments, and inbound SSH keeps answering. The captured output is in `docs/egress-evidence.txt`.

## Data pipeline

Event types (all share `ts, event_type, session_id, src_ip, src_port, proto`):

| event_type | extra fields |
|---|---|
| `connect`, `disconnect` | `error` (disconnect) |
| `auth_attempt` | `username, password, success, attempt, client_version` |
| `shell_open` | `username, term` |
| `command` | `username, command, mode` (`shell` or `exec`) |
| `file_read` | `path` |
| `download_attempt` | `tool, url, args` |
| `exec_attempt` | `path` |

### Classifier

First matching rule wins, and every label carries the reasons that produced it.

| Label | Rule (summary) |
|---|---|
| `scanner` | connected, no auth attempt, no commands |
| `auth_probe` / `brute_force` | failed logins only; `brute_force` at 3+ failures in one connection, or when one IP produces 5+ one-guess sessions (Hydra-style) |
| `login_only` | logged in, ran nothing |
| `cryptominer` | miner keywords (`xmrig`, `stratum+`, ...) |
| `malware_dropper` | download tool or logged download URL |
| `persistence` | `authorized_keys`, cron, `useradd`, ... |
| `human` | interactive shell and median gap between commands above a threshold |
| `recon_bot` | only discovery commands (`uname`, `cat /proc/...`, `ps`, `id`, ...) |
| `post_login_other` | anything else |

Command lines are split with Genno's own parser, so a quoted `;` or `|` is not mistaken for an operator.

### ATT&CK

About 20 techniques are mapped from behaviour (for example T1110.001 password guessing, T1078 valid accounts, T1105 ingress tool transfer, T1082 system information discovery, T1098.004 SSH authorized keys, T1496 resource hijacking). `analysis.run` exports an ATT&CK Navigator layer to `reports/attack-layer.json`. Check IDs against attack.mitre.org before reusing them, since the matrix changes between releases.

### Clustering

Each session's commands are normalized (URLs, IPs and numbers abstracted so only behaviour remains), turned into word 1-3-grams, TF-IDF weighted and clustered with DBSCAN on cosine distance. There is no `k` to guess, and sessions that fit no cluster are reported as noise. Sessions without commands (scanners, brute force) are excluded.

## Results

All numbers come from `./demo.sh`, which drives 24 simulated attackers (seed 1) from distinct loopback addresses against a host-run server.

| | |
|---|---|
| Sessions logged / logged in | 46 / 16 |
| Labels | brute_force 24, scanner 6, recon_bot 5, malware_dropper 5, cryptominer 2, persistence 2, human 2 |
| Rule classifier vs simulator ground truth | 46/46 |
| Clustering | 5 clusters, 2 noise, silhouette 0.937, no cluster mixes rule labels |
| Adjusted Rand index (clusters vs rule labels) | 0.821 |

How to read this:

- **The 100% is a pipeline check, not a measure of real-world accuracy.** The personas and the rules were written by the same author. The clustering result is the more informative one because it never sees the rules.
- The Rand index is below 1.0 because clustering **splits** the three recon-script variants into separate groups. It finds finer structure than the rule label records.
- These are simulated attackers only. The honeypot has not been exposed to the internet, so there are no real-world findings in this repository.

## Design notes

- **Medium interaction.** A low-interaction honeypot only logs banners. A high-interaction one gives the attacker a real OS, which is a containment risk. Emulating the shell is where the design work is.
- **Why a custom parser.** Real bots send one-line chains such as `cd /tmp; wget URL; chmod +x x; sh x; rm -f x`. Logging a command line is not enough; to see the second-stage behaviour the emulator has to parse and run the chain.
- **One filesystem per connection, not per channel.** Bots often run several `exec` commands on one connection and expect state (`echo x > /tmp/a`, then `cat /tmp/a`) to persist. Per-channel state was a fingerprinting tell found while building the simulators.
- **Consistent failure.** `./missing` gives `No such file or directory`, `wget` gives a resolver error, a non-root user is denied `/etc/shadow`. Each plausible-looking answer that is wrong is a fingerprint.
- **Honest error handling.** Emulator exceptions return an empty result instead of a traceback, and a logging failure never drops a session.

## Limitations and roadmap

Known gaps:

- No `$(...)`, backticks, globbing or heredocs; in `exec` mode stderr is merged into stdout.
- No SFTP/SCP, port forwarding or HTTP service. SSH only.
- No HASSH/JA3 fingerprinting, GeoIP enrichment or keystroke-level session recording. Per-command timestamps are the only timing data.
- No comparison against Cowrie, and the anti-fingerprinting detector tool is not built yet.
- No escape or fuzz testing yet. Containment is verified for egress, but the threat model's other paths (oversized input, malformed SSH packets, resource exhaustion) are listed in `docs/threat-model.md` and not yet attacked.
- Not deployed on the internet.

Planned next: `tools/honeypot_detector.py` with before/after fingerprint results, escape and fuzz tests with a hardening report, and a live run for real data.

## Repository layout

```
genno/
  ssh/server.py          SSH engine, auth policy, sessions
  shell/                 parser.py, vfs.py, commands.py, shell.py, profile.py
  profiles/              ubuntu-web.yaml (persona: banner, users, files, processes)
  telemetry/             sink.py (JSONL), ingest.py (SQLite)
analysis/                classifier.py, attack_map.py, cluster.py, run.py
tools/simulate.py        attacker personas + ground truth
deploy/                  Dockerfile, docker-compose.yml, nftables.rules, run.sh, egress-test.sh
docs/                    threat-model.md, egress-evidence.txt
tests/                   43 tests (parser, VFS, shell, SSH end to end, classifier, clustering)
demo.sh                  one-command demo
LICENSE                  MIT
```

## License

MIT, see [LICENSE](LICENSE).

## Safety and legal

- Run on a dedicated VM or a network segment you own, never on your main machine or home LAN.
- Keep egress blocked. Do not put real credentials, keys or data on the honeypot.
- Never execute captured payloads on a real system. Analyze them only in a separate sandbox.
- Check your network or hosting provider's terms before exposing a honeypot, and sanitize IP addresses before sharing datasets.
- For research and educational use only. The author accepts no responsibility for misuse.
