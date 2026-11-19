"""Rule-based session classifier. First matching rule wins; every label carries its reasons.

Session-level labels: scanner, auth_probe, brute_force, login_only, cryptominer,
malware_dropper, persistence, human, recon_bot, post_login_other.
Campaign rule: an IP with many one-shot failed-auth sessions (Hydra-style: one guess per
connection) has those sessions relabeled brute_force.
"""
import re, statistics
from collections import Counter
from dataclasses import dataclass
from genno.shell.parser import parse, ParseError

MINER = re.compile(r"xmrig|minerd|cpuminer|stratum\+|kdevtmpfsi", re.I)
DROPPER = re.compile(r"\b(wget|curl|tftp|ftpget)\b")
PERSIST = re.compile(r"authorized_keys|crontab|/etc/cron|/etc/rc\.local|systemctl\s+enable|useradd|adduser|chattr")
RECON_BINS = {"uname", "cat", "grep", "egrep", "wc", "head", "tail", "free", "nproc", "ps", "id",
              "whoami", "uptime", "hostname", "lscpu", "w", "who", "ls", "pwd", "echo", "which", "df"}


@dataclass
class Thresholds:
    human_gap: float = 1.0        # median seconds between commands in an interactive shell
    brute_attempts: int = 3       # failed auths inside one session
    brute_ip_sessions: int = 5    # one-shot failed-auth sessions from one IP


def simple_commands(cmdline):
    """Split a command line into simple commands (lists of words) using Genno's own parser."""
    try:
        return [[w.raw() for w in c.words] for _, p in parse(cmdline) for c in p if c.words]
    except ParseError:
        return [seg.split() for seg in re.split(r"[;&|]+", cmdline) if seg.split()]


def binaries(cmds):
    return {sc[0] for c in cmds for sc in simple_commands(c)}


def classify(s, th=None):
    th = th or Thresholds()
    cmds = [c[1] for c in s["commands"]]
    text = "\n".join(cmds)
    if not s["n_auth"] and not cmds:
        return "scanner", ["no_auth_no_commands"]
    if not s["login_success"]:
        if s["n_auth"] >= th.brute_attempts:
            return "brute_force", [f"failed_auth>={th.brute_attempts}"]
        return "auth_probe", ["failed_auth"]
    if not cmds:
        return "login_only", ["login_no_commands"]
    if MINER.search(text):
        return "cryptominer", ["miner_keyword"]
    if s["downloads"] or DROPPER.search(text):
        return "malware_dropper", ["download_tool_or_url"]
    if PERSIST.search(text):
        return "persistence", ["persistence_keyword"]
    ts = [c[0] for c in s["commands"]]
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    if s["interactive"] and gaps and statistics.median(gaps) >= th.human_gap:
        return "human", [f"interactive", f"median_gap>={th.human_gap}s"]
    if binaries(cmds) <= RECON_BINS:
        return "recon_bot", ["only_recon_commands"]
    return "post_login_other", ["no_rule"]


def classify_all(sessions, th=None):
    from analysis.attack_map import techniques
    th = th or Thresholds()
    res = {}
    for s in sessions:
        label, reasons = classify(s, th)
        res[s["session_id"]] = {"label": label, "reasons": list(reasons)}
    ip_probes = Counter(s["src_ip"] for s in sessions
                        if res[s["session_id"]]["label"] in ("auth_probe", "login_only"))
    for s in sessions:
        r = res[s["session_id"]]
        if r["label"] in ("auth_probe", "login_only") and ip_probes[s["src_ip"]] >= th.brute_ip_sessions:
            r["label"] = "brute_force"
            r["reasons"].append(f"ip_campaign>={th.brute_ip_sessions}_sessions")
        r["techniques"] = techniques(s, r["label"])
    return res
