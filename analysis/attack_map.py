"""Map session behaviour to MITRE ATT&CK (enterprise) and export an ATT&CK Navigator layer.
Verify IDs against attack.mitre.org before publishing: the matrix is revised twice a year."""
import json, os, re
from analysis.classifier import simple_commands, binaries, MINER

TECHNIQUES = {
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1087.001": ("Account Discovery: Local Account", "Discovery"),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1552.003": ("Unsecured Credentials: Bash History", "Credential Access"),
    "T1222.002": ("File and Directory Permissions Modification: Linux", "Defense Evasion"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1070.004": ("Indicator Removal: File Deletion", "Defense Evasion"),
    "T1070.003": ("Indicator Removal: Clear Command History", "Defense Evasion"),
    "T1496": ("Resource Hijacking", "Impact"),
}
_SECRET_FILES = re.compile(r"config\.php|wp-config|\.env\b|id_rsa|\.aws/|credentials")
_HIST_CLEAR = re.compile(r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|>\s*\S*bash_history")


def techniques(s, label=None):
    cmds = [c[1] for c in s["commands"]]
    text = "\n".join(cmds)
    bins = binaries(cmds)
    words = {w for c in cmds for sc in simple_commands(c) for w in sc}
    reads = set(s.get("file_reads") or [])
    t = set()
    if label == "brute_force" or sum(1 for c in s["creds"] if not c[2]) >= 3:
        t.add("T1110.001")
    if s["login_success"]:
        t |= {"T1078", "T1021.004"}
    if cmds:
        t.add("T1059.004")
    if s["downloads"] or bins & {"wget", "curl", "tftp", "ftpget"}:
        t.add("T1105")
    if bins & {"uname", "free", "nproc", "lscpu", "hostname", "uptime"} or words & {
            "/proc/cpuinfo", "/proc/meminfo", "/proc/version", "/etc/os-release"}:
        t.add("T1082")
    if bins & {"whoami", "id", "w", "who", "last"}: t.add("T1033")
    if bins & {"ps", "top", "pgrep"}: t.add("T1057")
    if bins & {"ls", "find", "tree"}: t.add("T1083")
    if "/etc/passwd" in words: t.add("T1087.001")
    if "/etc/shadow" in words or "/etc/shadow" in reads: t.add("T1003.008")
    if any(_SECRET_FILES.search(p or "") for p in reads | words): t.add("T1552.001")
    if any(p and p.endswith(".bash_history") for p in reads | words) and not _HIST_CLEAR.search(text):
        t.add("T1552.003")
    if bins & {"chmod", "chown"}: t.add("T1222.002")
    if "authorized_keys" in text: t.add("T1098.004")
    if re.search(r"crontab|/etc/cron", text): t.add("T1053.003")
    if bins & {"useradd", "adduser"}: t.add("T1136.001")
    if "rm" in bins: t.add("T1070.004")
    if _HIST_CLEAR.search(text): t.add("T1070.003")
    if MINER.search(text): t.add("T1496")
    return sorted(t)


def export_navigator(session_techniques, path, name="Genno honeypot observations"):
    """session_techniques: iterable of technique-id lists (one per session)."""
    counts = {}
    for ts in session_techniques:
        for t in ts:
            counts[t] = counts.get(t, 0) + 1
    layer = {
        "name": name, "domain": "enterprise-attack",
        "versions": {"attack": "17", "navigator": "5.1.0", "layer": "4.5"},
        "description": "Techniques observed in Genno honeypot sessions; score = number of sessions.",
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": max(counts.values(), default=1)},
        "techniques": [{"techniqueID": t, "score": n, "comment": f"{TECHNIQUES.get(t, ('', ''))[0]} - {n} session(s)"}
                       for t, n in sorted(counts.items())],
    }
    os.makedirs(os.path.dirname(os.fspath(path)) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(layer, f, indent=2)
    return layer
