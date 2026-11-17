"""events.jsonl -> SQLite: a raw `events` table and one summarized row per session."""
import json, sqlite3
from collections import defaultdict

SCHEMA = """
DROP TABLE IF EXISTS events; DROP TABLE IF EXISTS sessions;
CREATE TABLE events (ts REAL, event_type TEXT, session_id TEXT, src_ip TEXT, src_port INT,
  username TEXT, password TEXT, success INT, attempt INT, command TEXT, mode TEXT,
  url TEXT, path TEXT, client_version TEXT, raw TEXT);
CREATE INDEX ev_session ON events(session_id);
CREATE TABLE sessions (session_id TEXT PRIMARY KEY, src_ip TEXT, start_ts REAL, end_ts REAL,
  duration REAL, n_auth INT, login_success INT, client_version TEXT, interactive INT,
  creds TEXT, commands TEXT, downloads TEXT, file_reads TEXT,
  label TEXT, reasons TEXT, techniques TEXT);
"""
_COLS = ("ts", "event_type", "session_id", "src_ip", "src_port", "username", "password",
         "success", "attempt", "command", "mode", "url", "path", "client_version")


def read_events(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue          # truncated tail line from a crash etc.
            if isinstance(e, dict) and "session_id" in e and "ts" in e:
                yield e


def build_sessions(events):
    by = defaultdict(list)
    for e in events:
        by[e["session_id"]].append(e)
    out = []
    for sid, evs in by.items():
        evs.sort(key=lambda e: e["ts"])
        auths = [e for e in evs if e["event_type"] == "auth_attempt"]
        out.append({
            "session_id": sid, "src_ip": evs[0]["src_ip"],
            "start_ts": evs[0]["ts"], "end_ts": evs[-1]["ts"],
            "duration": round(evs[-1]["ts"] - evs[0]["ts"], 3),
            "n_auth": len(auths),
            "login_success": any(a.get("success") for a in auths),
            "client_version": next((a.get("client_version") for a in auths if a.get("client_version")), None),
            "interactive": any(e["event_type"] == "shell_open" for e in evs),
            "creds": [[a.get("username"), a.get("password"), bool(a.get("success"))] for a in auths],
            "commands": [[e["ts"], e.get("command", ""), e.get("mode")] for e in evs if e["event_type"] == "command"],
            "downloads": [e.get("url") for e in evs if e["event_type"] == "download_attempt"],
            "file_reads": [e.get("path") for e in evs if e["event_type"] == "file_read"],
        })
    return sorted(out, key=lambda s: s["start_ts"])


def ingest(jsonl_path, db_path):
    events = list(read_events(jsonl_path))
    sessions = build_sessions(events)
    db = sqlite3.connect(db_path)
    db.executescript(SCHEMA)
    db.executemany(f"INSERT INTO events VALUES ({','.join('?' * (len(_COLS) + 1))})",
                   [tuple(e.get(c) for c in _COLS) + (json.dumps(e),) for e in events])
    db.executemany(
        "INSERT INTO sessions (session_id,src_ip,start_ts,end_ts,duration,n_auth,login_success,"
        "client_version,interactive,creds,commands,downloads,file_reads) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(s["session_id"], s["src_ip"], s["start_ts"], s["end_ts"], s["duration"], s["n_auth"],
          int(s["login_success"]), s["client_version"], int(s["interactive"]),
          json.dumps(s["creds"]), json.dumps(s["commands"]), json.dumps(s["downloads"]),
          json.dumps(s["file_reads"])) for s in sessions])
    db.commit(); db.close()
    return len(sessions)


def load_sessions(db_path):
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    rows = [dict(r) for r in db.execute("SELECT * FROM sessions ORDER BY start_ts")]
    db.close()
    for r in rows:
        for k in ("creds", "commands", "downloads", "file_reads", "reasons", "techniques"):
            r[k] = json.loads(r[k]) if r.get(k) else []
        r["login_success"], r["interactive"] = bool(r["login_success"]), bool(r["interactive"])
    return rows


def save_labels(db_path, labels):
    """labels: {session_id: {"label":..., "reasons":[...], "techniques":[...]}}"""
    db = sqlite3.connect(db_path)
    db.executemany("UPDATE sessions SET label=?, reasons=?, techniques=? WHERE session_id=?",
                   [(v["label"], json.dumps(v["reasons"]), json.dumps(v["techniques"]), sid)
                    for sid, v in labels.items()])
    db.commit(); db.close()
