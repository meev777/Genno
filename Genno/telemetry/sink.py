"""Append-only JSONL event sink. One event per line, flat schema."""
import json, threading, time
from pathlib import Path

class Sink:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, event_type, session_id, src_ip, src_port, **fields):
        ev = {"ts": round(time.time(), 3), "event_type": event_type,
              "session_id": session_id, "src_ip": src_ip, "src_port": src_port,
              "proto": "ssh", **fields}
        line = json.dumps(ev, separators=(",", ":"))
        with self._lock, self.path.open("a") as f:
            f.write(line + "\n")
        return ev
