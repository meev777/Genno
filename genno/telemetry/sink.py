"""Append-only JSONL event sink. One event per line, flat schema.

Logging failures must never break a session: errors go to stderr once, the event is dropped.
"""
import json, sys, threading, time
from pathlib import Path


class Sink:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._warned = False

    def emit(self, event_type, session_id, src_ip, src_port, **fields):
        ev = {"ts": round(time.time(), 3), "event_type": event_type,
              "session_id": session_id, "src_ip": src_ip, "src_port": src_port,
              "proto": "ssh", **fields}
        line = json.dumps(ev, separators=(",", ":"))
        try:
            with self._lock, self.path.open("a") as f:
                f.write(line + "\n")
        except OSError as e:
            if not self._warned:
                self._warned = True
                print(f"genno: telemetry write failed ({self.path}): {e}", file=sys.stderr, flush=True)
        return ev
