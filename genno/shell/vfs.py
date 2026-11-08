"""Virtual filesystem: shared read-only base + per-session copy-on-write overlay.

Nothing here touches the real disk. Paths are normalized lexically and clamp at
"/", so traversal ("../../..") can never leave the virtual tree.
"""
import posixpath, time
from collections import defaultdict
from dataclasses import dataclass, replace

MAX_FILE = 64 * 1024        # bytes per file
MAX_TOTAL = 1024 * 1024     # bytes written per session
MAX_NODES = 500             # files/dirs created per session
DEFAULT_MTIME = "Jan 12 09:14"


def now_label():
    t = time.localtime()
    return time.strftime("%b ", t) + f"{t.tm_mday:>2}" + time.strftime(" %H:%M", t)


@dataclass(frozen=True)
class Node:
    kind: str                # "f" | "d"
    content: str = ""
    mode: int = 0o644
    owner: str = "root"
    mtime: str = DEFAULT_MTIME


def normalize(cwd, path, home="/root"):
    if path == "~" or path.startswith("~/"):
        path = home + path[1:]
    if not path.startswith("/"):
        path = posixpath.join(cwd, path)
    parts = []
    for p in path.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if parts:
                parts.pop()
            continue
        parts.append(p)
    return "/" + "/".join(parts)


class BaseFS:
    """Built once per profile, never mutated afterwards (Node is frozen)."""
    def __init__(self):
        self.nodes = {"/": Node("d", mode=0o755)}
        self.children = defaultdict(set)

    def add(self, path, node):
        path = normalize("/", path)
        if path == "/":
            return
        parent = posixpath.dirname(path)
        if parent not in self.nodes:
            self.add(parent, Node("d", mode=0o755))
        self.nodes[path] = node
        self.children[parent].add(posixpath.basename(path))

    @classmethod
    def from_profile(cls, data):
        fs = cls()
        for d in data.get("dirs", []):
            if isinstance(d, str):
                d = {"path": d}
            fs.add(d["path"], Node("d", mode=int(str(d.get("mode", "755")), 8),
                                   owner=d.get("owner", "root")))
        for path, spec in data.get("files", {}).items():
            spec = spec or {}
            fs.add(path, Node("f", content=spec.get("content", ""),
                              mode=int(str(spec.get("mode", "644")), 8),
                              owner=spec.get("owner", "root")))
        return fs


class SessionFS:
    def __init__(self, base):
        self.base = base
        self.overlay = {}
        self.deleted = set()

    # --- reads
    def get(self, path):
        if path in self.deleted:
            return None
        n = self.overlay.get(path)
        return n if n is not None else self.base.nodes.get(path)

    def exists(self, path): return self.get(path) is not None
    def isdir(self, path):
        n = self.get(path); return n is not None and n.kind == "d"
    def isfile(self, path):
        n = self.get(path); return n is not None and n.kind == "f"

    def listdir(self, path):
        names = set(self.base.children.get(path, ()))
        names |= {posixpath.basename(p) for p in self.overlay
                  if p != "/" and posixpath.dirname(p) == path}
        return sorted(n for n in names if posixpath.join(path, n) not in self.deleted)

    # --- writes (return None on success, error string on failure)
    def _total(self):
        return sum(len(n.content) for n in self.overlay.values())

    def write(self, path, content, append=False, mode=None, owner="root"):
        if not self.isdir(posixpath.dirname(path)):
            return "No such file or directory"
        cur = self.get(path)
        if cur is not None and cur.kind == "d":
            return "Is a directory"
        if cur is not None and append:
            content = cur.content + content
        if len(content) > MAX_FILE:
            return "File too large"
        if cur is None and len(self.overlay) >= MAX_NODES:
            return "No space left on device"
        old = len(self.overlay[path].content) if path in self.overlay else 0
        if self._total() - old + len(content) > MAX_TOTAL:
            return "No space left on device"
        self.overlay[path] = Node(
            "f", content,
            mode if mode is not None else (cur.mode if cur else 0o644),
            cur.owner if cur else owner, now_label())
        self.deleted.discard(path)
        return None

    def mkdir(self, path, parents=False, owner="root"):
        if self.exists(path):
            return "File exists"
        parent = posixpath.dirname(path)
        if not self.isdir(parent):
            if not parents:
                return "No such file or directory"
            err = self.mkdir(parent, True, owner)
            if err:
                return err
        if len(self.overlay) >= MAX_NODES:
            return "No space left on device"
        self.overlay[path] = Node("d", mode=0o755, owner=owner, mtime=now_label())
        self.deleted.discard(path)
        return None

    def remove(self, path, recursive=False):
        n = self.get(path)
        if n is None:
            return "No such file or directory"
        if n.kind == "d":
            if self.listdir(path) and not recursive:
                return "Directory not empty"
            prefix = path.rstrip("/") + "/"
            for p in list(self.base.nodes) + list(self.overlay):
                if p.startswith(prefix):
                    self.deleted.add(p)
                    self.overlay.pop(p, None)
        self.deleted.add(path)
        self.overlay.pop(path, None)
        return None

    def chmod(self, path, mode):
        n = self.get(path)
        if n is None:
            return "No such file or directory"
        self.overlay[path] = replace(n, mode=mode)
        return None
