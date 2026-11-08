"""Persona profiles (YAML). A profile = identity + static file tree + fake process table."""
from functools import lru_cache
from pathlib import Path
import yaml
from .vfs import BaseFS

PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"


class Profile:
    def __init__(self, data):
        self.d = data
        self.base = BaseFS.from_profile(data)
    def __getitem__(self, k): return self.d[k]
    def get(self, k, default=None): return self.d.get(k, default)


@lru_cache(maxsize=8)
def load_profile(name="ubuntu-web"):
    p = Path(name)
    if not p.suffix:
        p = PROFILE_DIR / f"{name}.yaml"
    with open(p) as f:
        return Profile(yaml.safe_load(f))
