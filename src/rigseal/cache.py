"""On-disk cache of per-file analysis, keyed by file hash.

Agent setups rarely change, so most runs only need to hash files. The cache is thrown away whenever the
analysis code changes (its version is a hash of the modules that produce the results).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

ANALYSIS_MODULES = ("capabilities.py", "text_rules.py")


def analysis_version() -> str:
    h = hashlib.sha256()
    for name in ANALYSIS_MODULES:
        h.update((Path(__file__).parent / name).read_bytes())
    return h.hexdigest()[:16]


def cache_path(home: Path) -> Path:
    base = Path(os.environ["XDG_CACHE_HOME"]) if os.environ.get("XDG_CACHE_HOME") else home / ".cache"
    return base / "rigseal" / "analysis.json"


def _valid(result: object) -> bool:
    """The shape `analyze_file` returns. Anything else (a damaged or hand-made cache) is dropped and worked out again."""
    if not isinstance(result, dict):
        return False
    lists = (result.get(k, []) for k in ("sensitive", "hosts", "tools"))
    hits, hidden = result.get("hits", []), result.get("hidden", {})
    return (
        all(isinstance(values, list) and all(isinstance(v, str) for v in values) for values in lists)
        and isinstance(hits, list)
        and all(_valid_hit(h) for h in hits)
        and isinstance(hidden, dict)
        and all(isinstance(n, int) for n in hidden.values())
    )


def _valid_hit(hit: object) -> bool:
    """[rule, severity, message], as `file_hits` gives them."""
    if not (isinstance(hit, list) and len(hit) == 3 and all(isinstance(x, str) for x in hit)):
        return False
    return hit[0][:1] == "R" and hit[0][1:].isdigit() and hit[1] in ("high", "medium", "low")


class Cache:
    def __init__(self, path: Path):
        self.path = path
        self.version = analysis_version()
        self.entries: dict[str, dict] = {}
        self.used: set[str] = set()
        self.dirty = False
        try:
            doc = json.loads(path.read_text())
            if doc.get("version") == self.version and isinstance(doc.get("entries"), dict):
                self.entries = {k: v for k, v in doc["entries"].items() if _valid(v)}
        except (OSError, ValueError, AttributeError, RecursionError):
            pass  # missing or broken cache: start empty

    def get(self, key: str) -> dict | None:
        if key in self.entries:
            self.used.add(key)
            return self.entries[key]
        return None

    def put(self, key: str, value: dict) -> None:
        self.entries[key] = value
        self.used.add(key)
        self.dirty = True

    def save(self) -> None:
        """Write the entries used this run, so files that are gone drop out."""
        if not self.dirty and self.used == set(self.entries):
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps({"version": self.version, "entries": {k: self.entries[k] for k in sorted(self.used)}}))
            tmp.replace(self.path)
        except OSError:
            pass  # a cache that can't be written only costs speed
