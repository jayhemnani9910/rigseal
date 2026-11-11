"""Lockfiles and drift.

Two locks:
- repo lock (`rigseal.lock` in the project): project-scope items, paths relative to the project. Committed.
- machine lock (`$RIGSEAL_DIR/machine.lock`, default `~/.rigseal`): user, plugin and system items, plus
  local-scope items grouped per project. Never committed.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from rigseal import __version__
from rigseal.model import CollectError, Item

LOCK_VERSION = 0
REPO_LOCK_NAME = "rigseal.lock"
MAX_REPO_LOCK_BYTES = 64 * 1024 * 1024  # a repo lock arrives with a clone: don't read whatever size it claims


def rigseal_dir(home: Path) -> Path:
    return Path(os.environ["RIGSEAL_DIR"]) if os.environ.get("RIGSEAL_DIR") else home / ".rigseal"


def machine_lock_path(home: Path) -> Path:
    return rigseal_dir(home) / "machine.lock"


def repo_lock_path(project: Path) -> Path:
    return project / REPO_LOCK_NAME


def plain_key(item: Item) -> str:
    return f"{item.agent}/{item.scope}/{item.kind}/{item.name}"


def item_key(item: Item) -> str:
    return item.lock_key or plain_key(item)


def _rel(path: str, base: Path, prefix: str) -> str:
    try:
        return prefix + Path(path).relative_to(base).as_posix()
    except ValueError:
        return path


def entry(item: Item, base: Path, prefix: str) -> dict:
    return {
        "agent": item.agent,
        "scope": item.scope,
        "kind": item.kind,
        "name": item.name,
        "path": _rel(item.path, base, prefix),
        "sha256": item.sha256,
        "files": {f.path: f.sha256 for f in item.files},
        "details": item.details,
    }


def keyed(items: list[Item], base: Path, prefix: str) -> dict[str, dict]:
    """Items as lock entries by key. Same key twice (e.g. a plugin installed twice) gets #2, #3."""
    out: dict[str, dict] = {}
    for item in items:
        key = plain_key(item)
        n = 1
        while key in out:
            n += 1
            key = f"{plain_key(item)}#{n}"
        item.lock_key = key
        out[key] = entry(item, base, prefix)
    return out


@dataclass
class Current:
    """The live inventory split the way the two locks store it."""

    repo: dict[str, dict]
    machine: dict[str, dict]
    local: dict[str, dict]


def split(items: list[Item], home: Path, project: Path) -> Current:
    repo = [i for i in items if i.scope == "project"]
    local = [i for i in items if i.scope == "local"]
    machine = [i for i in items if i.scope not in ("project", "local")]
    return Current(keyed(repo, project, ""), keyed(machine, home, "~/"), keyed(local, home, "~/"))


# --- files -------------------------------------------------------------------


@dataclass
class Lock:
    path: Path
    items: dict[str, dict] = field(default_factory=dict)
    projects: dict[str, dict[str, dict]] = field(default_factory=dict)  # machine lock only
    signed_by: str | None = None

    @property
    def sig_path(self) -> Path:
        return self.path.with_name(self.path.name + ".sig")

    def to_json(self) -> str:
        doc: dict = {"lockfileVersion": LOCK_VERSION, "generator": f"rigseal {__version__}"}
        if self.signed_by:
            doc["signedBy"] = self.signed_by
        doc["items"] = dict(sorted(self.items.items()))
        if self.projects:
            doc["projects"] = {p: dict(sorted(v.items())) for p, v in sorted(self.projects.items()) if v}
        return json.dumps(doc, indent=2, sort_keys=False) + "\n"

    def write(self, sign: Callable[[Path], Path] | None = None) -> None:
        """Write the lock. With `sign`, a temp copy is signed first, so a failed signing leaves the old lock and .sig."""
        text, tmp = self.to_json(), self.path.with_name(self.path.name + ".tmp")
        if self.path.name == REPO_LOCK_NAME and len(text) > MAX_REPO_LOCK_BYTES:  # never write a lock we would refuse to read
            raise CollectError(f"{self.path} would be over {MAX_REPO_LOCK_BYTES // 2**20} MB: this project's agent folders hold too many files to lock")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.unlink(missing_ok=True)  # a link a repo left under this name is removed, never written through
            with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666), "w") as f:  # O_EXCL follows no link
                f.write(text)
        except OSError as e:
            raise CollectError(f"cannot write {self.path}: {e}") from e
        try:
            signature = sign(tmp) if sign else None
            tmp.replace(self.path)
            if signature:
                signature.replace(self.sig_path)
        finally:
            tmp.unlink(missing_ok=True)
            tmp.with_name(tmp.name + ".sig").unlink(missing_ok=True)


def read_lock(path: Path, repo: bool = False) -> Lock | None:
    """The lock at `path`, None if there is none. With `repo` the file arrived with a clone, so it has to be a plain
    file of a sane size that holds project-level entries only."""
    try:
        if (repo and path.is_symlink()) or (path.exists() and not path.is_file()):
            raise CollectError(f"{path} is not a regular file; not reading it")
        if repo and path.stat().st_size > MAX_REPO_LOCK_BYTES:
            raise CollectError(f"{path} is over {MAX_REPO_LOCK_BYTES // 2**20} MB; not reading it")
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError, RecursionError) as e:
        raise CollectError(f"cannot read lock {path}: {e}") from e
    if not isinstance(doc, dict) or doc.get("lockfileVersion") != LOCK_VERSION:
        raise CollectError(f"{path}: not a rigseal v{LOCK_VERSION} lockfile")
    items, projects, signed_by = doc.get("items") or {}, doc.get("projects") or {}, doc.get("signedBy")
    valid = _valid_entries(items) and isinstance(projects, dict) and all(_valid_entries(p) for p in projects.values())
    if not valid or not isinstance(signed_by, str | None):
        raise CollectError(f"{path}: malformed lockfile entries")
    if repo and (projects or any(key.split("/")[1] != "project" for key in items)):
        raise CollectError(f"{path}: a repo lock can only hold project-level entries")
    return Lock(path, items, projects, signed_by)


def _valid_entries(entries: object) -> bool:
    return isinstance(entries, dict) and all(_valid_key(k) and _valid_entry(e) for k, e in entries.items())


def _valid_key(key: object) -> bool:
    """agent/scope/kind/name, each part present. The name may hold more slashes."""
    return isinstance(key, str) and len(parts := key.split("/", 3)) == 4 and all(parts)


def _valid_entry(e: object) -> bool:
    if not isinstance(e, dict) or not isinstance(e.get("kind"), str) or not isinstance(e.get("sha256"), str):
        return False
    details = e.get("details") or {}
    if not isinstance(e.get("files", {}), dict) or not isinstance(details, dict):
        return False
    caps = details.get("capabilities") or {}
    return isinstance(caps, dict) and all(_valid_capability(k, v) for k, v in caps.items())


def _valid_capability(name: str, value: object) -> bool:
    """A flag, a list of strings, or for hidden_chars a map per file: the shapes `capability_diff` reads."""
    if name == "hidden_chars":
        return isinstance(value, dict)
    return isinstance(value, bool) or (isinstance(value, list) and all(isinstance(v, str) for v in value))


# --- diff --------------------------------------------------------------------


@dataclass
class Change:
    key: str
    status: str  # added | removed | changed
    lock: str  # repo | machine
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_changed: list[str] = field(default_factory=list)
    details_changed: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)  # "+ network", "+ host evil.com", "- shell"
    sha256: str = ""  # the item's current hash, empty once removed

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != "sha256" and (v or k in ("key", "status", "lock"))}


def diff_entries(locked: dict[str, dict], current: dict[str, dict], lock_name: str) -> list[Change]:
    changes = []
    for key in sorted(locked.keys() | current.keys()):
        old, new = locked.get(key), current.get(key)
        if new is None:
            changes.append(Change(key, "removed", lock_name))
        elif old is None:
            changes.append(Change(key, "added", lock_name, files_added=sorted(new["files"]), sha256=new["sha256"]))
        elif old["sha256"] != new["sha256"] or old.get("details") != new.get("details"):
            of, nf = old.get("files", {}), new["files"]
            od, nd = old.get("details") or {}, new.get("details") or {}
            changes.append(
                Change(
                    key,
                    "changed",
                    lock_name,
                    files_added=sorted(nf.keys() - of.keys()),
                    files_removed=sorted(of.keys() - nf.keys()),
                    files_changed=sorted(k for k in of.keys() & nf.keys() if of[k] != nf[k]),
                    details_changed=sorted(k for k in od.keys() | nd.keys() if od.get(k) != nd.get(k)),
                    capabilities=capability_diff(od.get("capabilities") or {}, nd.get("capabilities") or {}),
                    sha256=new["sha256"],
                )
            )
    return changes


CAP_LABELS = {"hosts": "host", "sensitive_paths": "sensitive path", "allowed_tools": "allowed tool"}


def capability_diff(old: dict, new: dict) -> list[str]:
    """Readable lines for what an item can now do that it couldn't before (and the reverse)."""
    lines = []
    for k in sorted(old.keys() | new.keys()):
        a, b = old.get(k), new.get(k)
        if a == b:
            continue
        if isinstance(a, bool) or isinstance(b, bool):
            lines.append(f"{'+' if b else '-'} {k}")
        elif k == "hidden_chars":
            lines += [f"+ hidden chars in {f}" for f in sorted((b or {}).keys() - (a or {}).keys())]
            lines += [f"- hidden chars in {f}" for f in sorted((a or {}).keys() - (b or {}).keys())]
        else:
            label = CAP_LABELS.get(k, k)
            lines += [f"+ {label} {v}" for v in sorted(set(b or []) - set(a or []))]
            lines += [f"- {label} {v}" for v in sorted(set(a or []) - set(b or []))]
    return lines


def apply(locked: dict[str, dict], current: dict[str, dict], keys: set[str] | None, who: str, when: str) -> dict[str, dict]:
    """Accept current state for `keys` (all if None). Returns the new locked entries."""
    out = dict(locked)
    for key in locked.keys() | current.keys():
        if keys is not None and key not in keys:
            continue
        if key in current:
            if locked.get(key, {}).get("sha256") == current[key]["sha256"] and locked[key].get("details") == current[key]["details"]:
                continue  # unchanged: keep the original approval
            out[key] = {**current[key], "approvedBy": who, "approvedAt": when}
        else:
            out.pop(key, None)
    return out


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
