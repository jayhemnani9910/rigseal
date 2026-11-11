"""The normalized inventory item and the hashing helpers every collector uses."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path


class CollectError(Exception):
    """A config file exists but can't be read or parsed."""


@dataclass
class FileHash:
    path: str  # relative to the item's root
    sha256: str


@dataclass
class Item:
    agent: str  # e.g. "claude-code"
    scope: str  # user | project | local | plugin
    kind: str  # settings | mcp | skill | command | agent | plugin | instructions
    name: str
    path: str  # where the item was found
    sha256: str  # one hash over everything that defines the item
    files: list[FileHash] = field(default_factory=list)
    details: dict = field(default_factory=dict)  # non-secret facts, shown to the user
    # The parsed config (MCP server, settings), for rules only. May hold secrets: never stored or printed.
    raw: object = field(default=None, repr=False, compare=False)
    # Text-rule hits per file, (relative name, [(rule, severity, message)]), filled with capabilities.
    file_hits: list[tuple[str, list[tuple[str, str, str]]]] = field(default_factory=list, repr=False, compare=False)
    # The key this item has in the lock when it differs from the plain one (a duplicate gets #2, #3).
    lock_key: str | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        del d["raw"], d["file_hits"], d["lock_key"]
        return d

    def text_files(self) -> list[tuple[str, Path]]:
        """(relative name, full path) for each hashed file of a file or folder item."""
        root = Path(self.path)
        if root.is_dir():  # links inside a folder are hashed by target, so their contents are never read
            return [(f.path, root / f.path) for f in self.files if not (root / f.path).is_symlink()]
        return [(f.path, root) for f in self.files]


@dataclass
class Finding:
    rule: str  # R2, R15, ...
    severity: str  # high | medium | low
    key: str  # item key, as in the lock
    message: str  # never contains secret values
    file: str | None = None  # file inside the item the finding is about, relative to the item's path

    def to_dict(self) -> dict:
        d = asdict(self)
        if d["file"] is None:
            del d["file"]
        return d


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    if not _files:
        return ""
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
    except OSError as e:
        raise CollectError(f"cannot read {path}: {e}") from e
    return h.hexdigest()


def hash_json(value: object) -> str:
    """Stable hash of a JSON value. Used so secrets in configs are hashed, never stored."""
    return hash_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode())


# Limits per folder item, so a hostile repo can't make a scan run for hours.
MAX_TREE_FILES = 20_000
MAX_TREE_BYTES = 500 * 1024 * 1024


@dataclass
class Tree:
    sha256: str
    files: list[FileHash]
    truncated: bool = False  # hit MAX_TREE_FILES or MAX_TREE_BYTES; the hash covers what was read


_scan: dict[tuple[str, frozenset[str]], Tree] | None = None
_files = True


@contextmanager
def one_scan(files: bool = True) -> Iterator[None]:
    """Inside one scan a folder is hashed once, however many items point at it. A repo can link one big folder
    under a hundred names, and each name would otherwise cost a full pass.
    With `files` off nothing is hashed at all: the scan only says what the config files hold. That is all the MCP
    gate needs, and it keeps a slow or hostile folder from holding up every tool call."""
    global _scan, _files
    _scan, _files = {}, files
    try:
        yield
    finally:
        _scan, _files = None, True


def hash_tree(root: Path, ignore: frozenset[str] = frozenset()) -> Tree:
    """Hash every file under root, dotfiles included. Symlinks are recorded by target, not followed.
    Names in `ignore` (files or folders) are skipped, for agent bookkeeping that changes every session."""
    if not _files:
        return Tree("", [])
    if _scan is None:
        return _hash_tree(root, ignore)
    key = (os.path.realpath(root), ignore)
    if key not in _scan:
        _scan[key] = _hash_tree(root, ignore)
    return _scan[key]


def _hash_tree(root: Path, ignore: frozenset[str]) -> Tree:
    files: list[FileHash] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in ignore)
        base = Path(dirpath)
        # os.walk does not descend into symlinked dirs, so record them here.
        for name in sorted(dirnames + [f for f in filenames if f not in ignore]):
            p = base / name
            rel = p.relative_to(root).as_posix()
            try:
                if p.is_symlink():
                    files.append(FileHash(rel, hash_bytes(b"symlink:" + os.readlink(p).encode(errors="surrogateescape"))))
                    continue
                size = p.stat().st_size if p.is_file() else None
            except OSError as e:
                raise CollectError(f"cannot read {p}: {e}") from e
            if size is not None:
                total += size
                if len(files) >= MAX_TREE_FILES or total > MAX_TREE_BYTES:
                    files.sort(key=lambda f: f.path)
                    return Tree(tree_digest(files), files, truncated=True)
                files.append(FileHash(rel, hash_file(p)))
    files.sort(key=lambda f: f.path)
    return Tree(tree_digest(files), files)


def tree_digest(files: list[FileHash]) -> str:
    lines = "".join(f"{f.path}\0{f.sha256}\n" for f in sorted(files, key=lambda f: f.path))
    return hash_bytes(lines.encode(errors="surrogateescape"))
