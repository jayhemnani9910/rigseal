"""Add rigseal's hooks to the user's agent config. It appends its own hooks and brings its own older entries up to
date; every other setting and hook is kept as it is."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from rigseal.model import CollectError
from rigseal.readers import read_json

CLAUDE_COMMAND = "rigseal hook claude-code"
CURSOR_COMMAND = "rigseal hook cursor"


def _claude(matcher: str, **more: object) -> dict:
    return {"matcher": matcher, "hooks": [{"type": "command", "command": CLAUDE_COMMAND, "timeout": 30, **more}]}


@dataclass
class Target:
    agent: str
    path: Path
    command: str
    wanted: dict[str, dict]  # event -> the entry to add
    base: dict  # what a new file starts with


def targets(home: Path) -> list[Target]:
    """One target per agent that is installed, which means its folder exists."""
    found = []
    if (home / ".claude").is_dir():
        wanted = {
            "SessionStart": _claude("startup|resume"),
            # Without onFailure a hook that crashes, times out or can't start lets the call through (Claude Code 2.1.295+).
            "PreToolUse": _claude("mcp__.*", onFailure="block"),
            "ConfigChange": _claude("user_settings|project_settings|local_settings|skills"),
        }
        found.append(Target("claude-code", home / ".claude" / "settings.json", CLAUDE_COMMAND, wanted, {}))
    if (home / ".cursor").is_dir():
        wanted = {"sessionStart": {"command": CURSOR_COMMAND}, "beforeMCPExecution": {"command": CURSOR_COMMAND, "failClosed": True}}
        found.append(Target("cursor", home / ".cursor" / "hooks.json", CURSOR_COMMAND, wanted, {"version": 1}))
    return found


def _read(target: Target) -> dict:
    doc = read_json(target.path)
    if doc is None:
        return dict(target.base)
    try:
        json.loads(target.path.read_text(encoding="utf-8-sig").strip() or "{}")
    except ValueError as e:  # read_json accepts comments, but writing the file back would lose them
        raise CollectError(
            f"{target.path} has comments or trailing commas, so rigseal won't rewrite it. Add the hooks by hand (see docs/reference.md)."
        ) from e
    hooks = doc.get("hooks", {})
    if not isinstance(hooks, dict) or not all(isinstance(v, list) for v in hooks.values()):
        raise CollectError(f"{target.path}: `hooks` is not in the expected format, so rigseal won't rewrite it.")
    return doc


UP_TO_USER = ("command", "timeout")  # a full path to rigseal or a longer timeout is the user's choice


def _ours(entries: list, command: str) -> dict | None:
    """The hook in an event's list that runs rigseal. Claude Code nests hooks under `hooks`, Cursor lists them flat."""
    for e in entries:
        if isinstance(e, dict):
            nested = e.get("hooks")
            for h in nested if isinstance(nested, list) else [e]:
                if isinstance(h, dict) and isinstance(h.get("command"), str) and h["command"].endswith(command):
                    return h
    return None


def _settings(target: Target, event: str) -> dict:
    """What rigseal's hook for `event` must say besides its command, such as failing closed."""
    entry = target.wanted[event]
    hook = entry["hooks"][0] if "hooks" in entry else entry
    return {k: v for k, v in hook.items() if k not in UP_TO_USER}


def missing(target: Target) -> list[str]:
    """Events that don't call rigseal yet, or call it with older settings than it now needs.
    Raises CollectError if the file can't be safely rewritten."""
    hooks = _read(target).get("hooks", {})
    out = []
    for event in target.wanted:
        mine = _ours(hooks.get(event, []), target.command)
        if mine is None or any(mine.get(k) != v for k, v in _settings(target, event).items()):
            out.append(event)
    return out


def installed(target: Target) -> bool:
    """True if any event already calls rigseal, so what `missing` reports is an update, not a first install."""
    hooks = _read(target).get("hooks", {})
    return any(_ours(hooks.get(event, []), target.command) for event in target.wanted)


def add(target: Target) -> None:
    doc = _read(target)
    hooks = doc.setdefault("hooks", {})
    for event in missing(target):
        mine = _ours(hooks.get(event, []), target.command)
        if mine is None:
            hooks.setdefault(event, []).append(target.wanted[event])
        else:
            mine.update(_settings(target, event))
    _write(target.path, doc)


def _write(path: Path, doc: dict) -> None:
    path = path.resolve()  # a symlink into a dotfiles repo stays a symlink
    tmp = path.with_name(path.name + ".rigseal-tmp")
    try:
        tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if path.exists():
            shutil.copymode(path, tmp)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)
