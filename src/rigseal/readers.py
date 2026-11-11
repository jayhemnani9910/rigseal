"""Read agent config files. VS Code and Copilot write JSON with comments and trailing commas."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from rigseal.model import CollectError

MAX_CONFIG_BYTES = 10 * 1024 * 1024  # agent configs are small; a huge one is an attack or an accident

# A JSON string, a // comment, or a /* */ comment. Strings come first so comment markers inside them are kept.
_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/', re.S)
_TRAILING_COMMA = re.compile(r'"(?:\\.|[^"\\])*"|,(\s*[}\]])', re.S)


def strip_jsonc(text: str) -> str:
    text = _TOKEN.sub(lambda m: m.group(0) if m.group(0).startswith('"') else "", text)
    return _TRAILING_COMMA.sub(lambda m: m.group(1) if m.group(1) is not None else m.group(0), text)


def read_json(path: Path) -> dict | None:
    """Return the object in a JSON/JSONC file, None if the file is missing, CollectError if it is broken."""
    try:
        if path.exists() and not path.is_file():
            raise CollectError(f"{path} is not a regular file; not reading it")
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise CollectError(f"{path} is over {MAX_CONFIG_BYTES // 2**20} MB; not reading it")
        text = path.read_text(encoding="utf-8-sig")  # some editors on Windows save JSON with a byte order mark
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as e:
        raise CollectError(f"cannot read {path}: {e}") from e
    if not text.strip():
        return {}
    try:
        try:
            data = json.loads(text)
        except ValueError:
            data = json.loads(strip_jsonc(text))
    except (ValueError, RecursionError) as e:
        raise CollectError(f"cannot parse {path}: {e}") from e
    if not isinstance(data, dict):
        raise CollectError(f"{path}: expected a JSON object")
    return data


def read_toml(path: Path) -> dict | None:
    try:
        if path.exists() and not path.is_file():
            raise CollectError(f"{path} is not a regular file; not reading it")
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise CollectError(f"{path} is over {MAX_CONFIG_BYTES // 2**20} MB; not reading it")
        with path.open("rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError, RecursionError) as e:  # ValueError covers bad TOML, bad UTF-8 and absurd numbers
        raise CollectError(f"cannot read {path}: {e}") from e
