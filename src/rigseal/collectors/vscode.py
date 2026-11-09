"""Collect what VS Code (Copilot Chat) and the Copilot CLI load: MCP servers, skills, prompts, instructions."""

from __future__ import annotations

import sys
from pathlib import Path

from rigseal.collectors import common
from rigseal.model import Item
from rigseal.readers import read_json

VSCODE = "vscode"
COPILOT = "copilot-cli"


def vscode_user_dir(home: Path) -> Path:
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Code" / "User"
    if sys.platform == "win32":
        return home / "AppData" / "Roaming" / "Code" / "User"
    return home / ".config" / "Code" / "User"


def collect(home: Path, project: Path | None) -> list[Item]:
    items: list[Item] = []

    user = vscode_user_dir(home)
    items += _mcp(VSCODE, user / "mcp.json", "servers", "user")
    items += common.files_matching(VSCODE, user / "prompts", ".md", "prompt", "user")

    copilot = home / ".copilot"
    items += _mcp(COPILOT, copilot / "mcp-config.json", "mcpServers", "user")
    items += common.skill_dirs(COPILOT, copilot / "skills", "user")
    items += common.skill_dirs(COPILOT, copilot / "installed-plugins", "plugin", kind="plugin")

    if project is not None:
        items += _mcp(VSCODE, project / ".vscode" / "mcp.json", "servers", "project")
        gh = project / ".github"
        items += common.optional_file(VSCODE, gh / "copilot-instructions.md", "project", "instructions", within=project)
        items += common.files_matching(VSCODE, gh / "instructions", ".md", "instructions", "project", within=project)
        items += common.files_matching(VSCODE, gh / "prompts", ".md", "prompt", "project", within=project)
        items += common.skill_dirs(VSCODE, gh / "skills", "project", within=project)
    return items


def _mcp(agent: str, path: Path, key: str, scope: str) -> list[Item]:
    return common.mcp_items(agent, (read_json(path) or {}).get(key), scope, path)
