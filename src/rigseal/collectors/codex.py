"""Collect what OpenAI Codex loads: config.toml (MCP servers, hooks, plugins), skills, plugins, rules, AGENTS.md."""

from __future__ import annotations

import os
from functools import partial
from pathlib import Path

from rigseal.collectors import common
from rigseal.model import Item
from rigseal.readers import read_toml

AGENT = "codex"

RISKY_CONFIG_KEYS = (
    "approval_policy",
    "sandbox_mode",
    "hooks",
    "notify",
    "shell_environment_policy",
    "model_providers",
    "marketplaces",
    "plugins",
)

optional_file = partial(common.optional_file, AGENT)
skill_dirs = partial(common.skill_dirs, AGENT)


def collect(home: Path, project: Path | None) -> list[Item]:
    codex_home = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else home / ".codex"
    items: list[Item] = []

    config = _config(codex_home / "config.toml", "user", items)
    items += skill_dirs(codex_home / "skills", "user", skip=(".system",))
    items += skill_dirs(codex_home / "skills" / ".system", "system")
    enabled = (config or {}).get("plugins")
    items += _plugins(codex_home / "plugins" / "cache", enabled if isinstance(enabled, dict) else {})
    items += common.files_matching(AGENT, codex_home / "rules", ".rules", "rule", "user")
    items += optional_file(codex_home / "AGENTS.md", "user", "instructions")

    if project is not None:
        _config(project / ".codex" / "config.toml", "project", items)
        items += skill_dirs(project / ".codex" / "skills", "project", within=project)
    return items


def _config(path: Path, scope: str, items: list[Item]) -> dict | None:
    data = read_toml(path)
    if data is None:
        return None
    items.append(common.settings_item(AGENT, path, data, scope, RISKY_CONFIG_KEYS))
    items += common.mcp_items(AGENT, data.get("mcp_servers"), scope, path)
    return data


def _plugins(cache: Path, enabled: dict) -> list[Item]:
    """Plugins live in cache/<marketplace>/<plugin>/<version>/. The config says which are enabled.
    MCP servers come from each version folder's .mcp.json."""
    if not cache.is_dir():
        return []
    items = []
    for market in (p for p in common.children(cache) if p.is_dir()):
        for plugin in (p for p in common.children(market) if p.is_dir()):
            name = f"{plugin.name}@{market.name}"
            entry = enabled.get(name)
            details = {"enabled": bool(entry.get("enabled")) if isinstance(entry, dict) else False}
            items.append(common.tree_item(AGENT, plugin, "plugin", "plugin", name, details))
            for version in (p for p in common.children(plugin) if p.is_dir()):
                for mcp in common.plugin_mcp(AGENT, version, plugin.name):
                    mcp.details["plugin_enabled"] = details["enabled"]
                    mcp.details["version"] = version.name
                    items.append(mcp)
    return items
