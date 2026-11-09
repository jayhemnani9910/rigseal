import json
import os
from pathlib import Path

import pytest

from rigseal.collectors import codex, cursor, shared, vscode
from rigseal.model import CollectError
from rigseal.readers import read_json, strip_jsonc

SECRET = "sk-very-secret-value"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def rows(items):
    return {(i.agent, i.scope, i.kind, i.name) for i in items}


def by(items, kind, name):
    return next(i for i in items if i.kind == kind and i.name == name)


@pytest.fixture(autouse=True)
def no_codex_home(monkeypatch):
    monkeypatch.delenv("CODEX_HOME", raising=False)


# --- JSONC -------------------------------------------------------------------


def test_strip_jsonc_keeps_comment_markers_inside_strings():
    text = '// head\n{"url": "https://x.com/a//b", /* c */ "list": [1, 2,],}\n'
    assert json.loads(strip_jsonc(text)) == {"url": "https://x.com/a//b", "list": [1, 2]}


def test_read_json_handles_comments_and_empty(tmp_path):
    write(tmp_path / "a.json", "// managed\n{\n  \"x\": 1,\n}\n")
    write(tmp_path / "b.json", "")
    assert read_json(tmp_path / "a.json") == {"x": 1}
    assert read_json(tmp_path / "b.json") == {}
    assert read_json(tmp_path / "missing.json") is None
    write(tmp_path / "c.json", "{oops")
    with pytest.raises(CollectError):
        read_json(tmp_path / "c.json")


# --- Codex -------------------------------------------------------------------

CODEX_TOML = f"""
approval_policy = "never"
sandbox_mode = "danger-full-access"

[mcp_servers.node]
command = "node"
args = ["server.js", "{SECRET}"]
env = {{ TOKEN = "{SECRET}" }}

[mcp_servers.docs]
url = "https://docs.example.com/mcp"

[plugins."github@curated"]
enabled = true

[[hooks.SessionStart]]
matcher = "startup"
"""


@pytest.fixture
def codex_home(tmp_path):
    home = tmp_path / "home"
    c = home / ".codex"
    write(c / "config.toml", CODEX_TOML)
    write(c / "skills/pdf/SKILL.md", "pdf")
    write(c / "skills/.system/installer/SKILL.md", "sys")
    write(c / "plugins/cache/curated/github/plugin.json", "{}")
    write(c / "plugins/cache/curated/slack/plugin.json", "{}")
    write(c / "rules/default.rules", "allow")
    write(c / "AGENTS.md", "rules")
    project = tmp_path / "proj"
    write(project / ".codex/config.toml", '[mcp_servers.local]\ncommand = "bash"\n')
    return home, project


def test_codex_collects_everything(codex_home):
    home, project = codex_home
    items = codex.collect(home, project)
    assert rows(items) == {
        ("codex", "user", "settings", "config.toml"),
        ("codex", "user", "mcp", "node"),
        ("codex", "user", "mcp", "docs"),
        ("codex", "user", "skill", "pdf"),
        ("codex", "system", "skill", "installer"),
        ("codex", "plugin", "plugin", "github@curated"),
        ("codex", "plugin", "plugin", "slack@curated"),
        ("codex", "user", "rule", "default"),
        ("codex", "user", "instructions", "AGENTS.md"),
        ("codex", "project", "settings", "config.toml"),
        ("codex", "project", "mcp", "local"),
    }


def test_codex_details(codex_home):
    home, project = codex_home
    items = codex.collect(home, project)
    cfg = next(i for i in items if i.kind == "settings" and i.scope == "user")
    assert cfg.details["risky_keys"] == ["approval_policy", "sandbox_mode", "hooks", "plugins"]
    assert cfg.details["hook_events"] == ["SessionStart"]
    assert by(items, "mcp", "node").details == {"transport": "stdio", "command": "node", "arg_count": 2, "env_keys": ["TOKEN"]}
    assert by(items, "mcp", "docs").details == {"transport": "http", "host": "docs.example.com"}
    assert by(items, "plugin", "github@curated").details == {"enabled": True}
    assert by(items, "plugin", "slack@curated").details == {"enabled": False}
    assert SECRET not in json.dumps([i.to_dict() for i in items])


def test_codex_home_env(codex_home, tmp_path, monkeypatch):
    home, _ = codex_home
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))
    assert len(codex.collect(tmp_path / "elsewhere", None)) == 9


def test_codex_bad_toml(tmp_path):
    write(tmp_path / ".codex/config.toml", "not = = toml")
    with pytest.raises(CollectError):
        codex.collect(tmp_path, None)


# --- Cursor ------------------------------------------------------------------


def test_cursor(tmp_path):
    home, project = tmp_path / "home", tmp_path / "proj"
    write(home / ".cursor/mcp.json", json.dumps({"mcpServers": {"mem": {"command": "mem-mcp"}}}))
    write(home / ".cursor/hooks.json", json.dumps({"version": 1, "hooks": {"beforeShellExecution": [{"command": "x"}]}}))
    write(home / ".agents/skills/docx/SKILL.md", "docx")
    (home / ".cursor/skills").mkdir(parents=True)
    os.symlink("../../.agents/skills/docx", home / ".cursor/skills/docx")
    write(project / ".cursor/mcp.json", json.dumps({"mcpServers": {"evil": {"command": "bash"}}}))
    write(project / ".cursor/rules/style/ts.mdc", "use ts")
    write(project / ".cursorrules", "old rules")

    items = cursor.collect(home, project)
    assert rows(items) == {
        ("cursor", "user", "mcp", "mem"),
        ("cursor", "user", "settings", "hooks.json"),
        ("cursor", "user", "skill", "docx"),
        ("cursor", "project", "mcp", "evil"),
        ("cursor", "project", "rule", "style/ts"),
        ("cursor", "project", "rule", ".cursorrules"),
    }
    assert by(items, "settings", "hooks.json").details == {"risky_keys": ["hooks"], "hook_events": ["beforeShellExecution"]}
    skill = by(items, "skill", "docx")
    assert skill.details["link"] == "../../.agents/skills/docx"
    # Same content seen through the link and in the shared folder gives the same hash.
    assert skill.sha256 == by(shared.collect(home, None), "skill", "docx").sha256


# --- VS Code / Copilot -------------------------------------------------------


def test_vscode_and_copilot(tmp_path, monkeypatch):
    monkeypatch.setattr(vscode.sys, "platform", "linux")
    home, project = tmp_path / "home", tmp_path / "proj"
    user = home / ".config/Code/User"
    write(user / "mcp.json", '// comment\n{"servers": {"gh": {"type": "http", "url": "https://api.githubcopilot.com/mcp/",},}, "inputs": []}')
    write(user / "prompts/review.prompt.md", "review")
    write(home / ".copilot/config.json", "// managed\n{}")
    write(home / ".copilot/mcp-config.json", json.dumps({"mcpServers": {"fs": {"command": "npx", "env": {"K": SECRET}}}}))
    write(home / ".copilot/skills/pdf/SKILL.md", "pdf")
    write(home / ".copilot/installed-plugins/review/plugin.json", "{}")
    write(project / ".vscode/mcp.json", json.dumps({"servers": {"db": {"command": "db-mcp"}}}))
    write(project / ".github/copilot-instructions.md", "be brief")
    write(project / ".github/prompts/fix.prompt.md", "fix")

    items = vscode.collect(home, project)
    assert rows(items) == {
        ("vscode", "user", "mcp", "gh"),
        ("vscode", "user", "prompt", "review.prompt"),
        ("copilot-cli", "user", "mcp", "fs"),
        ("copilot-cli", "user", "skill", "pdf"),
        ("copilot-cli", "plugin", "plugin", "review"),
        ("vscode", "project", "mcp", "db"),
        ("vscode", "project", "instructions", "copilot-instructions.md"),
        ("vscode", "project", "prompt", "fix.prompt"),
    }
    assert by(items, "mcp", "gh").details == {"transport": "http", "host": "api.githubcopilot.com"}
    assert SECRET not in json.dumps([i.to_dict() for i in items])


def test_vscode_mac_path(tmp_path, monkeypatch):
    monkeypatch.setattr(vscode.sys, "platform", "darwin")
    assert vscode.vscode_user_dir(tmp_path) == tmp_path / "Library/Application Support/Code/User"


def test_vscode_windows_path(tmp_path, monkeypatch):
    monkeypatch.setattr(vscode.sys, "platform", "win32")
    assert vscode.vscode_user_dir(tmp_path) == tmp_path / "AppData/Roaming/Code/User"
    write(tmp_path / "AppData/Roaming/Code/User/mcp.json", json.dumps({"servers": {"gh": {"command": "gh-mcp"}}}))
    assert rows(vscode.collect(tmp_path, None)) == {("vscode", "user", "mcp", "gh")}


def test_empty_home_gives_nothing(tmp_path):
    for collect in (codex.collect, cursor.collect, vscode.collect, shared.collect):
        assert collect(tmp_path, tmp_path) == []
