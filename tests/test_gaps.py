"""Plugin-shipped MCP servers, synced plugins and skills, and hostile project content."""

import json
import os
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rigseal import model
from rigseal.cache import Cache, analysis_version
from rigseal.cli import app
from rigseal.collectors import claude_code, codex, common
from rigseal.model import CollectError
from rigseal.readers import read_json
from rigseal.rules import scan


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def rows(items, kind):
    return {(i.scope, i.name) for i in items if i.kind == kind}


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    for var in ("CODEX_HOME", "RIGSEAL_DIR", "XDG_CACHE_HOME"):
        monkeypatch.delenv(var, raising=False)


# --- item 1: MCP servers that plugins ship ------------------------------------


def test_claude_plugin_mcp_from_mcp_json_and_manifest(tmp_path):
    home = tmp_path
    a = home / ".claude/plugins/cache/m/a/1.0"
    write(a / ".mcp.json", json.dumps({"mcpServers": {"web": {"type": "http", "url": "https://x.io/mcp"}}}))
    b = home / ".claude/plugins/cache/m/b/1.0"
    write(b / ".claude-plugin/plugin.json", json.dumps({"name": "b", "mcpServers": "./servers.json"}))
    write(b / "servers.json", json.dumps({"mcpServers": {"run": {"command": "bash", "args": ["-c", "x"]}}}))
    c = home / ".claude/plugins/cache/m/c/1.0"
    write(c / ".claude-plugin/plugin.json", json.dumps({"mcpServers": {"inline": {"command": "npx", "args": ["pkg"]}}}))
    installs = {f"{n}@m": [{"installPath": str(p), "version": "1.0"}] for n, p in (("a", a), ("b", b), ("c", c))}
    write(home / ".claude/plugins/installed_plugins.json", json.dumps({"plugins": installs}))

    items = claude_code.collect(home, None)
    assert rows(items, "mcp") == {("plugin", "a:web"), ("plugin", "b:run"), ("plugin", "c:inline")}
    assert {(f.rule, f.key) for f in scan(items) if f.rule in ("R2", "R16")} == {
        ("R2", "claude-code/plugin/mcp/b:run"),
        ("R16", "claude-code/plugin/mcp/c:inline"),
    }


def test_manifest_path_cannot_leave_plugin(tmp_path):
    p = tmp_path / "plug"
    write(p / ".claude-plugin/plugin.json", json.dumps({"mcpServers": "../../outside.json"}))
    write(tmp_path / "outside.json", json.dumps({"mcpServers": {"x": {"command": "x"}}}))
    assert common.plugin_mcp("claude-code", p, "plug") == []


def test_synced_plugins_and_skills(tmp_path):
    home = tmp_path
    acct = home / ".claude/plugins/synced/acct-1"
    write(acct / "sales~g2/.claude-plugin/plugin.json", json.dumps({"name": "sales"}))
    write(acct / "sales~g2/.mcp.json", json.dumps({"mcpServers": {"slack": {"type": "http", "url": "https://mcp.slack.com/mcp"}}}))
    write(acct / "uuid-123/.claude-plugin/plugin.json", json.dumps({"name": "productivity"}))
    write(acct / "uuid-123/.in_use/4242", "session")
    write(acct / "sales~g2.meta.json", "{}")
    write(home / ".claude/skills/synced/acct-1/pdf/SKILL.md", "# pdf")
    write(home / ".claude/skills/synced/acct-1/.last-complete-round", "x")

    items = claude_code.collect(home, None)
    assert rows(items, "plugin") == {("plugin", "sales"), ("plugin", "productivity")}
    assert rows(items, "mcp") == {("plugin", "sales:slack")}
    assert rows(items, "skill") == {("synced", "pdf")}
    prod = next(i for i in items if i.name == "productivity")
    assert [f.path for f in prod.files] == [".claude-plugin/plugin.json"]  # session files are not hashed


def test_codex_plugin_mcp(tmp_path):
    home = tmp_path
    write(home / ".codex/config.toml", '[plugins."gh@curated"]\nenabled = true\n')
    write(home / ".codex/plugins/cache/curated/gh/abc123/.mcp.json", json.dumps({"mcpServers": {"github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/"}}}))
    items = codex.collect(home, None)
    [mcp] = [i for i in items if i.kind == "mcp"]
    assert mcp.name == "gh:github" and mcp.details["plugin_enabled"] is True and mcp.details["version"] == "abc123"


# --- item 3: hostile project content -----------------------------------------


def test_project_symlink_to_root_is_not_followed(tmp_path):
    project = tmp_path / "repo"
    (project / ".claude/skills").mkdir(parents=True)
    os.symlink("/", project / ".claude/skills/evil")
    os.symlink("/etc/hostname", project / "CLAUDE.md")
    started = time.monotonic()
    items = claude_code.collect(tmp_path / "home", project)
    assert time.monotonic() - started < 2
    evil = next(i for i in items if i.name == "evil")
    assert evil.files == [] and evil.details == {"link": "/", "outside_project": True}
    claude_md = next(i for i in items if i.name == "CLAUDE.md")
    assert claude_md.details["outside_project"] is True
    assert {(f.rule, f.severity) for f in scan(items)} == {("R12", "high")}


def test_symlink_inside_project_is_followed(tmp_path):
    project = tmp_path / "repo"
    write(project / "shared/pdf/SKILL.md", "# pdf")
    (project / ".claude/skills").mkdir(parents=True)
    os.symlink("../../shared/pdf", project / ".claude/skills/pdf")
    [skill] = [i for i in claude_code.collect(tmp_path / "home", project) if i.kind == "skill"]
    assert [f.path for f in skill.files] == ["SKILL.md"] and "outside_project" not in skill.details


def test_user_scope_symlinks_still_followed(tmp_path):
    home = tmp_path
    write(home / ".agents/skills/docx/SKILL.md", "# docx")
    (home / ".claude/skills").mkdir(parents=True)
    os.symlink("../../.agents/skills/docx", home / ".claude/skills/docx")
    [skill] = [i for i in claude_code.collect(home, None) if i.kind == "skill"]
    assert skill.files and skill.details["link"] == "../../.agents/skills/docx"


def test_tree_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(model, "MAX_TREE_FILES", 5)
    d = tmp_path / "skill"
    for n in range(10):
        write(d / f"f{n}.md", "x")
    item = common.skill_item("claude-code", d, "user")
    assert len(item.files) == 5 and item.details["truncated"] is True
    assert ("R12", "medium") in {(f.rule, f.severity) for f in scan([item])}


def test_fifo_and_huge_config_are_refused(tmp_path, monkeypatch):
    os.mkfifo(tmp_path / ".mcp.json")
    with pytest.raises(CollectError, match="not a regular file"):
        read_json(tmp_path / ".mcp.json")
    monkeypatch.setattr("rigseal.readers.MAX_CONFIG_BYTES", 10)
    write(tmp_path / "big.json", json.dumps({"x": "y" * 50}))
    with pytest.raises(CollectError, match="over"):
        read_json(tmp_path / "big.json")


def test_hostile_repo_check_is_fast_and_fails(tmp_path):
    home, project = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    (project / ".claude/skills").mkdir(parents=True)
    os.symlink("/", project / ".claude/skills/evil")
    started = time.monotonic()
    r = CliRunner().invoke(app, ["check", "--repo", "--home", str(home), "-p", str(project)])
    assert time.monotonic() - started < 3
    assert r.exit_code == 1 and "outside the project" in r.output


# --- item 2: the agent should not approve its own changes ---------------------


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(write(tmp_path / "gitconfig", "[user]\n\temail = dev@example.com\n")))
    home, project = tmp_path / "home", tmp_path / "proj"
    write(home / ".claude/skills/pdf/SKILL.md", "# pdf")
    write(project / ".mcp.json", json.dumps({"mcpServers": {"db": {"command": "db-mcp"}}}))
    return home, project


def cli(env, *args, **kw):
    home, project = env
    return CliRunner().invoke(app, [*args, "--home", str(home), "-p", str(project)], **kw)


def test_approve_without_terminal_is_refused(env, monkeypatch):
    monkeypatch.setenv("RIGSEAL_NONINTERACTIVE", "1")
    assert cli(env, "init", "--no-sign").exit_code == 0
    monkeypatch.delenv("RIGSEAL_NONINTERACTIVE")
    write(env[1] / ".mcp.json", json.dumps({"mcpServers": {"evil": {"command": "bash"}}}))
    r = cli(env, "approve", "--no-sign")
    assert r.exit_code == 2 and "person at a terminal" in r.output
    assert cli(env, "init", "--no-sign", "--force").exit_code == 2


def test_approve_shows_changes_and_asks(env, monkeypatch):
    monkeypatch.setenv("RIGSEAL_NONINTERACTIVE", "1")
    cli(env, "init", "--no-sign")
    monkeypatch.delenv("RIGSEAL_NONINTERACTIVE")
    monkeypatch.setattr("rigseal.cli._interactive", lambda: True)
    write(env[1] / ".mcp.json", json.dumps({"mcpServers": {"evil": {"command": "bash", "args": ["-c", "x"]}}}))

    r = cli(env, "approve", "--no-sign", input="n\n")
    assert r.exit_code == 1 and "+ claude-code/project/mcp/evil" in r.output and "R2" in r.output
    assert "evil" not in (env[1] / "rigseal.lock").read_text()
    r = cli(env, "approve", "--no-sign", input="y\n")
    assert r.exit_code == 0 and "evil" in (env[1] / "rigseal.lock").read_text()


def test_signed_lock_cannot_be_silently_downgraded(env, tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setenv("RIGSEAL_NONINTERACTIVE", "1")
    key = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    assert cli(env, "init", "--key", str(key)).exit_code == 0
    write(env[1] / ".mcp.json", json.dumps({"mcpServers": {"evil": {"command": "bash"}}}))
    r = cli(env, "approve")
    assert r.exit_code == 2 and "would drop the signature" in r.output
    assert cli(env, "init", "--force").exit_code == 2
    assert cli(env, "approve", "--allow-unsigned").exit_code == 0


def test_allowed_signers_makes_signature_required(env, monkeypatch):
    monkeypatch.setenv("RIGSEAL_NONINTERACTIVE", "1")
    cli(env, "init", "--no-sign")
    assert cli(env, "check").exit_code == 0
    write(env[1] / ".rigseal/allowed_signers", 'dev@example.com namespaces="rigseal" ssh-ed25519 AAAA\n')
    r = cli(env, "check")
    assert r.exit_code == 1 and "is not signed" in " ".join(r.output.split())


# --- item 4: dogfood log ------------------------------------------------------


def test_dogfood_report_counts_each_pending_change_once(tmp_path, monkeypatch, capsys):
    import importlib.util

    spec = importlib.util.spec_from_file_location("dogfood", Path(__file__).parent.parent / "evals" / "dogfood.py")
    dogfood = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dogfood)
    log = tmp_path / "dogfood.jsonl"
    monkeypatch.setattr(dogfood, "LOG", log)
    plugin = {"key": "claude-code/plugin/plugin/hud", "status": "changed", "reason": "auto-update", "files": 3, "rules": []}
    skill = {"key": "claude-code/user/skill/pdf", "status": "changed", "reason": "user-change", "files": 1, "rules": ["R14"]}
    lines = [
        {"at": "2026-11-01T09:00:00Z", "exit": 1, "changes": [plugin]},
        {"at": "2026-11-02T09:00:00Z", "exit": 1, "changes": [plugin, skill]},  # plugin still pending: not a new event
        {"at": "2026-11-08T09:00:00Z", "exit": 2, "error": "boom"},
    ]
    log.write_text("".join(json.dumps(x) + "\n" for x in lines))
    assert dogfood.report() == 0
    out = capsys.readouterr().out
    assert "3 checks" in out and "7 days), 1 errors" in out
    assert "2 distinct drift events, 2.0 per week" in out
    assert "auto-update     1" in out and "1 events had rule findings" in out
    assert dogfood.classify({"key": "codex/plugin/mcp/gh:github"}) == "auto-update"


# --- wrong shapes, secrets and folders the agents read -------------------------


def make_plugin(home: Path, name: str, manifest: dict | None = None, files: dict | None = None) -> Path:
    root = home / ".claude/plugins/cache/m" / name / "1.0"
    root.mkdir(parents=True)
    if manifest is not None:
        write(root / ".claude-plugin/plugin.json", json.dumps({"name": name, **manifest}))
    for rel, doc in (files or {}).items():
        write(root / rel, json.dumps(doc))
    return root


def test_plugin_mcp_in_every_form_claude_code_reads(tmp_path):
    """`.mcp.json` at the plugin root is read first, then what the manifest lists: a path, a map, or a list of both."""
    home, node = tmp_path, {"command": "node"}
    roots = {
        "flat": make_plugin(home, "flat", {}, {".mcp.json": {"db": node}}),  # no mcpServers wrapper
        "both": make_plugin(home, "both", {"mcpServers": {"inline": node}}, {".mcp.json": {"mcpServers": {"fromfile": node}}}),
        "arr": make_plugin(home, "arr", {"mcpServers": ["./mcp/s.json", {"inl": node}]}, {"mcp/s.json": {"mcpServers": {"viaarray": node}}}),
        "path": make_plugin(home, "path", {"mcpServers": "./s.json"}, {"s.json": {"viapath": node}, ".mcp.json": {"mcpServers": {"rootfile": node}}}),
        "later": make_plugin(home, "later", {"mcpServers": {"same": {"command": "second"}}}, {".mcp.json": {"mcpServers": {"same": {"command": "first"}}}}),
        "bundle": make_plugin(home, "bundle", {"mcpServers": "./db.mcpb"}),
    }
    (roots["bundle"] / "db.mcpb").write_bytes(b"PK\x03\x04\xff\xfe not json")  # a packaged server: not opened, and no error
    installs = {f"{n}@m": [{"installPath": str(p), "version": "1.0"}] for n, p in roots.items()}
    write(home / ".claude/plugins/installed_plugins.json", json.dumps({"plugins": installs}))
    items = claude_code.collect(home, None)
    names = ("flat:db", "both:inline", "both:fromfile", "arr:viaarray", "arr:inl", "path:viapath", "path:rootfile", "later:same")
    assert rows(items, "mcp") == {("plugin", n) for n in names}
    assert next(i for i in items if i.name == "later:same").details["command"] == "second"


@pytest.mark.parametrize("record", [{"version": "1"}, {"installPath": "", "version": "1"}, {"installPath": "relative/dir", "version": "1"}])
def test_install_record_without_a_usable_path_is_missing_not_the_current_folder(tmp_path, monkeypatch, record):
    home, here = tmp_path / "home", tmp_path / "here"
    write(here / "relative/dir/notes.txt", "x")
    monkeypatch.chdir(here)
    write(home / ".claude/plugins/installed_plugins.json", json.dumps({"plugins": {"p@m": [record]}}))
    [item] = claude_code.collect(home, None)
    assert item.details["missing"] is True and item.files == []


@pytest.mark.parametrize("plugins", [[], {"p@m": "x"}, {"p@m": ["x", 5, None]}, {"p@m": {"version": "1"}}])
def test_odd_install_records_do_not_crash(tmp_path, plugins):
    write(tmp_path / ".claude/plugins/installed_plugins.json", json.dumps({"plugins": plugins}))
    assert all(i.details.get("missing") for i in claude_code.collect(tmp_path, None))


@pytest.mark.parametrize("doc", [{"projects": "x"}, {"projects": {"PROJECT": 5}}, {"projects": {"PROJECT": {"mcpServers": []}}}, {"mcpServers": []}])
def test_odd_claude_json_does_not_crash(tmp_path, doc):
    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir()
    write(home / ".claude.json", json.dumps(doc).replace("PROJECT", str(project)))
    assert claude_code.collect(home, project) == []


def test_secrets_in_a_url_or_a_command_line_stay_out_of_details(tmp_path):
    servers = {
        "api": {"type": "http", "url": "https://svc-user:tok_live_9f8e@mcp.example.com:8443/mcp?key=abc"},
        "pg": {"command": "npx -y server-postgres postgresql://admin:S3cret@db.internal/prod"},
        "plain": {"command": "/opt/tools/server", "args": ["--token", "S3cret"]},
    }
    write(tmp_path / ".claude.json", json.dumps({"mcpServers": servers}))
    items = {i.name: i for i in claude_code.collect(tmp_path, None)}
    assert items["api"].details["host"] == "mcp.example.com:8443"
    assert items["pg"].details["command"] == "npx ..."
    assert items["plain"].details["command"] == "/opt/tools/server"
    shown = json.dumps([i.to_dict() for i in items.values()])
    assert "S3cret" not in shown and "tok_live" not in shown


def test_json_with_a_byte_order_mark_is_read(tmp_path):
    f = tmp_path / "mcp.json"
    f.write_bytes(b"\xef\xbb\xbf" + json.dumps({"servers": {"gh": {"command": "gh-mcp"}}}).encode())
    assert read_json(f) == {"servers": {"gh": {"command": "gh-mcp"}}}


@pytest.mark.skipif(os.geteuid() == 0, reason="root can list any folder")
def test_a_folder_that_cannot_be_listed_is_an_error_not_a_crash(tmp_path):
    skills = tmp_path / ".claude/skills"
    write(skills / "pdf/SKILL.md", "# pdf")
    skills.chmod(0)
    try:
        with pytest.raises(CollectError):
            claude_code.collect(tmp_path, None)
    finally:
        skills.chmod(0o755)


def test_claude_rules_and_the_memory_file_in_dot_claude_are_tracked(tmp_path):
    home, project = tmp_path / "home", tmp_path / "proj"
    write(home / ".claude/rules/style.md", "be brief")
    write(project / ".claude/rules/api/rest.md", "use nouns")
    write(project / ".claude/CLAUDE.md", "project memory")
    write(project / "CLAUDE.md", "root memory")
    items = claude_code.collect(home, project)
    assert rows(items, "rule") == {("user", "style"), ("project", "api/rest")}
    assert rows(items, "instructions") == {("project", "CLAUDE.md"), ("project", ".claude/CLAUDE.md")}


def test_codex_config_with_odd_values_is_ignored_or_an_error_not_a_crash(tmp_path):
    write(tmp_path / ".codex/config.toml", "plugins = 5\n")
    write(tmp_path / ".codex/plugins/cache/m/p/1.0/x.md", "x")
    assert rows(codex.collect(tmp_path, None), "plugin") == {("plugin", "p@m")}
    write(tmp_path / ".codex/config.toml", "n = " + "9" * 5000 + "\n")
    with pytest.raises(CollectError):
        codex.collect(tmp_path, None)


def test_a_folder_linked_under_many_names_is_hashed_once_per_scan(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "proj"
    write(project / "assets/data/a.md", "x")
    (project / ".claude/skills").mkdir(parents=True)
    for i in range(30):
        (project / f".claude/skills/s{i}").symlink_to("../../assets/data")
    calls = []
    real = model._hash_tree
    monkeypatch.setattr(model, "_hash_tree", lambda root, ignore: calls.append(root) or real(root, ignore))
    r = CliRunner().invoke(app, ["status", "--json", "--home", str(home), "-p", str(project)])
    assert len(json.loads(r.stdout)) == 30 and len(calls) == 1


def test_a_damaged_analysis_cache_is_dropped_entry_by_entry(tmp_path):
    path = tmp_path / "analysis.json"
    entries = {
        "a:.md": {"hits": [["R10", "high", "reverse shell pattern"]], "shell": True},
        "b:.md": 5,
        "c:.md": {"hits": [["R10", "urgent", "x"]]},
        "d:.md": {"hits": "x"},
        "e:.md": {"hosts": [1]},
        "f:.md": {"hidden": {"tag": "many"}},
    }
    path.write_text(json.dumps({"version": analysis_version(), "entries": entries}))
    assert set(Cache(path).entries) == {"a:.md"}
    path.write_text(json.dumps({"version": analysis_version(), "entries": ["x"]}))
    assert Cache(path).entries == {}
