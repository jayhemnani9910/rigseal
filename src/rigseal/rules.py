"""Detection rules. Each looks at one item and returns findings.

Rules may read item.raw (real config values) but a finding's message only names the pattern that matched,
never the values themselves.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import PurePath

from rigseal.capabilities import hidden_chars
from rigseal.lock import item_key
from rigseal.model import Finding, Item
from rigseal.text_rules import followed_by, text_findings

SEVERITIES = ("high", "medium", "low")

SHELLS = {"bash", "sh", "zsh", "dash", "fish", "ksh", "pwsh", "powershell", "cmd", "cmd.exe"}
INLINE_FLAGS = {"-c", "/c", "-command", "-encodedcommand", "-e", "--eval", "-ec"}
INTERPRETERS = {"python", "python3", "node", "perl", "ruby", "deno", "bun"}
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
RUNNERS = {"npx": 0, "bunx": 0, "uvx": 0, "pnpx": 0}  # package is the first non-flag arg
BASE_URL_ENV = re.compile(r"(_BASE_URL|_API_URL|_ENDPOINT|^HTTPS?_PROXY|^ALL_PROXY)$", re.I)
# Bash, Bash(*), and a shell as the command prefix, which also allows any command: Bash(bash:*), Bash(sh *).
BROAD_BASH = re.compile(rf"^Bash(\((\*|\*\*|\*:\*|({'|'.join(re.escape(s) for s in sorted(SHELLS))})[: ]\*)\))?$")
NOT_POSIX = {"pwsh", "powershell", "cmd", "cmd.exe"}  # their long single-dash flags aren't clusters
CURL_PIPE_SH = re.compile(followed_by(r"\b(curl|wget)\b", r"\|\s*(ba|z|da)?sh\b", r"[^|]"))
C_CLUSTER = re.compile(r"^-[a-zA-Z]*c[a-zA-Z]*$")  # bash -lc, sh -xc, python3 -uc
E_CLUSTER = re.compile(r"^-[a-zA-Z]*e[a-zA-Z]*$")  # perl -ne, ruby -pe


def _base(cmd: object) -> str:
    return PurePath(str(cmd)).name.lower()


def _mcp_parts(item: Item) -> tuple[str, list[str]] | None:
    cfg = item.raw
    if not isinstance(cfg, dict) or "command" not in cfg:
        return None
    args = cfg.get("args") or []
    return str(cfg["command"]), [str(a) for a in args] if isinstance(args, list) else []


def _inline_shell_flag(base: str, args: list[str]) -> str | None:
    if exact := sorted({a.lower() for a in args} & INLINE_FLAGS):
        return exact[0]
    return None if base in NOT_POSIX else next((a for a in args if C_CLUSTER.match(a)), None)


def _runs_inline_code(name: str, args: list[str]) -> bool:
    if {a.lower() for a in args} & INLINE_FLAGS:
        return True
    if name == "python":
        return any(C_CLUSTER.match(a) for a in args)
    if name in ("perl", "ruby"):
        return any(E_CLUSTER.match(a) for a in args)
    if name in ("node", "bun"):
        return bool({"-p", "--print", "-pe"} & set(args))
    return name == "deno" and args[:1] == ["eval"]


def r2_risky_stdio(item: Item) -> list[Finding]:
    if item.kind != "mcp" or not (parts := _mcp_parts(item)):
        return []
    cmd, args = parts
    base = _base(cmd)
    key, out = item_key(item), []

    def hit(msg: str) -> None:
        out.append(Finding("R2", "high", key, msg))

    if base in SHELLS and (flag := _inline_shell_flag(base, args)):
        hit(f"MCP server runs inline shell code ({base} {flag})")
    if (name := base.rstrip("0123456789.")) in INTERPRETERS and _runs_inline_code(name, args):
        hit(f"MCP server runs inline {base} code")
    joined = " ".join([cmd, *args])
    if CURL_PIPE_SH.search(joined):
        hit("MCP server pipes a download into a shell (curl | sh)")
    if str(cmd).startswith(TEMP_DIRS):
        hit("MCP server binary lives in a temp folder")
    return out


PACKAGE_FLAGS = {"-p", "--package", "--from"}  # the next arg is the package
VALUE_FLAGS = {"--with", "--python", "--index-url", "--registry", "--cache"}  # the next arg is something else


def _package_arg(args: list[str]) -> str | None:
    it = iter(args)
    for a in it:
        if a in PACKAGE_FLAGS:
            return next(it, None)
        if a in VALUE_FLAGS:
            next(it, None)
        elif not a.startswith("-"):
            return a
    return None


def _pinned(pkg: str, runner: str) -> bool:
    if runner == "uvx":
        return bool(re.search(r"(==|@)\d", pkg))
    _, _, version = pkg[1:].partition("@") if pkg.startswith("@") else pkg.partition("@")
    return bool(re.match(r"\d", version))


def r16_unpinned_runner(item: Item) -> list[Finding]:
    if item.kind != "mcp" or not (parts := _mcp_parts(item)):
        return []
    cmd, args = parts
    runner = _base(cmd)
    if runner == "pnpm" and args[:1] == ["dlx"]:
        runner, args = "pnpx", args[1:]
    if runner not in RUNNERS or not (pkg := _package_arg(args)):
        return []
    if _pinned(pkg, runner):
        return []
    return [Finding("R16", "medium", item_key(item), f"{runner} runs {pkg.split('==')[0]} without a pinned version")]


def r3_self_approving_project(item: Item) -> list[Finding]:
    if item.kind != "settings" or item.scope != "project" or not isinstance(item.raw, dict):
        return []
    data, key, out = item.raw, item_key(item), []

    def hit(sev: str, msg: str) -> None:
        out.append(Finding("R3", sev, key, msg))

    if item.agent == "claude-code":
        if data.get("enableAllProjectMcpServers") is True:
            hit("high", "repo turns on every MCP server in .mcp.json without asking (enableAllProjectMcpServers)")
        if data.get("enabledMcpjsonServers"):
            hit("high", "repo pre-approves its own MCP servers (enabledMcpjsonServers)")
        perms = data.get("permissions") or {}
        if isinstance(perms, dict):
            allow = perms.get("allow")
            if isinstance(allow, list) and any(isinstance(p, str) and BROAD_BASH.match(p) for p in allow):
                hit("high", "repo allows any shell command (permissions.allow Bash(*))")
            if perms.get("defaultMode") == "bypassPermissions":
                hit("high", "repo turns off permission prompts (defaultMode bypassPermissions)")
        if data.get("hooks"):
            hit("high", "repo defines hooks, which run shell commands on agent events")
        if "apiKeyHelper" in data:
            hit("high", "repo sets apiKeyHelper, a command that runs to fetch your API key")
        env = data.get("env") or {}
        if isinstance(env, dict) and any(BASE_URL_ENV.search(k) for k in env):
            hit("high", "repo redirects API traffic through env (*_BASE_URL / proxy)")
    elif item.agent == "codex":
        if data.get("approval_policy") == "never":
            hit("high", "repo config turns off approvals (approval_policy = never)")
        if data.get("sandbox_mode") == "danger-full-access":
            hit("high", "repo config turns off the sandbox (danger-full-access)")
        if data.get("hooks"):
            hit("high", "repo config defines hooks, which run shell commands")
        if data.get("model_providers"):
            hit("high", "repo config adds model providers, which can redirect API traffic")
    elif item.agent == "cursor" and data.get("hooks"):
        hit("high", "repo defines Cursor hooks, which run shell commands")
    return out


def r15_hidden_unicode(item: Item) -> list[Finding]:
    found: dict[str, dict[str, int]] = dict((item.details.get("capabilities") or {}).get("hidden_chars") or {})
    if item.raw is not None and (in_cfg := hidden_chars(json.dumps(item.raw, ensure_ascii=False, default=str))):
        found["config"] = in_cfg
    return [
        Finding(
            "R15",
            "high",
            item_key(item),
            f"hidden characters in {where}: " + ", ".join(f"{k} x{n}" for k, n in kinds.items()),
            file=None if where == "config" else where,
        )
        for where, kinds in sorted(found.items())
    ]


def r18_undeclared(item: Item) -> list[Finding]:
    if item.kind not in ("skill", "command", "agent"):
        return []
    caps = item.details.get("capabilities") or {}
    if not caps.get("shell") and not caps.get("network"):
        return []
    uses = " and ".join(k for k in ("shell", "network") if caps.get(k))
    tools = caps.get("allowed_tools")
    if tools is None:
        return [Finding("R18", "low", item_key(item), f"uses {uses} but declares no allowed-tools")]
    names = {t.split("(")[0] for t in tools}
    missing = [k for k in ("shell", "network") if caps.get(k) and not ({"Bash"} if k == "shell" else {"Bash", "WebFetch"}) & names]
    if missing:
        return [Finding("R18", "medium", item_key(item), f"uses {' and '.join(missing)} but allowed-tools doesn't allow it")]
    return []


def r12_containment(item: Item) -> list[Finding]:
    """R12 (structure): links that leave the project, and folders too big to hash fully."""
    out = []
    if item.details.get("outside_project"):
        out.append(Finding("R12", "high", item_key(item), "links to a path outside the project (not followed)"))
    if item.details.get("truncated"):
        out.append(Finding("R12", "medium", item_key(item), "too many files or bytes to hash fully"))
    return out


RULES: list[Callable[[Item], list[Finding]]] = [
    r2_risky_stdio,
    r3_self_approving_project,
    r15_hidden_unicode,
    r16_unpinned_runner,
    r18_undeclared,
    text_findings,
    r12_containment,
]


def scan(items: list[Item]) -> list[Finding]:
    findings = [f for item in items for rule in RULES for f in rule(item)]
    return sorted(findings, key=lambda f: (SEVERITIES.index(f.severity), f.rule, f.key))


def r1_mcp_drift(key: str, kind: str, status: str) -> Finding | None:
    """R1: any MCP config change that wasn't approved."""
    if kind != "mcp":
        return None
    return Finding("R1", "high", key, f"MCP server {status} since last approve")
