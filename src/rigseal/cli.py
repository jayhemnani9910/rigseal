from __future__ import annotations

import json
import os
import shutil
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from rigseal import __version__
from rigseal import lock as lk
from rigseal import hook_config, hooks, rules, sarif, signing
from rigseal import watch as wt
from rigseal.cache import Cache, cache_path
from rigseal.capabilities import enrich
from rigseal.collectors import AGENTS_OF, COLLECTORS
from rigseal.model import CollectError, Finding, Item
from rigseal.signing import SignError

app = typer.Typer(no_args_is_help=True, add_completion=False)
out = Console()
err = Console(stderr=True)

ProjectOpt = Annotated[Path, typer.Option("--project", "-p", help="Project folder to inspect.", exists=True, file_okay=False)]
HomeOpt = Annotated[Path, typer.Option(hidden=True)]
JsonOpt = Annotated[bool, typer.Option("--json", help="Print JSON.")]
SarifOpt = Annotated[bool, typer.Option("--sarif", help="Print SARIF 2.1.0 (for GitHub code scanning).")]
RepoOpt = Annotated[bool, typer.Option("--repo", help="Only the repo lock (for CI).")]
KeyOpt = Annotated[Path | None, typer.Option("--key", help="SSH key to sign with (default: $RIGSEAL_SIGNING_KEY, then git user.signingkey).")]
NoSignOpt = Annotated[bool, typer.Option("--no-sign", help="Do not sign.")]
AllowUnsignedOpt = Annotated[bool, typer.Option("--allow-unsigned", help="Allow replacing a signed lock with an unsigned one.")]
AllowedSignersOpt = Annotated[
    Path | None,
    typer.Option("--allowed-signers", help="Signer list from outside the repo that must also accept the repo lock (default: $RIGSEAL_ALLOWED_SIGNERS, then ~/.rigseal/allowed_signers)."),
]


def _version(value: bool) -> None:
    if value:
        out.print(__version__, highlight=False)
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", help="Print the version and exit.", callback=_version, is_eager=True),
    ] = None,
) -> None:
    """A lockfile for your AI agent setup."""


def safe(text: object) -> str:
    """For printing anything that comes from a config or repo: it can't act as Rich markup or break the terminal encoding."""
    return escape(str(text).encode("utf-8", "backslashreplace").decode())


def inventory(home: Path, project: Path | None, errors: dict[str, str] | None = None) -> list[Item]:
    """Everything the agents load. With `errors`, an agent whose config can't be read is recorded there and skipped."""
    items: list[Item] = []
    for collect in COLLECTORS:
        try:
            items += collect(home, project)
        except Exception as e:
            if errors is None:
                raise
            errors.update(dict.fromkeys(AGENTS_OF[collect], str(e) or type(e).__name__))
    cache = Cache(cache_path(home))
    enrich(items, cache)
    cache.save()
    return items


def _fail(message: str) -> typer.Exit:
    err.print(f"[red]error:[/red] {safe(message)}")
    return typer.Exit(2)


def _paths(home: Path, project: Path) -> tuple[Path, Path | None]:
    """Resolve paths. The project is None when it is the home folder itself, so user config isn't counted twice."""
    home, project = home.expanduser().resolve(), project.resolve()
    return home, None if project == home else project


@dataclass
class Ctx:
    home: Path
    project: Path | None
    items: list[Item]
    current: lk.Current
    repo: lk.Lock | None
    machine: lk.Lock | None

    @property
    def project_key(self) -> str:
        return str(self.project) if self.project else ""


def _load(home: Path, project: Path, errors: dict[str, str] | None = None) -> Ctx:
    home, proj = _paths(home, project)
    items = inventory(home, proj, errors)
    repo = lk.read_lock(lk.repo_lock_path(proj)) if proj else None
    machine = lk.read_lock(lk.machine_lock_path(home))
    return Ctx(home, proj, items, lk.split(items, home, proj or home), repo, machine)


def load(home: Path, project: Path) -> Ctx:
    try:
        return _load(home, project)
    except CollectError as e:
        raise _fail(str(e)) from e


def change_findings(ctx: Ctx, found: list[lk.Change]) -> dict[str, list[Finding]]:
    """Findings on added or changed items, plus R1 for any MCP drift, keyed by item key."""
    by_key: dict[str, list[Finding]] = {}
    for f in rules.scan(ctx.items):
        by_key.setdefault(f.key, []).append(f)
    kinds = {k: e["kind"] for part in (ctx.current.repo, ctx.current.machine, ctx.current.local) for k, e in part.items()}
    locked = [ctx.repo.items if ctx.repo else {}] + ([ctx.machine.items, *ctx.machine.projects.values()] if ctx.machine else [])
    for part in locked:
        kinds.update({k: e["kind"] for k, e in part.items() if k not in kinds})
    out: dict[str, list[Finding]] = {}
    for c in found:
        r1 = rules.r1_mcp_drift(c.key, kinds.get(c.key, ""), c.status)
        here = ([r1] if r1 else []) + (by_key.get(c.key, []) if c.status != "removed" else [])
        if here:
            out[c.key] = here
    return out


def changes(ctx: Ctx, repo_only: bool) -> list[lk.Change]:
    """Drift against the locks. A missing repo lock counts as empty, so a fresh clone's MCP servers show as added."""
    result = lk.diff_entries(ctx.repo.items if ctx.repo else {}, ctx.current.repo, "repo")
    if not repo_only:
        if ctx.machine is None:
            raise _fail(f"no machine lock at {lk.machine_lock_path(ctx.home)}. Run `rigseal init` first.")
        result += lk.diff_entries(ctx.machine.items, ctx.current.machine, "machine")
        result += lk.diff_entries(ctx.machine.projects.get(ctx.project_key, {}), ctx.current.local, "machine")
    return result


def drift(ctx: Ctx) -> tuple[list[lk.Change], str | None]:
    """All drift, for hooks and watch. Without a machine lock rigseal is not set up: nothing is checked, a note says so."""
    machine = ctx.machine
    if machine is None:
        return [], f"rigseal is not set up (no {lk.machine_lock_path(ctx.home)}); run `rigseal init`."
    problems = []
    if ctx.repo and ctx.project and (bad := lock_problems(ctx, ctx.repo, False)):  # a lock that fails its signature approves nothing
        problems += bad
        ctx.repo = lk.Lock(ctx.repo.path)
    if bad := lock_problems(ctx, machine, False):
        problems += bad
        ctx.machine = lk.Lock(machine.path)
    return changes(ctx, repo_only=False), "; ".join(problems) or None


def item_paths(ctx: Ctx) -> dict[str, str]:
    """Key -> absolute path, for current items and for locked ones that are gone."""
    out = {}
    locked = [(ctx.repo.items if ctx.repo else {}, ctx.project or ctx.home)]
    if ctx.machine:
        locked += [(ctx.machine.items, ctx.home), *((v, ctx.home) for v in ctx.machine.projects.values())]
    for entries, base in locked:
        for key, e in entries.items():
            path = str(e.get("path", ""))
            out[key] = str(ctx.home / path[2:] if path.startswith("~/") else base / path)
    out.update({lk.item_key(i): i.path for i in ctx.items})
    return out


def lock_problems(ctx: Ctx, lock: lk.Lock, require: bool, allowed: Path | None = None) -> list[str]:
    """Signature problems of one lock. A list inside the repo can be edited along with the lock, so the repo lock
    must also pass a list from outside it when there is one."""
    machine_list = lk.rigseal_dir(ctx.home) / "allowed_signers"
    project = ctx.project if lock is ctx.repo else None
    named = allowed or (Path(v).expanduser() if (v := os.environ.get("RIGSEAL_ALLOWED_SIGNERS")) else None)
    outside = (named or (machine_list if machine_list.is_file() else None)) if project else None
    signers = signing.allowed_signers_for(project / ".rigseal" / "allowed_signers" if project else machine_list, ctx.project)

    if not lock.sig_path.exists():
        if lock.signed_by:
            return [f"{lock.path} says it is signed by {lock.signed_by} but {lock.sig_path.name} is missing"]
        if require or signers.is_file() or (project and named):  # once signers are set up, unsigned is not ok
            return [f"{lock.path} is not signed"]
        return []
    if not lock.signed_by:
        return [f"{lock.path} has a signature but no signedBy"]
    lists = ([signers] if signers.is_file() or outside is None else []) + ([outside] if outside else [])
    try:
        for signer_list in dict.fromkeys(lists):
            signing.verify(lock.path, lock.signed_by, signer_list)
    except SignError as e:
        return [str(e)]
    if require and project and outside is None and signers.is_relative_to(project):
        return [f"{lock.path} is only checked against a signer list inside the repo, which anyone who can edit the lock can change. Pass --allowed-signers."]
    return []


def signature_problems(ctx: Ctx, repo_only: bool, require: bool, allowed: Path | None = None) -> list[str]:
    problems = []
    if ctx.repo and ctx.project:
        problems += lock_problems(ctx, ctx.repo, require, allowed)
    if ctx.machine and not repo_only:
        problems += lock_problems(ctx, ctx.machine, require)
    return problems


SEV_STYLE = {"high": "red", "medium": "yellow", "low": "dim"}


def finding_line(f: Finding) -> str:
    return f"[{SEV_STYLE[f.severity]}]{f.severity.upper():6}[/] {f.rule:4} {safe(f.message)}"


def print_changes(found: list[lk.Change], findings: dict[str, list[Finding]], all_files: bool = False) -> None:
    marks = {"added": "[green]+[/green]", "removed": "[red]-[/red]", "changed": "[yellow]~[/yellow]"}
    for c in found:
        out.print(f"{marks[c.status]} {safe(c.key)}  [dim]({c.lock} lock, {c.status})[/dim]")
        for f in findings.get(c.key, []):
            out.print(f"    {finding_line(f)}")
        if c.status != "changed":
            continue
        groups = (("changed", c.files_changed), ("new file", c.files_added), ("gone", c.files_removed))
        if c.key.split("/", 3)[2] == "plugin" and not all_files:  # a plugin update touches many files; what it can now do matters more
            counts = ", ".join(f"{len(files)} {label}" for label, files in groups if files)
            if counts:
                out.print(f"    files: {counts} [dim](`rigseal diff --files` lists them)[/dim]")
            if not c.capabilities:
                out.print("    [dim]no new capabilities detected[/dim]")
        else:
            for label, files in groups:
                for f in files:
                    out.print(f"    {label}: {safe(f)}")
        for line in c.capabilities:
            out.print(f"    [bold]{safe(line)}[/bold]")
        other = [d for d in c.details_changed if d != "capabilities"]
        if other:
            out.print(f"    details: {safe(', '.join(other))}")


def _notes(item: Item) -> str:
    d = item.details
    parts = []
    if d.get("risky_keys"):
        parts.append("risky: " + ", ".join(d["risky_keys"]))
    if d.get("transport"):
        parts.append(d["transport"] + (f" {d['command']}" if d.get("command") else "") + (f" {d['host']}" if d.get("host") else ""))
    if d.get("env_keys"):
        parts.append("env: " + ", ".join(d["env_keys"]))
    if d.get("version"):
        parts.append(f"v{d['version']}")
    if d.get("link"):
        parts.append(f"-> {d['link']}")
    if d.get("enabled") is False:
        parts.append("disabled")
    if d.get("missing"):
        parts.append("install folder missing")
    if item.kind == "skill" and not d.get("has_skill_md"):
        parts.append("no SKILL.md")
    return "; ".join(parts)


def _print_summary(ctx: Ctx) -> None:
    by_agent = Counter(i.agent for i in ctx.items)
    out.print(f"{len(ctx.items)} items: " + ", ".join(f"{agent} {n}" for agent, n in sorted(by_agent.items())))
    if ctx.machine is None:
        out.print("locks: [yellow]not set up[/yellow], run `rigseal setup`")
    else:
        found, note = drift(ctx)
        if note:
            out.print(f"[red]signature:[/red] {safe(note)}")
        out.print(f"locks: [yellow]{len(found)} changed[/yellow], run `rigseal diff`" if found else "locks: [green]0 changed[/green]")
    counts = Counter(f.severity for f in rules.scan(ctx.items))
    out.print("findings: " + ", ".join(f"{counts[s]} {s}" for s in rules.SEVERITIES) + (", run `rigseal scan`" if counts else ""))
    try:
        hook_state = [f"{t.agent} {'[yellow]missing[/yellow]' if hook_config.missing(t) else '[green]on[/green]'}" for t in hook_config.targets(ctx.home)]
    except CollectError as e:
        hook_state = [f"[red]unreadable[/red]: {safe(e)}"]
    if hook_state:
        out.print("hooks: " + ", ".join(hook_state))


@app.command()
def status(
    project: ProjectOpt = Path("."),
    show_all: Annotated[bool, typer.Option("--all", help="List every item.")] = False,
    as_json: JsonOpt = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Sum up what your agents load and whether it changed. --all lists every skill, plugin, hook and MCP server."""
    if not show_all and not as_json:
        _print_summary(load(home, project))
        return
    home, proj = _paths(home, project)
    try:
        items = inventory(home, proj)
    except CollectError as e:
        raise _fail(str(e)) from e

    if as_json:
        typer.echo(json.dumps([i.to_dict() for i in items], indent=2))
        return

    table = Table(show_lines=False)
    for col in ("agent", "scope", "kind", "name", "files", "hash", "notes"):
        table.add_column(col, overflow="fold")
    for i in items:
        table.add_row(i.agent, i.scope, i.kind, safe(i.name), str(len(i.files)), i.sha256[:12], safe(_notes(i)))
    out.print(table)
    typer.echo(f"{len(items)} items")


@app.command()
def diff(
    project: ProjectOpt = Path("."),
    repo_only: RepoOpt = False,
    all_files: Annotated[bool, typer.Option("--files", help="List every file of a changed plugin.")] = False,
    as_json: JsonOpt = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Show what changed since the last approve."""
    ctx = load(home, project)
    found = changes(ctx, repo_only)
    findings = change_findings(ctx, found)
    if as_json:
        typer.echo(json.dumps([{**c.to_dict(), **_findings_json(findings, c.key)} for c in found], indent=2))
    elif found:
        print_changes(found, findings, all_files)
    else:
        out.print("no drift")


def _findings_json(findings: dict[str, list[Finding]], key: str) -> dict:
    return {"findings": [f.to_dict() for f in findings[key]]} if key in findings else {}


@app.command()
def check(
    project: ProjectOpt = Path("."),
    repo_only: RepoOpt = False,
    require_signature: Annotated[bool, typer.Option("--require-signature", help="Fail if a lock is unsigned.")] = False,
    allowed_signers: AllowedSignersOpt = None,
    as_json: JsonOpt = False,
    as_sarif: SarifOpt = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Exit 0 if nothing changed and signatures are valid, 1 if not, 2 on error."""
    ctx = load(home, project)
    found = changes(ctx, repo_only)
    findings = change_findings(ctx, found)
    problems = signature_problems(ctx, repo_only, require_signature, allowed_signers)
    if as_sarif:
        flat = [f for fs in findings.values() for f in fs]
        typer.echo(json.dumps(sarif.report(ctx.items, flat, found, ctx.project, problems), indent=2))
    elif as_json:
        changes_json = [{**c.to_dict(), "sha256": c.sha256, **_findings_json(findings, c.key)} for c in found]
        typer.echo(json.dumps({"changes": changes_json, "signature_problems": problems}, indent=2))
    else:
        for p in problems:
            out.print(f"[red]signature:[/red] {safe(p)}")
        print_changes(found, findings)
        out.print(f"{len(found)} change(s), {len(problems)} signature problem(s)" if found or problems else "ok")
    if found or problems:
        raise typer.Exit(1)


def _save(lock: lk.Lock, key: Path | None, signer: str) -> str:
    """Write the lock, signed if there is a key. Without one an old signature is removed, since it no longer matches."""
    lock.signed_by = signer if key else None
    if key is None:
        lock.write()
        lock.sig_path.unlink(missing_ok=True)
        return f"wrote {safe(lock.path)} [yellow](unsigned)[/yellow]"
    lock.write(lambda path: signing.sign(path, key))
    return f"wrote and signed {safe(lock.path)}"


def _approve(ctx: Ctx, keys: set[str] | None, key: Path | None) -> list[str]:
    who, when = signing.identity(ctx.project), lk.now()
    notes = []
    if ctx.project and (ctx.repo or ctx.current.repo):
        old = ctx.repo or lk.Lock(lk.repo_lock_path(ctx.project))
        new_items = lk.apply(old.items, ctx.current.repo, keys, who, when)
        if ctx.repo is None or new_items != old.items:
            notes.append(_save(lk.Lock(old.path, new_items), key, who))

    old_m = ctx.machine or lk.Lock(lk.machine_lock_path(ctx.home))
    new_m = lk.apply(old_m.items, ctx.current.machine, keys, who, when)
    projects = dict(old_m.projects)
    if ctx.project:
        entries = lk.apply(projects.get(ctx.project_key, {}), ctx.current.local, keys, who, when)
        if entries:
            projects[ctx.project_key] = entries
        else:
            projects.pop(ctx.project_key, None)
    if ctx.machine is None or new_m != old_m.items or projects != old_m.projects:
        notes.append(_save(lk.Lock(old_m.path, new_m, projects), key, who))
    return notes


def _interactive() -> bool:
    return sys.stdin.isatty()


def _require_person() -> None:
    """Approving is a human decision. An agent running rigseal through a tool call has no terminal.
    CI and scripts can opt out with RIGSEAL_NONINTERACTIVE=1. See docs/threat-model.md for what this does not stop."""
    if os.environ.get("RIGSEAL_NONINTERACTIVE") == "1":
        return
    if not _interactive():
        raise _fail("approving needs a person at a terminal.")


def _trust_own_key(ctx: Ctx, key: Path | None, no_sign: bool) -> None:
    """First setup only: with no signer list, locks signed with this key would fail their own check and approve nothing."""
    signers = lk.rigseal_dir(ctx.home) / "allowed_signers"
    sign_key = None if no_sign else signing.signing_key(key, ctx.project)
    if sign_key is None or signers.exists():
        return
    try:
        line = f'{signing.identity(ctx.project)} namespaces="{signing.NAMESPACE}" {signing.public_key(sign_key)}\n'
    except SignError as e:
        raise _fail(str(e)) from e
    signers.parent.mkdir(parents=True, exist_ok=True)
    signers.write_text(line)
    out.print(f"trusting your signing key in {safe(signers)}")


def _run_approve(ctx: Ctx, keys: set[str] | None, key: Path | None, no_sign: bool, allow_unsigned: bool) -> None:
    sign_key = None if no_sign else signing.signing_key(key, ctx.project)
    signed = [lock for lock in (ctx.repo, ctx.machine) if lock and lock.signed_by]
    if sign_key is None and signed and not allow_unsigned:
        raise _fail(
            f"{signed[0].path} is signed; approving without a key would drop the signature. "
            "Pass --key, or --allow-unsigned if that is what you want."
        )
    try:
        for note in _approve(ctx, keys, sign_key):
            out.print(note)
    except SignError as e:
        raise _fail(str(e)) from e


@app.command()
def init(
    project: ProjectOpt = Path("."),
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing locks.")] = False,
    key: KeyOpt = None,
    no_sign: NoSignOpt = False,
    allow_unsigned: AllowUnsignedOpt = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Write the machine lock, and the repo lock if this project has agent config."""
    ctx = load(home, project)
    _require_person()
    existing = [str(lock.path) for lock in (ctx.repo, ctx.machine) if lock]
    if existing and not force:
        raise _fail(f"lock already exists: {', '.join(existing)}. Use `rigseal approve`, or --force.")
    old_repo, old_machine = ctx.repo, ctx.machine
    if (old_repo and old_repo.signed_by) or (old_machine and old_machine.signed_by):
        sign_key = None if no_sign else signing.signing_key(key, ctx.project)
        if sign_key is None and not allow_unsigned:
            raise _fail("the existing lock is signed; --force without a key would drop the signature. Pass --key or --allow-unsigned.")
    ctx.repo = ctx.machine = None
    _trust_own_key(ctx, key, no_sign)
    _run_approve(ctx, None, key, no_sign, allow_unsigned=True)


@app.command()
def setup(
    project: ProjectOpt = Path("."),
    key: KeyOpt = None,
    no_sign: NoSignOpt = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Don't ask.")] = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Turn rigseal on: add its hooks to the agents you use and lock what they load today."""
    _require_person()
    if shutil.which("rigseal") is None:  # the hooks call `rigseal` by name; without it the MCP gate would silently not run
        raise _fail("`rigseal` is not on your PATH, so the hooks could not run. Install it with `uv tool install`, see the README.")
    ctx = load(home, project)
    try:
        todo = [(t, events) for t in hook_config.targets(ctx.home) if (events := hook_config.missing(t))]
    except CollectError as e:
        raise _fail(str(e)) from e
    fresh = ctx.machine is None
    if not todo and not fresh:
        out.print("already set up. `rigseal status` shows where things stand.")
        return

    for target, events in todo:
        out.print(f"add {target.agent} hooks to {safe(target.path)}: {', '.join(events)}")
    if fresh:
        out.print(f"lock the {len(ctx.items)} items your agents load today")
    if not yes and os.environ.get("RIGSEAL_NONINTERACTIVE") != "1" and not typer.confirm("Go ahead?", default=True):
        raise typer.Exit(1)

    for target, _ in todo:
        hook_config.add(target)
        out.print(f"[green]hooks on[/green] for {target.agent}")
    if not fresh:
        out.print("Your settings changed, so run `rigseal approve` once to accept the new hooks.")
        return

    ctx = load(home, project)  # the settings just changed, and the lock must include the new hooks
    # A repo lock that already exists belongs to the repo's reviewers. Only the machine lock is new.
    keys = (set(ctx.current.machine) | set(ctx.current.local)) if ctx.repo else None
    _trust_own_key(ctx, key, no_sign)
    _run_approve(ctx, keys, key, no_sign, allow_unsigned=True)
    high = sum(f.severity == "high" for f in rules.scan(ctx.items))
    if high:
        out.print(f"[yellow]{high} high finding(s) in what you just locked.[/yellow] Run `rigseal scan` to read them.")


@app.command()
def approve(
    keys: Annotated[list[str] | None, typer.Argument(help="Item keys to approve (default: all changes).")] = None,
    project: ProjectOpt = Path("."),
    key: KeyOpt = None,
    no_sign: NoSignOpt = False,
    allow_unsigned: AllowUnsignedOpt = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Don't ask; approve what is listed.")] = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Accept the current state into the locks. Shows what you are approving and asks first."""
    _require_person()
    ctx = load(home, project)
    pending = changes(ctx, repo_only=False)
    wanted = set(keys) if keys else None
    if wanted and (unknown := wanted - {c.key for c in pending}):
        raise _fail(f"not a pending change: {', '.join(sorted(unknown))}. See `rigseal diff`.")
    if not pending:
        out.print("nothing to approve")
        return
    if not yes and os.environ.get("RIGSEAL_NONINTERACTIVE") != "1":
        shown = [c for c in pending if wanted is None or c.key in wanted]
        print_changes(shown, change_findings(ctx, shown))
        if not typer.confirm(f"Approve {len(shown)} change(s)?", default=False):
            raise typer.Exit(1)
    _run_approve(ctx, wanted, key, no_sign, allow_unsigned)


@app.command()
def scan(
    project: ProjectOpt = Path("."),
    fail_on: Annotated[str, typer.Option("--fail-on", help="Exit 1 at this severity or worse: high, medium, low, never.")] = "high",
    show_all: Annotated[bool, typer.Option("--all", help="Also show low findings.")] = False,
    as_json: JsonOpt = False,
    as_sarif: SarifOpt = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Run the rules on everything your agents load, approved or not."""
    if fail_on not in (*rules.SEVERITIES, "never"):
        raise _fail("--fail-on must be high, medium, low or never")
    home, proj = _paths(home, project)
    try:
        items = inventory(home, proj)
    except CollectError as e:
        raise _fail(str(e)) from e
    findings = rules.scan(items)
    if as_sarif:
        typer.echo(json.dumps(sarif.report(items, findings, [], proj), indent=2))
    elif as_json:
        typer.echo(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        shown = [f for f in findings if show_all or fail_on == "low" or f.severity != "low"]
        for key in dict.fromkeys(f.key for f in shown):
            out.print(safe(key))
            for f in shown:
                if f.key == key:
                    out.print(f"    {finding_line(f)}")
        counts = {s: sum(f.severity == s for f in findings) for s in rules.SEVERITIES}
        hidden = " (low hidden, --all shows them)" if len(shown) < len(findings) else ""
        out.print(", ".join(f"{n} {s}" for s, n in counts.items()) + hidden if findings else "no findings")
    if fail_on != "never" and any(rules.SEVERITIES.index(f.severity) <= rules.SEVERITIES.index(fail_on) for f in findings):
        raise typer.Exit(1)


AGENTS = ("claude-code", "cursor")


def project_root(start: Path, home: Path) -> Path:
    """The agent may be working in a subfolder; the project's lock and config live at its top."""
    start, home = start.resolve(), home.expanduser().resolve()
    for folder in (start, *start.parents):
        if folder == home:
            break
        if (folder / lk.REPO_LOCK_NAME).exists() or (folder / ".git").exists():
            return folder
    return start


@app.command()
def hook(
    agent: Annotated[str, typer.Argument(help="claude-code or cursor")],
    home: HomeOpt = Path.home(),
) -> None:
    """Run as an agent hook: reads the hook's JSON on stdin, prints the agent's JSON reply. See README for setup."""
    if agent not in AGENTS:
        raise _fail(f"agent must be one of: {', '.join(AGENTS)}")
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    roots = payload.get("workspace_roots") or []
    where = Path(str(payload.get("cwd") or (roots[0] if roots else "") or Path.cwd()))
    errors: dict[str, str] = {}
    try:
        ctx = _load(home, project_root(where, home) if where.is_dir() else home, errors)
        found, note = drift(ctx)
        paths = item_paths(ctx)
        found = [c for c in found if c.key.split("/", 1)[0] not in errors]  # an unreadable agent's items only look removed
        if errors:
            note = " ".join(filter(None, [note, f"rigseal could not read the config of: {', '.join(sorted(errors))}."]))
        broken = errors.get(agent)
    except Exception as e:  # noqa: BLE001  never crash the agent, and never let a failed check open the MCP gate
        found, note, paths, broken = [], f"rigseal could not check the agent setup: {e}", {}, str(e) or type(e).__name__
    if not lk.machine_lock_path(home.expanduser().resolve()).exists():
        broken = None  # not set up yet: hooks never block
    if agent == "claude-code":
        reply, code = hooks.claude_code(payload, found, paths, note, broken)
    else:
        reply, code = hooks.cursor(payload, found, note, broken)
    if reply is not None:
        typer.echo(json.dumps(reply))
    raise typer.Exit(code)


@app.command()
def watch(
    project: ProjectOpt = Path("."),
    interval: Annotated[float, typer.Option("--interval", help="Seconds between file checks.")] = 0.5,
    rescan: Annotated[float, typer.Option("--rescan", help="Seconds between full checks when no file changed.")] = 30.0,
    home: HomeOpt = Path.home(),
) -> None:
    """Watch your agent setup and print drift the moment it appears. Ctrl-C to stop."""
    state: dict = {}

    def say_once(note: str | None) -> None:
        if note and note != state.get("note"):
            out.print(f"[yellow]{safe(note)}[/yellow]")
        state["note"] = note

    def check() -> wt.Result:
        try:
            ctx = _load(home, project)
        except CollectError as e:  # e.g. a config caught half-written by an editor: keep the last result, try again
            say_once(f"error: {e}")
            return state.get("result") or wt.Result([], [], {})
        found, note = drift(ctx)
        say_once(note)
        current = {**ctx.current.repo, **ctx.current.machine, **ctx.current.local}
        locks = [lk.machine_lock_path(ctx.home)] + ([lk.repo_lock_path(ctx.project)] if ctx.project else [])
        shas = {c.key: current.get(c.key, {}).get("sha256") for c in found}
        state["ctx"], state["result"] = ctx, wt.Result(wt.watched_paths(ctx.items, locks), found, shas)
        return state["result"]

    watcher = wt.Watcher(check, rescan=rescan)
    out.print(f"watching, file check every {interval}s. Ctrl-C to stop.")
    try:
        while True:
            if tick := watcher.poll():
                new, cleared = tick
                stamp = datetime.now().strftime("%H:%M:%S")
                if new:
                    out.print(f"[bold]{stamp}[/bold] drift:")
                    print_changes(new, change_findings(state["ctx"], new))
                for key in cleared:
                    out.print(f"[bold]{stamp}[/bold] [green]ok[/green] {safe(key)} (approved or reverted)")
            time.sleep(interval)
    except KeyboardInterrupt:
        out.print("stopped")
