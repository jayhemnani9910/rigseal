# Reference

Everything the README leaves out.

## Commands

```sh
rigseal status              # summary: items, drift, findings, hooks (--all lists every item)
rigseal setup               # hooks + locks, in one step
rigseal init                # only the locks: ~/.rigseal/machine.lock, and rigseal.lock in the repo
rigseal diff                # what changed since you approved
rigseal approve [KEY...]    # show changes and ask, then accept them (all, or just these keys)
rigseal check               # exit 0 clean, 1 drift or bad signature, 2 error
rigseal check --repo --require-signature   # in CI: repo lock only, must be signed
```

`rigseal scan` runs the rules on everything, approved or not, and exits 1 on any HIGH finding (`--fail-on medium|low|never` to change that). Low findings are hidden unless you pass `--all`. `diff` and `check` show the same findings on items that were added or changed. A changed plugin shows file counts and any new capabilities; `rigseal diff --files` lists its files.

## Watch and hooks

`rigseal watch` checks file stats every 0.5 s and prints drift as soon as it appears, and again when it is approved or reverted. A rewritten `.mcp.json` shows up in under a second.

`rigseal hook claude-code` and `rigseal hook cursor` run as agent hooks. A drifted MCP server (added, changed or removed since approve) gets its tool calls denied, and so does every MCP call if that agent's own config or a lock can't be read. A lock that fails its signature approves nothing. Other drift is reported. Until `rigseal init` has run, hooks only say that rigseal is not set up; they never block. Each call takes about a second (a full check).

`rigseal setup` adds these for you. To add them by hand instead, for Claude Code, in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [{ "matcher": "startup|resume", "hooks": [{ "type": "command", "command": "rigseal hook claude-code", "timeout": 30 }] }],
    "PreToolUse": [{ "matcher": "mcp__.*", "hooks": [{ "type": "command", "command": "rigseal hook claude-code", "timeout": 30 }] }],
    "ConfigChange": [{ "matcher": "user_settings|project_settings|local_settings|skills", "hooks": [{ "type": "command", "command": "rigseal hook claude-code", "timeout": 30 }] }]
  }
}
```

- `SessionStart`: shows you the drift and tells the agent to treat changed items as untrusted. It can't block.
- `PreToolUse`: denies calls to a drifted MCP server. `.mcp.json` and `~/.claude.json` have no config-change event, so this is the gate.
- `ConfigChange`: keeps a drifted settings or skill file out of the running session. Claude Code shows no message when it blocks; run `rigseal diff`.

Cursor, in `~/.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "sessionStart": [{ "command": "rigseal hook cursor" }],
    "beforeMCPExecution": [{ "command": "rigseal hook cursor", "failClosed": true }]
  }
}
```

Adding these by hand changes your settings, so approve once afterwards.

## Rules

| Rule | Severity | Flags |
|---|---|---|
| R1 | high | an MCP server added, removed or changed without approval |
| R2 | high | MCP server runs inline shell or interpreter code (`bash -c`, `python -c`), pipes a download into a shell, or lives in a temp folder |
| R3 | high | project settings that approve themselves: `enableAllProjectMcpServers`, `enabledMcpjsonServers`, `Bash(*)`, `bypassPermissions`, hooks, `apiKeyHelper`, `*_BASE_URL`/proxy env; Codex `approval_policy = never`, `danger-full-access`, `model_providers`, hooks; Cursor hooks |
| R7 | high | "install this prerequisite first" next to a direct download (archive, binary, release asset, paste site, shortener, raw IP) |
| R8 | high | an encoded blob (base64, hex) plus something that decodes it |
| R9 | medium | a password-protected archive with the password in the text |
| R10 | high | reverse shell patterns (`/dev/tcp`, `nc -e`, `bash -i >&`, socket + `dup2`/`pty.spawn`) |
| R11 | high | code that touches keys, wallets or browser data and makes a network call |
| R12 | medium | a skill, command or agent that ships a hidden folder, a binary or an archive |
| R13 | high | words mixing Latin and Cyrillic letters (look-alike spoofing) |
| R14 | high/medium | decodes code and runs it (high); pipes a download into a shell (medium, common in install docs) |
| R15 | high | hidden characters: Unicode tags anywhere; bidi and zero-width in instruction files and MCP config |
| R16 | medium | `npx`/`uvx`/`bunx`/`pnpm dlx` package without a pinned version |
| R18 | low/medium | skill, command or agent uses shell or network but `allowed-tools` doesn't declare it |

Each skill, command, agent, rule and plugin also gets a capability summary (shell, network, hosts in code, sensitive paths like `~/.ssh`, `allowed-tools`). It is locked, so `diff` shows lines like `+ host evil.io` or `+ shell`. Vendored folders (`node_modules`, `.venv`, `.git`) are hashed but not read for capabilities. Findings name the pattern that matched, never config values. Text is folded (NFKC + look-alike letters) before matching, so `curl` spelled with a Cyrillic `с` still matches.

Per-file results are cached in `~/.cache/rigseal/` by file hash, so only new or changed files are read again.

**How well do the rules work?** See [eval.md](eval.md): on MaliciousSkillBench's held-out test split, rules alone catch 2.7% of malicious skills at HIGH with 0.7% false alarms. Rules are a helper; the lock is the product.

`rigseal.lock` holds project-level items and is meant to be committed. The machine lock holds your user-level setup and stays on your laptop. In a fresh clone with no `rigseal.lock`, every project MCP server, skill and hook shows up as new.

**Signing.** `init` and `approve` sign each lock with `ssh-keygen -Y sign` using `--key`, `$RIGSEAL_SIGNING_KEY`, or git's SSH `user.signingkey`. `check` verifies against `.rigseal/allowed_signers` in the repo (or `~/.rigseal/allowed_signers` for the machine lock). The repo can edit its own list, so the repo lock must also pass a list from outside it: `--allowed-signers`, `$RIGSEAL_ALLOWED_SIGNERS`, or `~/.rigseal/allowed_signers`. With none of those, `--require-signature` fails. The GitHub Action uses the base branch's list on a PR. The first `setup` or `init` adds your own key to `~/.rigseal/allowed_signers` if that file doesn't exist. The format is git's allowed-signers:

```
you@example.com namespaces="rigseal" ssh-ed25519 AAAA...
```

Format details: [lockfile.md](lockfile.md).

rigseal only reads files. It never runs MCP servers, and it never prints secret values: env vars, args and headers are hashed, and only their key names are shown.

`approve` and `init` need a person at a terminal (set `RIGSEAL_NONINTERACTIVE=1` in CI). A signed lock can't be replaced by an unsigned one without `--allow-unsigned`, and once an `allowed_signers` file exists, `check` requires a valid signature. Read [threat-model.md](threat-model.md) for what this does and does not stop: the short version is that approvals are only as safe as a signing key the agent can't use.

In a project, symlinks that leave the repo are recorded but not followed (R12). Folders stop hashing at 20,000 files or 500 MB, and configs over 10 MB or that aren't regular files are refused.

## What it reads

| Agent | Where |
|---|---|
| Claude Code | `~/.claude/settings.json`, `.claude/settings{,.local}.json`, `~/.claude.json` (user + per-project MCP), `.mcp.json`, `skills/*/`, `commands/**/*.md`, `agents/**/*.md`, `~/.claude/plugins/installed_plugins.json` + install folders, synced plugins and skills (`plugins/synced/`, `skills/synced/`), MCP servers that plugins ship (`.mcp.json` or `plugin.json` `mcpServers`), `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` |
| Codex | `~/.codex/config.toml` (or `$CODEX_HOME`) and `.codex/config.toml`: settings, `mcp_servers`, hooks; `skills/*/` incl. `.system/`; `plugins/cache/<market>/<plugin>/` and each plugin's `.mcp.json`; `rules/*.rules`; `AGENTS.md` |
| Cursor | `~/.cursor/` and `.cursor/`: `mcp.json`, `hooks.json`, `skills/*/`, `rules/**/*.mdc`; `.cursorrules` |
| VS Code / Copilot | VS Code user `mcp.json` + `prompts/` (Linux, macOS and Windows paths), `.vscode/mcp.json`, `.github/copilot-instructions.md`, `.github/{instructions,prompts}/`, `.github/skills/`; `~/.copilot/mcp-config.json`, `skills/`, `installed-plugins/` |
| Shared | `~/.agents/skills/*/`, `.agents/skills/*/` |

Skill folders are hashed file by file, dotfiles included. Symlinked skills are listed under each agent that loads them, with the link target shown. JSON files with comments (VS Code, Copilot) are read too.

## Develop

```sh
uv sync
uv run pytest
uv run --group eval python evals/fetch.py      # eval data into ~/.cache/rigseal-eval
uv run --group eval python evals/run.py --split train
uv run python evals/dogfood.py log      # one check, appended to ~/.rigseal/dogfood.jsonl (run daily)
uv run python evals/dogfood.py report   # drift events per week, and how many were plugin updates
```

claude.ai connectors (Gmail, Drive, ...) are configured on your account, not on disk, so rigseal can't see them.
