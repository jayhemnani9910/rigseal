# Changelog

## Unreleased

Second audit. Security fixes first.

- The MCP gate no longer misses a server named like `x#2`, or one whose name holds an emoji or other odd characters.
- The Claude Code hook is installed with `onFailure: "block"`: a hook that crashes, times out or can't start now denies the call (Claude Code 2.1.295+). `rigseal setup` updates hooks installed before.
- The check before an MCP call reads config files only. It takes a fraction of a second and a slow or hostile folder can't stall it.
- Text rules run in linear time. One crafted 16 KB file used to hang every command and time out the hook.
- The hook uses Claude Code's project folder, so `cd` into a nested repo no longer hides the project's servers.
- Hook input that can't be read, and a lock with a malformed key, deny instead of letting the call through.
- A lock that fails its signature shows everything as pending in `diff` and `approve`, as it already did for the hooks. Approving one item no longer re-signs entries nobody looked at.
- Writing a lock never goes through a link a repo planted as `rigseal.lock.tmp`. A repo lock must be a plain file, at most 64 MB, with project entries only.
- Names from a repo can't drive the terminal (escape codes, new lines, bidi marks) or pass for instructions in what the hooks tell the agent.
- A URL's `user:password@` part and the arguments of a command line no longer end up in `status` or in the lock. Entries that held them show as changed once.
- Plugin MCP servers are found in every form Claude Code reads: `.mcp.json` first, then the manifest's path, map or list. A packaged bundle no longer stops rigseal.
- Now tracked: Claude Code `rules/` folders and `.claude/CLAUDE.md`. They show as added once.
- Commands look at the repo around the current folder, as the hooks do.
- `setup` checks the signing key before it changes any file, and a key written into git config (1Password) no longer breaks it. The signer list is written only after signing worked, and `approve` warns when a new signature won't verify.
- No crash on: plugin records without a path (rigseal used to hash the current folder), odd shapes in `~/.claude.json`, a JSON file with a byte order mark, a folder that can't be listed, a damaged analysis cache.
- Bad hook input now exits 2 (it was ignored).

## 0.1.0 (2026-11-09)

First public version.

- Inventory for Claude Code, Codex, Cursor, VS Code/Copilot and the shared `~/.agents/skills` folder.
- `rigseal setup` adds the hooks to the agents you use and locks what they load.
- `init`, `diff`, `approve`, `check`: machine and repo locks, signed with your SSH key.
- `rigseal hook`: denies tool calls to an MCP server that changed since the last approve (Claude Code and Cursor).
- `rigseal watch`: shows drift as soon as it appears.
- `rigseal scan`: rules R1 to R18, with SARIF output.
- GitHub Action: fails a PR that changes agent config without an approved lock.
- `status` prints a short summary (`--all` for every item), `scan` hides low findings (`--all` shows them), and a changed plugin shows file counts and new capabilities (`diff --files` lists the files).
