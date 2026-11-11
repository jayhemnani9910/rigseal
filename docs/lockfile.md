# rigseal lockfile, v0

v0 may still change before 1.0.

## Two files

| File | Holds | Paths | Commit it? |
|---|---|---|---|
| `rigseal.lock` (project root) | items with scope `project` | relative to the project | yes, review it in PRs |
| `~/.rigseal/machine.lock` (or `$RIGSEAL_DIR/machine.lock`) | scopes `user`, `plugin`, `system`; scope `local` grouped under `projects` | `~/`-relative | no |

A missing `rigseal.lock` counts as empty, so in a fresh clone every project-level MCP server, skill or hook shows up as `added`.

## Format

```json
{
  "lockfileVersion": 0,
  "generator": "rigseal 0.1.0",
  "signedBy": "dev@example.com",
  "items": {
    "claude-code/project/mcp/db": {
      "agent": "claude-code",
      "scope": "project",
      "kind": "mcp",
      "name": "db",
      "path": ".mcp.json",
      "sha256": "…",
      "files": {},
      "details": {"transport": "stdio", "command": "npx", "arg_count": 2, "env_keys": ["TOKEN"]},
      "approvedBy": "dev@example.com",
      "approvedAt": "2026-11-07T10:00:00Z"
    }
  },
  "projects": {
    "/home/dev/app": { "claude-code/local/settings/settings.local.json": { "…": "…" } }
  }
}
```

- **Key:** `agent/scope/kind/name`. If the same key comes up twice (e.g. a plugin installed twice), the second gets `#2`.
- **`sha256`:** for folders (skills, plugins), the hash of the sorted `path\0sha256\n` lines of every file, dotfiles included, with symlinks recorded by target. For MCP servers, the hash of the server's config as canonical JSON. Secrets in env, args and headers are part of that hash but never written to the lock.
- **`files`:** per-file hashes, so `diff` can say which file changed.
- **`details`:** non-secret facts shown to people (risky settings keys, MCP transport, the program a command starts, the host of a URL, env key names, symlink target). A change here is drift too.
- **`details.capabilities`** (skills, commands, agents, rules, plugins): `shell`, `network`, `hosts` (from code and code blocks, not prose links), `sensitive_paths`, `hidden_chars` (per file), `allowed_tools`. Only present keys are written. `diff` prints changes here as `+ host x`, `- shell`, and so on.
- **`path`** is informational and is not compared.
- `projects` appears only in the machine lock. A repo lock holds project-scope entries and nothing else; one that holds more is refused.
- A repo lock has to be a plain file, not a link, and at most 64 MB.

## Drift

| Status | Meaning |
|---|---|
| `added` | in the inventory, not in the lock |
| `removed` | in the lock, gone from the inventory |
| `changed` | `sha256` or `details` differ; the change lists files added, removed and changed, and detail keys changed |

`rigseal approve` accepts drift. Approving an unchanged item keeps its original `approvedBy`/`approvedAt`.

## Signing

`approve` and `init` sign each lock they write with an SSH key, the same way git signs commits:

```sh
ssh-keygen -Y sign -n rigseal -f <key> rigseal.lock   # writes rigseal.lock.sig
```

- Key: `--key`, then `$RIGSEAL_SIGNING_KEY`, then git `user.signingkey` when `gpg.format=ssh`. With no key, the lock is written unsigned and any old `.sig` is removed.
- `signedBy` is the signer's git `user.email`.
- `check` verifies against an allowed signers file (same format as git's): `.rigseal/allowed_signers` in the project for the repo lock, `~/.rigseal/allowed_signers` for the machine lock, else git `gpg.ssh.allowedSignersFile`. The repo lock must also pass a list from outside the repo, when there is one: `--allowed-signers`, `$RIGSEAL_ALLOWED_SIGNERS`, then `~/.rigseal/allowed_signers`.
- A lock with `signedBy` but no `.sig` fails `check`, so a deleted signature is caught. Use `--require-signature` in CI so an unsigned lock fails too. It also fails when the only signer list is inside the repo.

## Exit codes

`rigseal check`: `0` no drift and signatures OK, `1` drift or a signature problem, `2` error (unreadable config or lock, no machine lock).
