# rigseal

A lockfile for your AI agent setup.

Your agents load skills, plugins, hooks and MCP servers. Any of them can change without you knowing. rigseal pins them all and blocks a changed MCP server until you approve it. Runs 100% local.

![An MCP server is rewritten, rigseal flags it, and the agent's tool call is denied](docs/demo.gif)

[One-minute guide (mp4)](https://github.com/jayhemnani9910/rigseal/releases/download/v0.1.0/rigseal-howto.mp4)

## Install

Needs [uv](https://docs.astral.sh/uv/).

```sh
uv tool install git+https://github.com/jayhemnani9910/rigseal
rigseal setup
```

`setup` shows what it will do and asks first. It adds the hooks and locks what your agents load today.

To look first. This only reads your agent files (it keeps a cache in `~/.cache/rigseal`):

```sh
uvx --from git+https://github.com/jayhemnani9910/rigseal rigseal status
```

## Quick start

```sh
rigseal status     # what's loaded, what changed
rigseal diff       # what changed, and why it's risky
rigseal approve    # you made the change, accept it
```

Didn't make the change? Undo it, and rigseal goes back to clean.

```sh
git restore .mcp.json
```

## How it works

1. `setup` hashes everything your agents load into two locks. `rigseal.lock` is for the repo, commit it. `~/.rigseal/machine.lock` stays on your laptop.
2. Hooks check those locks when a session starts and before every MCP call. A changed server gets denied. Other changes get reported. If the check itself fails, the call is denied too.
3. If you have an SSH signing key, the locks are signed. A lock that fails its signature approves nothing.
4. `approve` asks a person at a terminal. That stops an agent approving by accident, not a determined one.

## Agents

| Agent | Tracks changes | Blocks changed MCP servers |
|---|---|---|
| Claude Code | yes | yes |
| Cursor | yes | yes |
| Codex | yes | no |
| VS Code / Copilot | yes | no |

`~/.agents/skills` is tracked too.

## Commands

| Command | What it does |
|---|---|
| `rigseal status` | Summary. `--all` lists every item |
| `rigseal setup` | Add hooks, write locks |
| `rigseal diff` | What changed since you approved |
| `rigseal approve` | Accept changes |
| `rigseal check` | For scripts. Exit 0 clean, 1 changed, 2 error |
| `rigseal scan` | Run the rules on everything |
| `rigseal watch` | Print changes as they happen |

## On a team

Commit `rigseal.lock`. If rigseal signs it for you, also commit `rigseal.lock.sig` and a `.rigseal/allowed_signers` file that lists the team's keys ([format](docs/reference.md#signing)). This fails any PR that changes agent config without approving it:

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  rigseal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jayhemnani9910/rigseal@v0.1.0
```

## Good to know

- rigseal only reads files. It never runs an MCP server and never prints secret values.
- The scan rules are a helper. On a public benchmark they catch [2.7% of malicious skills](docs/eval.md). The lock is the product.
- Approvals are only as safe as a signing key your agent can't use. See the [threat model](docs/threat-model.md).
- A repo you clone can bring its own `rigseal.lock`, and rigseal takes it as approved. Run `rigseal scan` in a clone you don't know yet.
- rigseal pins what the config says. It does not hash the script a local MCP server runs, or every file an agent can load ([what is not read yet](docs/reference.md#not-read-yet)).
- claude.ai connectors live on your account, not on disk, so rigseal can't see them.

Rules, manual hook setup, signing and every path it reads: [docs/reference.md](docs/reference.md).

## License

Apache-2.0
