# security_v0 — Sandbox & Approval Hardening

This spec defines the **safety boundaries** for the minimal clone kernel (Checkpoint 7).

It is intentionally pragmatic:
- It **hardens defaults**.
- It keeps behavior **auditable** (everything is logged to the transaction ledger).
- It is **not** an OS-level sandbox.

## Goals

1. **Safe-by-default** execution.
2. Make every side effect **attributable** to a transaction and to an explicit approval decision.
3. Provide a clear, explicit escalation path to **dangerous capability**.

## Non-goals

- Providing a true process sandbox (seccomp, containers, VMs, MAC policies).
- Preventing all data exfiltration if a user explicitly enables `full/danger`.
- Perfect command classification. The command policy is heuristic + allowlist oriented.

## Concepts

### Sandbox policy

A sandbox policy is attached to each transaction (and may be supplied per turn).

```json
{
  "type": "read-only | workspace-write | full/danger",
  "writable_roots": ["..."],
  "network_access": false
}
```

### Server hardening flags

These are *server startup* flags and cannot be enabled silently by the client:

- `--danger`  
  Enables selecting `full/danger` sandbox type.

- `--allow-sensitive-roots` (VERY UNSAFE)  
  Allows filesystem access to known sensitive directories (e.g., `~/.ssh`) that are otherwise blocked.

- `--allow-denylisted-commands` (VERY UNSAFE)  
  Allows commands that are otherwise hard-blocked by denylist.

## Sandbox modes

### 1) `read-only`

- **Filesystem writes:** forbidden
- **Command execution:** forbidden
- **Filesystem reads:** allowed, subject to sensitive-root blocks

Intended use:
- auditing
- patch proposal / review mode
- generating diffs without modifying the workspace

### 2) `workspace-write` (default)

- **Filesystem writes:** allowed **only within** declared workspace roots / writable roots
- **Command execution:** allowlisted commands may run; non-allowlisted commands require explicit approval
- **Network:** default offline (no network-related commands)

### 3) `full/danger`

- Allows absolute paths and operations outside the workspace
- Requires server flag: `--danger`
- Still blocks sensitive roots unless `--allow-sensitive-roots` is set

This mode exists because some workflows (monorepos, multi-root workspaces, migrations) genuinely need it.
The keyword is **explicit**.

## Path guards

Path guards are enforced on every file operation initiated by the agent kernel.

### Rules

In `read-only` / `workspace-write`:

- Reject absolute paths.
- Reject traversal segments (`..`).
- Resolve symlinks via `realpath`.
- Enforce **realpath containment** within `workspaceRoot`.

In `full/danger`:

- Absolute paths allowed (server must be started with `--danger`).
- Still apply sensitive-root blocks unless overridden.

### Sensitive roots block

By default, access is blocked to:

- `~/.ssh`
- `~/.aws`
- `~/.gnupg`
- `~/.kube`
- `~/.config/gcloud`
- `~/.config/gh`
- `~/.docker`
- `~/.pypirc`
- `~/.npmrc`

This block applies **even in danger mode** unless overridden.

## Command policy

Commands are represented as `argv: string[]` (no shell strings).

### Allowlist (examples)

Allowlisted commands may execute without approval:

- `ls`, `dir`
- `git status`, `git diff`, `git log`, `git rev-parse`, `git branch`, `git show`, `git grep`
- `cat <relative-path>` / `type <relative-path>`
- a specific safe python listdir snippet:
  `python -c "import os; print('\n'.join(sorted(os.listdir('.'))))"`

### Denylist (hard block by default)

Blocked command families (unless server started with `--allow-denylisted-commands`):

- network tools: `curl`, `wget`, `ssh`, `scp`, `sftp`, `nc`, `netcat`, `telnet`, etc.
- shell entrypoints: `bash`, `sh`, `zsh`, `powershell`, `cmd`
- deletion primitives: `rm`, `rmdir`, `del`, `erase`

### Offline / network policy

If `network_access=false`:

- Block commands that are network-related (explicit network tools, or `git clone/fetch/pull/push`, or argv containing `http(s)://`).

### Approval integration

- Commands not on the allowlist must trigger `approval/request`.
- If the user denies, the command must **not execute**.
- If a command/patch fingerprint is denied, retry in the same turn is **auto-denied** (no silent loops).

### Approval policy: `never`

`approvalPolicy="never"` disables interactive approvals.

Security rule:
- In non-danger sandboxes, the backend must **refuse** to run non-allowlisted commands when approvals are disabled.

## Approval persistence

- `approval/request` is logged when requested.
- `approval/decision` is logged **as soon as the backend receives** `approval/respond` (not only after the worker resumes).

This ensures the ledger remains correct even if the worker crashes after the user answers.

## Known limitations

- This is not an OS sandbox.
- A sufficiently powerful allowlisted interpreter could still do harmful things. Keep the allowlist tight.
- Any real deployment should add process sandboxing (containers/VM), structured tool APIs, and secret scanning.

## “Done when” (Checkpoint 7)

- Sandbox modes are defined and enforced.
- Path guards prevent traversal and out-of-root writes in workspace mode.
- Sensitive roots are blocked by default.
- Command policy is enforced (allowlist/denylist + offline).
- Approval decisions are persisted and denied actions do not execute.
