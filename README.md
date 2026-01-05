# codex_like_mvp_project

This project contains a minimal **transaction-first** coding agent kernel with:
- JSON-RPC-ish transport over stdio (NDJSON)
- typed `turn/item` stream
- approval gating for commands + file changes
- patch proposal + apply
- append-only ledger under `codex_like_mvp/state/transactions/`

Checkpoint 10 adds:
- **multi-file patchsets** (one proposal may touch multiple files)
- **tool-call provenance artifacts** captured as content-addressed JSON under each transaction
- an **invariants validator** to detect illegal event sequences / broken references

## Quick demo

From this directory:

```bash
python -m codex_like_mvp.client.mvp_cli demo
```

Checkpoint 9 semantics: the `demo` command runs a **REVIEW** turn by default (proposal only).
To actually mutate files, you must explicitly apply:

```bash
python -m codex_like_mvp.client.mvp_cli demo --apply
```

## Checkpoint 7 — Sandbox & Approval Hardening

The backend supports three sandbox modes:

- `read-only`: no filesystem writes, no command execution
- `workspace-write` (default): writes restricted to the workspace root(s); commands restricted by allowlist/denylist + approval
- `full/danger`: allows absolute paths and "outside workspace" operations **only** if the backend is started with `--danger`

Run demo in read-only mode (patch is proposed; apply is disallowed):

```bash
python -m codex_like_mvp.client.mvp_cli demo --sandbox read-only
```

Apply an existing transaction later:

```bash
python -m codex_like_mvp.client.mvp_cli apply --tx <TRANSACTION_ID>
```

Resume a transaction (inspect status + pending approvals, optionally apply):

```bash
python -m codex_like_mvp.client.mvp_cli resume --tx <TRANSACTION_ID>
python -m codex_like_mvp.client.mvp_cli resume --tx <TRANSACTION_ID> --apply
```

Run demo in full/danger mode (requires explicit backend opt-in):

```bash
python -m codex_like_mvp.client.mvp_cli demo --sandbox full/danger --danger
```

Security spec: `specs/security_v0.md`

Review/Apply/Resume spec: `specs/review_apply_resume_v0.md`

## Notes
The agent in this MVP is deterministic (no LLM). Replace the logic in
`codex_like_mvp/backend/agent.py` with an actual model call to evolve it.

This is **not** a real OS sandbox. The allowlist/denylist is application-level.

## Optional: validate the latest transaction

If you install `jsonschema`, you can validate the typed turn items in the latest transaction ledger:

```bash
pip install jsonschema
python tools/validate_latest_transaction.py

# Checkpoint 10: semantic invariant checks (no extra deps)
python tools/validate_invariants.py
```

