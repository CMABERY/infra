# codex_like_mvp

A minimal **transaction-first** coding agent kernel:
- JSON-RPC-ish transport over stdio (NDJSON)
- typed `turn/item` stream
- approval gating for commands + file changes
- patch proposal + apply
- append-only transaction ledger (`events.jsonl`)

This is intentionally small and dependency-light (stdlib only).

## Quick demo

From the repository root:

```bash
python -m codex_like_mvp.client.mvp_cli demo
```

What it does:
1. Starts the backend process.
2. Creates a thread rooted at `demo_workspace/`.
3. Starts a turn that removes a `TODO` line from `demo_workspace/example.js`.
4. Requests approvals (auto-approved in demo mode).
5. Applies the patch.
6. Writes a transaction ledger under `state/transactions/...`.

## Interactive mode

```bash
python -m codex_like_mvp.client.mvp_cli
```

You can then paste instructions; approvals will be prompted.

## Files

- `backend/mvp_server.py` — JSON-RPC server + worker orchestration
- `backend/agent.py` — deterministic “TODO remover” agent for demo
- `backend/transaction_store.py` — transaction-first ledger and patch store
- `client/mvp_cli.py` — minimal client that renders typed events and approvals

## Notes

This is **not** a replica of OpenAI Codex. It’s a minimal kernel that matches the
contracts we reverse-engineered:
- transaction-first ledger
- typed event stream
- approvals + apply separation


## Ledger location

Transactions are stored under:

`state/transactions/<YYYY>/<MM>/<DD>/<txid>/`

Each transaction contains:
- `transaction.json` (metadata)
- `events.jsonl` (append-only ledger)
- `patches/<sha256>.diff` (content-addressed patch)
