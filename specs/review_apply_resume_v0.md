# Checkpoint 9 — Review / Apply / Resume Semantics (v0)

This spec formalizes the split between **proposal** and **side effects** in the minimal clone kernel.

## Goals

- **Review-only mode** exists by default: producing a patch proposal must not mutate the workspace.
- **Explicit apply action**: the client must issue a dedicated `apply/execute` request to perform writes.
- **Resume interrupted runs**: a client can reopen a previously created transaction (after restart) and continue approvals/apply.
- **Distinct logging**: proposal and apply are separate phases in the transaction ledger.

## Core ideas

### Proposal phase (“review”)

A turn produces:

- `turn/start`
- zero or more `turn/item` events (plan, commandExecution, fileChange, turnDiff, …)
- `tx/status` transition to `proposed`

**Crucially:** proposal emits **no workspace writes**. The patch is stored (redacted) and referenced from metadata.

### Apply phase (“side effects”)

Apply is a separate RPC action:

- request: `apply/execute { transactionId }`
- emits `apply/start` and `apply/complete`
- updates the prior `fileChange` item via `turn/item` upsert (sets `metadata.applied = true`)
- transitions `tx/status` to `applied` then `completed` and finally emits `tx/close`

## Persistence & resume

A transaction is resumable because:

- metadata is stored as `transaction.json`
- the append-only ledger is `events.jsonl`
- the latest proposal is referenced in `transaction.json.pointers.proposal`

### `pointers.proposal` required fields

The proposal pointer is the bridge between the **review trace** and the later **apply**.

Checkpoint 10 stores a multi-file version:

- `kind`: `"remove_todo_multi"`
- `workspace_root`: absolute
- `target_files`: list of relative paths included in the patchset
- `needle`: string
- `base_sha256_by_path`: map `{rel_path -> sha256(base_text)}`
- `patch_id`: sha256(raw concatenated unified diff bytes)
- `patch_fingerprint`: `"patchset:{patch_id}"` (approval key)
- `contains_secret_introductions`: boolean
- `proposal_turn_id`, `proposal_item_id`

## Approvals in the apply phase

`apply/execute` is allowed to create approvals:

- If approvals are missing, it emits `approval/request` events and returns:
  - `{ ok: false, pendingApprovals: [...] }`

- The client decides with:
  - `approval/respond { transactionId, approvalRequestId, decision }`

The backend records decisions as `approval/decision` events.

### “No silent retry” (deny sticks)

If an approval fingerprint has a `deny` decision in the ledger, subsequent apply attempts fail fast.

## Safety interactions

- Sandbox rules are enforced for both proposal and apply.
- `read-only` sandbox disallows apply entirely.
- Secret guardrails apply during `apply/execute`:
  - if secrets appear in **added diff lines**, a `secrets_override` approval is required.

## Recommended UI flow

1. Start a review turn: `turn/start`
2. Show streamed items and proposed diff
3. Ask user: “Apply this patch?”
4. If yes: call `apply/execute`
5. If approvals are requested: prompt user and send `approval/respond`
6. Re-call `apply/execute` until `ok:true` or blocked
