# Invariants v0 (Checkpoint 10)

This document defines **ledger invariants** for the transaction-first kernel.

An invariant is a rule that makes a trace **well-formed**. If a trace violates an invariant, the system should treat it as **corrupt** (or at minimum, suspicious) and refuse to rely on it for safety-critical decisions.

The reference implementation is the script:

- `tools/validate_invariants.py`

## Goals

- Make event streams **auditable** and **machine-checkable**.
- Detect broken implementations early (regressions, partial writes, reordered streams).
- Ensure governance signals (approvals) cannot be bypassed via weird sequences.

## Scope

This v0 invariant set validates:

- event sequencing (turn/apply/close)
- referential integrity (approval decisions refer to requests)
- provenance object integrity (artifacts referenced by events actually exist)

It does **not** attempt to:

- prove the OS-level sandbox is secure
- validate semantic correctness of diffs
- detect covert exfiltration

## Event ordering invariants

### I-SEQ-001 — `tx/meta` must be first
The first ledger event must be `tx/meta`.

### I-SEQ-002 — `tx/close` is terminal
After `tx/close`, **no more events** may appear.

### I-SEQ-003 — `turn/start` precedes `turn/item`
Any `turn/item` must reference a `turn_id` that has appeared in a prior `turn/start`.

### I-SEQ-004 — apply is bracketed
If an `apply/start` event exists, there must be a corresponding `apply/complete` for the same `apply_id`, and no nested apply blocks are allowed.

## Approval invariants

### I-APP-001 — decisions require a request
Every `approval/decision.approval_request_id` must refer to a prior `approval/request.approval_request_id`.

### I-APP-002 — requests are decided at most once
A given `approval_request_id` cannot have multiple decisions.

## Provenance / artifact invariants

### I-ART-001 — stored artifacts must exist
For every `artifact/stored` event, `path` must exist on disk relative to the transaction directory.

### I-ART-002 — commandExecution items reference artifacts
For every `turn/item` of `type=commandExecution` in `status=completed|failed`, if `metadata.artifact` is present, the referenced artifact must exist.

### I-ART-003 — fileChange items reference patch files
For every `turn/item` of `type=fileChange`, if `metadata.patch_id` is present, `patches/{patch_id}.diff` must exist.

## Status transition invariants (minimal)

### I-STAT-001 — `tx/status.from` should match previous
For each `tx/status` event, the `from` field should match the last-seen status.

This is treated as a **soft invariant** in v0 (reported, but not fatal) because older traces may be missing intermediate transitions.

## Validator output

The validator prints:

- the transaction id
- the tx directory
- the number of events
- a list of invariant violations with event indices

Exit code `2` means violations exist.
