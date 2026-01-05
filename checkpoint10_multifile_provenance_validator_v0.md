# Checkpoint 10 — Multi-file Patchsets, Provenance Artifacts, Invariant Validation

This checkpoint extends the minimal clone kernel with three features:

1. **Multi-file patchsets**
2. **Tool-call provenance** (inputs/outputs stored as content-addressed artifacts)
3. **An invariants validator** that detects illegal event sequences and broken references

The goal is to move from "single-file demo" to a trace that more closely resembles real-world coding agents, while preserving governance and auditability.

## 1) Multi-file patchsets

### Representation
A patchset is expressed as a single `turn/item` of type `fileChange` where:

- `changes` is an **array** of per-file change objects
- multiple entries are allowed (multi-file)
- each change has:
  - `path`: the relative file path
  - `kind`: one of `add|delete|update|rename` (Checkpoint 10 uses `update`)
  - `unified_diff`: the per-file unified diff (redacted)

Additionally, `metadata` includes:

- `patch_id`: SHA-256 of the **raw concatenated unified diff** (all files)
- `patch_fingerprint`: `"patchset:{patch_id}"` (used for approvals)
- `base_sha256_by_path`: base hashes for each file (prevents TOCTOU between review and apply)

The item also includes `patchId` (camelCase) to match the schema.

### Proposal vs Apply
- **Review** computes the patchset and writes proposal pointers into `transaction.json`.
- **Apply** recomputes the patchset deterministically from the captured base files + needle and refuses to apply if:
  - any base hash has changed
  - the recomputed patch_id differs

## 2) Tool-call provenance artifacts

### Motivation
A `turn/item` event should remain reasonably small and safe to print.
However, we still need durable provenance for audit/debug.

### Mechanism
When a tool executes (e.g. `commandExecution`), the server stores a JSON artifact under:

- `transactions/.../<txid>/artifacts/{sha256}.json`

Where `sha256` is computed from the **raw JSON bytes** (stable fingerprinting).

Artifacts are persisted in **redacted** form by default.

### Ledger linkage
Every stored artifact triggers an `artifact/stored` event:

- `type`: `artifact/stored`
- `payload`: `{artifact_id, kind, path, content_type, redacted}`

The corresponding `turn/item` stores an `artifact` reference in `item.metadata.artifact`.

## 3) Invariant validation

A trace can be *syntactically valid JSON* while being *semantically illegal* (reordered events, missing approvals, dangling references).

Checkpoint 10 adds:

- `tools/validate_invariants.py`

It validates:

- ordering invariants (`tx/meta` first, `tx/close` terminal, turn/apply ordering)
- referential integrity (approval decisions must reference known requests)
- artifact existence (artifact files referenced by events must exist)
- patch existence (patch_id must exist in `patches/`)

For the current invariant set, see:

- `invariants_v0.md`

## Compatibility
- Turn items remain compatible with `specs/turn_item_schema_v0.1.json`.
- The implementation relies on `additionalProperties: true` to attach provenance refs.

