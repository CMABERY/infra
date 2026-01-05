# 3-way Merge & Conflict Markers v0 (Checkpoint 12)

This checkpoint adds **safe recovery behavior** when the workspace has changed since a patch proposal.

Previously, the kernel required:

- `sha256(current_file) == base_sha256_by_path[file]`

Otherwise apply refused and forced a full re-proposal.

Now, if a file's base hash mismatches and direct patch application fails, the kernel attempts a **3-way merge** and (when needed) emits **conflict markers**.

## Terms

- **BASE**: the file content captured at proposal time (stored as an internal blob).
- **WORKSPACE**: the file content at apply time.
- **PATCH**: the proposed target content = `apply(diff, BASE)`.

## Apply algorithm (per file)

1. Try **direct apply**: `apply(diff, WORKSPACE)`
   - If it succeeds, use the result (even if base hash mismatched).
2. If direct apply fails:
   - Load `BASE` snapshot from `proposal.base_snapshot_blob_by_path[file]`.
   - Compute `PATCH` by applying the stored diff to `BASE`.
   - Run a line-based **diff3-style merge**: `merge(BASE, WORKSPACE, PATCH)`.

## Conflict markers

If WORKSPACE and PATCH changed the same BASE region differently, the merged output includes:

```
<<<<<<< WORKSPACE
...workspace version...
=======
...patch version...
>>>>>>> PATCH
```

The kernel writes this merged output to the file (subject to sandbox path guards).

## Transaction status behavior

- If any file produces conflicts:
  - `apply/complete.success = false`
  - Transaction status becomes `conflicted`
  - The transaction is **not** `tx/close`'d automatically (workspace now requires human resolution).
- If no conflicts:
  - normal path: `applied -> completed -> tx/close`

## Storage

To enable 3-way merge without recomputation, proposal time now stores BASE snapshots as blobs:

- `blobs/raw/{blob_id}.txt` (internal only)
- `blobs/redacted/{blob_id}.txt` (safe for inspection)

Ledger references only the **redacted** blob path via `artifact/stored`.

## Safety notes

- This is a *pragmatic* merge implementation intended for an MVP.
- It is line-based and favors transparency over maximum auto-resolution.
- Secret redaction discipline is maintained for UI + ledger; conflict marker content is not streamed as raw content.
