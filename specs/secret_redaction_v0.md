# Secret Redaction & Guardrails (v0)

## Purpose
Checkpoint 8 makes the kernel **safe-by-default** around secrets.

The objective is to prevent accidental leakage of credentials through:

- The **UI event stream** (JSON-RPC notifications)
- The **transaction ledger** (`events.jsonl`)
- The **patch store** (`patches/*.diff`)

It also adds a guardrail: **patches that introduce secrets are blocked** unless the operator explicitly approves an override.

## Definitions
- **Secret**: a text pattern likely to represent credential material (API keys, access tokens, private keys, etc.).
- **Redaction**: transforming text so the secret value is replaced with a placeholder while keeping enough structure for debugging.
- **Introduction**: a secret that appears in a **newly added** diff line (unified diff lines beginning with `+`, excluding headers).

## Normative requirements

### R1 — Emit redacted events only
All events sent via transport notifications MUST be redacted before emission.

### R2 — Ledger redaction
All events persisted to `events.jsonl` MUST be redacted before writing.

### R3 — Patch store redaction
Patch files stored under `patches/` MUST contain redacted diff content.

Note: the content-addressed `patch_id` is computed from the **raw diff bytes** for stability, but the stored file content is redacted by default.

### R4 — Redaction metadata
When redaction occurs, the event payload MUST include:

- `_redaction.redacted = true`
- `_redaction.kinds = [ ... ]` (a list of redaction kind identifiers)

No secret values may appear in `_redaction`.

### R5 — Guardrail: secret introductions
If secret introductions are detected in a proposed patch, the kernel MUST:

1) Record findings on the `fileChange` item:
   - `metadata.secret_introductions = [{kind, line}, ...]`
   - `metadata.diff_redacted = true`

2) Request an explicit override approval before applying:
   - Emit `approval/request` with `kind = "secrets_override"`

3) Block apply unless the override approval decision is `approve`.

4) If `approvalPolicy == "never"`, the kernel MUST NOT apply the patch, and MUST surface the reason as blocked.

### R6 — No silent retry for secret overrides
A denied secret override attempt MUST be recorded as a denied fingerprint, and subsequent retries MUST be auto-denied for the same turn.

## Detection patterns (v0)
The implementation uses conservative, high-confidence patterns plus a small amount of heuristic gating:

High-confidence patterns:
- Private key blocks (PEM/OpenSSH): `-----BEGIN ... KEY----- ... -----END ... KEY-----`
- OpenAI keys: `sk-...`
- GitHub tokens: `ghp_...`, `gho_...`, `github_pat_...`
- AWS access key IDs: `AKIA...` / `ASIA...`
- Google API keys: `AIza...`
- Slack tokens: `xox...`
- JWTs: `eyJ...` (3-part JWT format)

Moderate/low-confidence patterns:
- `Bearer <token>` where the token is long
- `password=...`, `token: ...`, `api_key=...` style assignments where the value looks secret-like

## Limitations
- Secret detection is necessarily imperfect (false negatives are possible).
- Redaction may cause false positives in log output comparisons.
- This is not an OS-level sandbox; it is an application-level safety layer.

## Implementation mapping
- `codex_like_mvp/backend/redaction.py`
  - `redact_text`, `redact_event`, `detect_secret_introductions_in_diff`
- `codex_like_mvp/backend/mvp_server.py`
  - Redacts before UI + ledger emission
  - Guardrail + `secrets_override` approval path
- `codex_like_mvp/backend/transaction_store.py`
  - Redacts events and stores redacted patch content
