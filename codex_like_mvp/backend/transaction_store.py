"""transaction_store.py

Filesystem-backed Transaction Store.

Implements the Transaction-First Architecture:
- Each transaction has durable metadata (transaction.json)
- All activity is appended to an immutable ledger (events.jsonl)
- Content-addressed blobs are stored under the transaction

Checkpoint history (cumulative):
  - Checkpoint 2: transaction-first architecture (ledger is source of truth)
  - Checkpoint 8: secret redaction before persistence
  - Checkpoint 9: proposal vs apply separation (review/apply/resume)
  - Checkpoint 10: tool-call provenance artifacts + multi-file patchsets support

Important:
- This is NOT an OS sandbox. It is an application-level audit store.
- Redaction happens before persistence to avoid secrets landing in state.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .redaction import redact_event, redact_obj, redact_text

CROCKFORD32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_ulid() -> str:
    """Generate a ULID-like identifier (26 Crockford base32 chars)."""
    t_ms = int(time.time() * 1000)
    if t_ms < 0 or t_ms >= 2**48:
        raise ValueError("time out of range for ULID")
    time_bytes = t_ms.to_bytes(6, "big")
    rand_bytes = secrets.token_bytes(10)
    data = time_bytes + rand_bytes  # 16 bytes
    value = int.from_bytes(data, "big") << 2  # pad to 130 bits
    chars: List[str] = []
    for i in range(26):
        idx = (value >> (125 - 5 * i)) & 0x1F
        chars.append(CROCKFORD32[idx])
    return "".join(chars)


def _sha256_hex(b: bytes) -> str:
    import hashlib

    return hashlib.sha256(b).hexdigest()


@dataclass
class TransactionPaths:
    root: str
    meta_json: str
    events_jsonl: str
    inputs_dir: str
    context_dir: str
    patches_dir: str
    patches_raw_dir: str
    patches_redacted_dir: str
    artifacts_dir: str
    blobs_dir: str
    blobs_raw_dir: str
    blobs_redacted_dir: str
    approvals_dir: str
    outputs_dir: str


class TransactionStore:
    """Filesystem-backed transaction store.

    Layout:
        {root}/transactions/YYYY/MM/DD/{txid}/
            transaction.json
            events.jsonl
            patches/{sha256}.diff
            artifacts/{sha256}.json
            approvals/
            inputs/
            context/
            outputs/

    Notes:
    - patches and artifacts are content-addressed by SHA-256 of the *raw* bytes.
      The persisted file content is redacted by default.
    """

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.tx_root = os.path.join(self.root, "transactions")
        os.makedirs(self.tx_root, exist_ok=True)

    # -----------------------------
    # Transaction lifecycle
    # -----------------------------

    def create_transaction(
        self,
        workspace_roots: List[str],
        cwd: str,
        sandbox_policy: Dict[str, Any],
        approval_policy: str,
        description: str = "",
        labels: Optional[Dict[str, str]] = None,
        thread_id: Optional[str] = None,
    ) -> Tuple[str, TransactionPaths]:
        """Create a new transaction and write initial metadata + events."""
        if not workspace_roots:
            raise ValueError("workspace_roots must be non-empty")

        txid = _new_ulid()
        now = _utc_now()
        dt = datetime.now(timezone.utc)
        tx_dir = os.path.join(
            self.tx_root,
            dt.strftime("%Y"),
            dt.strftime("%m"),
            dt.strftime("%d"),
            txid,
        )
        os.makedirs(tx_dir, exist_ok=False)

        paths = TransactionPaths(
            root=tx_dir,
            meta_json=os.path.join(tx_dir, "transaction.json"),
            events_jsonl=os.path.join(tx_dir, "events.jsonl"),
            inputs_dir=os.path.join(tx_dir, "inputs"),
            context_dir=os.path.join(tx_dir, "context"),
            patches_dir=os.path.join(tx_dir, "patches"),
            patches_raw_dir=os.path.join(tx_dir, "patches", "raw"),
            patches_redacted_dir=os.path.join(tx_dir, "patches", "redacted"),
            artifacts_dir=os.path.join(tx_dir, "artifacts"),
            blobs_dir=os.path.join(tx_dir, "blobs"),
            blobs_raw_dir=os.path.join(tx_dir, "blobs", "raw"),
            blobs_redacted_dir=os.path.join(tx_dir, "blobs", "redacted"),
            approvals_dir=os.path.join(tx_dir, "approvals"),
            outputs_dir=os.path.join(tx_dir, "outputs"),
        )

        for d in [
            paths.inputs_dir,
            paths.context_dir,
            paths.patches_dir,
            paths.patches_raw_dir,
            paths.patches_redacted_dir,
            paths.artifacts_dir,
            paths.blobs_dir,
            paths.blobs_raw_dir,
            paths.blobs_redacted_dir,
            paths.approvals_dir,
            paths.outputs_dir,
        ]:
            os.makedirs(d, exist_ok=True)

        meta: Dict[str, Any] = {
            "version": "0",
            "transaction_id": txid,
            "created_at": now,
            "updated_at": now,
            "status": "created",
            "workspace_roots": [os.path.abspath(p) for p in workspace_roots],
            "cwd": os.path.abspath(cwd),
            "sandbox_policy": sandbox_policy,
            "approval_policy": approval_policy,
            "active_thread_id": thread_id,
            "current_turn_id": None,
            "labels": labels or {},
            "notes": "",
            "pointers": {
                "events_jsonl": "events.jsonl",
                "latest_diff": None,
                "latest_turn": None,
                "latest_artifact": None,
            },
        }

        with open(paths.meta_json, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        # Initialize events ledger.
        Path(paths.events_jsonl).write_text("", encoding="utf-8")

        # Initial events
        self.append_event(
            paths,
            "tx/meta",
            {
                "transaction_id": txid,
                "workspace_roots": meta["workspace_roots"],
                "cwd": meta["cwd"],
                "sandbox_policy": sandbox_policy,
                "approval_policy": approval_policy,
                "description": description,
                "labels": meta["labels"],
            },
        )
        self.update_status(paths, "in_progress", reason="created")
        return txid, paths

    def get_paths(self, transaction_id: str) -> TransactionPaths:
        """Locate an existing transaction by ID and return its paths.

        Enables **resume** semantics across process restarts.
        """
        # Layout assumption:
        #   root/transactions/YYYY/MM/DD/{txid}/...
        for year in sorted(os.listdir(self.tx_root), reverse=True):
            ydir = os.path.join(self.tx_root, year)
            if not os.path.isdir(ydir):
                continue
            for month in sorted(os.listdir(ydir), reverse=True):
                mdir = os.path.join(ydir, month)
                if not os.path.isdir(mdir):
                    continue
                for day in sorted(os.listdir(mdir), reverse=True):
                    ddir = os.path.join(mdir, day)
                    if not os.path.isdir(ddir):
                        continue
                    candidate = os.path.join(ddir, transaction_id)
                    if os.path.isdir(candidate):
                        return TransactionPaths(
                            root=candidate,
                            meta_json=os.path.join(candidate, "transaction.json"),
                            events_jsonl=os.path.join(candidate, "events.jsonl"),
                            inputs_dir=os.path.join(candidate, "inputs"),
                            context_dir=os.path.join(candidate, "context"),
                            patches_dir=os.path.join(candidate, "patches"),
                            patches_raw_dir=os.path.join(candidate, "patches", "raw"),
                            patches_redacted_dir=os.path.join(candidate, "patches", "redacted"),
                            artifacts_dir=os.path.join(candidate, "artifacts"),
                            blobs_dir=os.path.join(candidate, "blobs"),
                            blobs_raw_dir=os.path.join(candidate, "blobs", "raw"),
                            blobs_redacted_dir=os.path.join(candidate, "blobs", "redacted"),
                            approvals_dir=os.path.join(candidate, "approvals"),
                            outputs_dir=os.path.join(candidate, "outputs"),
                        )
        raise FileNotFoundError(f"transaction not found: {transaction_id}")

    # -----------------------------
    # Ledger
    # -----------------------------

    def append_event(
        self,
        paths: TransactionPaths,
        event_type: str,
        payload: Dict[str, Any],
        *,
        timestamp: Optional[str] = None,
    ) -> None:
        """Append an event to the transaction ledger.

        Checkpoint 8+: redact secrets before persistence.
        """
        event = {"timestamp": timestamp or _utc_now(), "type": event_type, "payload": payload}
        safe_event, _kinds = redact_event(event)
        line = json.dumps(safe_event, ensure_ascii=False)
        with open(paths.events_jsonl, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def iter_events(self, paths: TransactionPaths) -> Iterable[Dict[str, Any]]:
        if not os.path.exists(paths.events_jsonl):
            return
        with open(paths.events_jsonl, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue

    # -----------------------------
    # Metadata
    # -----------------------------

    def read_meta(self, paths: TransactionPaths) -> Dict[str, Any]:
        with open(paths.meta_json, "r", encoding="utf-8") as f:
            return json.load(f)

    def write_meta(self, paths: TransactionPaths, meta: Dict[str, Any]) -> None:
        meta["updated_at"] = _utc_now()
        with open(paths.meta_json, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    def update_status(self, paths: TransactionPaths, new_status: str, reason: str = "") -> None:
        meta = self.read_meta(paths)
        old = meta.get("status")
        meta["status"] = new_status
        self.write_meta(paths, meta)
        self.append_event(
            paths,
            "tx/status",
            {
                "transaction_id": meta["transaction_id"],
                "from": old,
                "to": new_status,
                "reason": reason,
            },
        )

    # -----------------------------
    # Blobs
    # -----------------------------

    def store_patch(
        self,
        paths: TransactionPaths,
        unified_diff: str,
        *,
        redacted_diff: Optional[str] = None,
        contains_secrets: bool = False,
    ) -> str:
        """Store a unified diff as a content-addressed patchset.

        patch_id = sha256(raw_diff_bytes)

        Checkpoint 8+: we keep redaction discipline for anything that could end up
        in logs/UI, *but* Checkpoint 11 requires apply to use the **stored diff itself**.
        Therefore we persist:
          - raw diff at patches/raw/{patch_id}.diff  (for apply engine)
          - redacted diff at patches/redacted/{patch_id}.diff (for UI/ledger pointers)

        NOTE: The raw diff is still subject to the "secret introduction" guardrail
        at apply time; storing raw diffs is considered sensitive.
        """
        b = unified_diff.encode("utf-8")
        patch_id = _sha256_hex(b)

        raw_fn = os.path.join(paths.patches_raw_dir, f"{patch_id}.diff")
        red_fn = os.path.join(paths.patches_redacted_dir, f"{patch_id}.diff")

        if not os.path.exists(raw_fn):
            with open(raw_fn, "wb") as f:
                f.write(unified_diff.encode("utf-8"))

        if not os.path.exists(red_fn):
            content = redacted_diff
            if content is None:
                content, _ = redact_text(unified_diff)
            with open(red_fn, "wb") as f:
                f.write(content.encode("utf-8"))

        meta = self.read_meta(paths)
        meta.setdefault("pointers", {})["latest_diff"] = f"patches/redacted/{patch_id}.diff"
        meta.setdefault("pointers", {})["latest_diff_redacted"] = True
        meta.setdefault("pointers", {})["latest_diff_contains_secrets"] = bool(contains_secrets)
        self.write_meta(paths, meta)
        return patch_id

    def read_patch_raw(self, paths: TransactionPaths, patch_id: str) -> str:
        fn = os.path.join(paths.patches_raw_dir, f"{patch_id}.diff")
        with open(fn, "r", encoding="utf-8") as f:
            return f.read()

    def read_patch_redacted(self, paths: TransactionPaths, patch_id: str) -> str:
        fn = os.path.join(paths.patches_redacted_dir, f"{patch_id}.diff")
        with open(fn, "r", encoding="utf-8") as f:
            return f.read()

    def store_artifact_json(
        self,
        paths: TransactionPaths,
        *,
        kind: str,
        raw_obj: Dict[str, Any],
        redacted_obj: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Store a JSON artifact, content-addressed by the SHA-256 of the *raw* JSON bytes.

        Returns (artifact_id, artifact_ref).

        The persisted artifact content is redacted by default.
        """
        raw_bytes = json.dumps(raw_obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
        artifact_id = _sha256_hex(raw_bytes)
        fn = os.path.join(paths.artifacts_dir, f"{artifact_id}.json")

        if not os.path.exists(fn):
            if redacted_obj is None:
                safe_obj, kinds = redact_obj(raw_obj)
                assert isinstance(safe_obj, dict)
            else:
                safe_obj, kinds = redact_obj(redacted_obj)
                assert isinstance(safe_obj, dict)
            safe_obj.setdefault("_artifact", {})
            safe_obj["_artifact"] = {
                "kind": kind,
                "raw_sha256": artifact_id,
                "redacted": True,
                "redaction_kinds": kinds,
            }
            with open(fn, "w", encoding="utf-8") as f:
                json.dump(safe_obj, f, indent=2, ensure_ascii=False)

        meta = self.read_meta(paths)
        meta.setdefault("pointers", {})["latest_artifact"] = f"artifacts/{artifact_id}.json"
        self.write_meta(paths, meta)

        ref = {
            "artifact_id": artifact_id,
            "kind": kind,
            "path": f"artifacts/{artifact_id}.json",
            "content_type": "application/json",
            "redacted": True,
        }
        return artifact_id, ref

    # -----------------------------
    # Raw/Redacted blob storage (Checkpoint 12)
    # -----------------------------

    def store_blob_text(
        self,
        paths: TransactionPaths,
        *,
        kind: str,
        raw_text: str,
        content_type: str = "text/plain; charset=utf-8",
        redacted_text: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Store a text blob as a content-addressed object.

        blob_id = sha256(raw_bytes)

        We persist both:
          - raw at blobs/raw/{blob_id}.txt (for internal apply/merge)
          - redacted at blobs/redacted/{blob_id}.txt (for safe inspection)

        The ledger should only ever reference the redacted path; raw reads should
        be internal-only.
        """
        b = raw_text.encode("utf-8")
        blob_id = _sha256_hex(b)

        os.makedirs(paths.blobs_raw_dir, exist_ok=True)
        os.makedirs(paths.blobs_redacted_dir, exist_ok=True)

        raw_fn = os.path.join(paths.blobs_raw_dir, f"{blob_id}.txt")
        red_fn = os.path.join(paths.blobs_redacted_dir, f"{blob_id}.txt")

        if not os.path.exists(raw_fn):
            with open(raw_fn, "wb") as f:
                f.write(b)

        if not os.path.exists(red_fn):
            content = redacted_text
            if content is None:
                content, _ = redact_text(raw_text)
            with open(red_fn, "wb") as f:
                f.write(content.encode("utf-8"))

        ref = {
            "blob_id": blob_id,
            "kind": kind,
            "path": f"blobs/redacted/{blob_id}.txt",
            "content_type": content_type,
            "redacted": True,
        }
        return blob_id, ref

    def read_blob_raw(self, paths: TransactionPaths, blob_id: str) -> str:
        fn = os.path.join(paths.blobs_raw_dir, f"{blob_id}.txt")
        with open(fn, "rb") as f:
            return f.read().decode("utf-8")

    def read_blob_redacted(self, paths: TransactionPaths, blob_id: str) -> str:
        fn = os.path.join(paths.blobs_redacted_dir, f"{blob_id}.txt")
        with open(fn, "rb") as f:
            return f.read().decode("utf-8")


    # -----------------------------
    # Discovery
    # -----------------------------

    def list_transactions(self, *, limit: int = 50) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for year in sorted(os.listdir(self.tx_root), reverse=True):
            ydir = os.path.join(self.tx_root, year)
            if not os.path.isdir(ydir):
                continue
            for month in sorted(os.listdir(ydir), reverse=True):
                mdir = os.path.join(ydir, month)
                if not os.path.isdir(mdir):
                    continue
                for day in sorted(os.listdir(mdir), reverse=True):
                    ddir = os.path.join(mdir, day)
                    if not os.path.isdir(ddir):
                        continue
                    for txid in sorted(os.listdir(ddir), reverse=True):
                        txdir = os.path.join(ddir, txid)
                        if not os.path.isdir(txdir):
                            continue
                        meta_path = os.path.join(txdir, "transaction.json")
                        if not os.path.exists(meta_path):
                            continue
                        try:
                            with open(meta_path, "r", encoding="utf-8") as f:
                                meta = json.load(f)
                            out.append(
                                {
                                    "transaction_id": meta.get("transaction_id"),
                                    "created_at": meta.get("created_at"),
                                    "updated_at": meta.get("updated_at"),
                                    "status": meta.get("status"),
                                    "cwd": meta.get("cwd"),
                                    "pointers": meta.get("pointers", {}),
                                }
                            )
                        except Exception:
                            continue
                        if len(out) >= limit:
                            return out
        return out
