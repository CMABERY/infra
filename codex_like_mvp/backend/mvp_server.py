"""mvp_server.py — JSON-RPC-ish backend over stdio (NDJSON)

This backend is the *kernel* of a transaction-first, governed patch engine.

Checkpoint history (cumulative):
  - 7: sandbox + command policy + path guards + approvals
  - 8: secret redaction + "secret introduction" guardrails
  - 9: review/apply/resume semantics (review proposes; apply explicit)
  - 10: multi-file patchsets + tool-call provenance artifacts + invariant-ready event sequences

Transport:
  - Requests/Responses: JSON-RPC-ish over NDJSON stdin/stdout
  - Notifications: {"jsonrpc":"2.0","method":"event","params":{"event":{timestamp,type,payload}}}

Design notes:
  - This is an application-level safety layer, not an OS sandbox.
  - Secrets are redacted before UI emission and before ledger persistence.
  - Side effects (writes) occur only in apply/execute.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .agent import classify_command, propose_patchset_remove_todo_text, safe_listdir_command
from .diff_apply import parse_unified_diff, apply_file_patch
from .merge3 import merge3_text
from .redaction import SecretFinding, detect_secret_introductions_in_diff, redact_event, redact_text
from .security import (
    CommandDecision,
    DangerNotEnabled,
    SandboxPolicy,
    SandboxViolation,
    SecurityConfig,
    SecurityEnforcer,
)
from .transaction_store import TransactionPaths, TransactionStore


def utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False)


def sha256_hex(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class StdIoTransport:
    """NDJSON over stdin/stdout with a global write lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def send(self, msg: Dict[str, Any]) -> None:
        line = json_dumps(msg)
        with self._lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def notify_event(self, event: Dict[str, Any]) -> None:
        self.send({"jsonrpc": "2.0", "method": "event", "params": {"event": event}})


# -----------------------------
# State models
# -----------------------------


@dataclass
class ThreadInfo:
    thread_id: str
    created_at: str
    workspace_roots: List[str]
    cwd: str


@dataclass
class TurnInfo:
    turn_id: str
    thread_id: str
    transaction_id: str
    created_at: str
    status: str = "inProgress"
    items: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    diff: Optional[str] = None
    error: Optional[Dict[str, Any]] = None
    cancelled: bool = False
    tx_paths: Optional[TransactionPaths] = None


# -----------------------------
# Backend
# -----------------------------


class Backend:
    def __init__(
        self,
        *,
        state_dir: str,
        security_config: SecurityConfig,
        default_sandbox_type: str = "workspace-write",
        default_network_access: bool = False,
    ) -> None:
        self.transport = StdIoTransport()
        self.store = TransactionStore(root=state_dir)
        self.threads: Dict[str, ThreadInfo] = {}
        self.turns: Dict[str, TurnInfo] = {}

        # In-process hint mapping (not relied upon for resume)
        self._approval_index: Dict[str, str] = {}  # approval_request_id -> transaction_id

        self._lock = threading.Lock()
        self.security_config = security_config
        self.default_sandbox_type = default_sandbox_type
        self.default_network_access = default_network_access

        if self.default_sandbox_type == "full/danger" and not self.security_config.danger_enabled:
            raise DangerNotEnabled(
                "Server default sandbox is full/danger but --danger was not provided."
            )

    # ---- Event persistence + notify

    def _emit_event(
        self,
        paths: Optional[TransactionPaths],
        event_type: str,
        payload: Dict[str, Any],
        *,
        persist: bool = True,
    ) -> None:
        """Emit an event to UI + (optionally) persist to the transaction ledger.

        Secrets are redacted before UI emission and persistence.
        """
        event = {"timestamp": utc_now_iso(), "type": event_type, "payload": payload}
        safe_event, _kinds = redact_event(event)
        if persist and paths is not None:
            self.store.append_event(
                paths,
                safe_event["type"],
                safe_event.get("payload") or {},
                timestamp=safe_event.get("timestamp"),
            )
        self.transport.notify_event(safe_event)

    def _transition_tx_status(self, paths: TransactionPaths, new_status: str, reason: str = "") -> None:
        meta = self.store.read_meta(paths)
        old = meta.get("status")
        self.store.update_status(paths, new_status, reason=reason)
        # Notify without re-persisting (update_status already persisted tx/status)
        self._emit_event(
            paths,
            "tx/status",
            {
                "transaction_id": meta.get("transaction_id"),
                "from": old,
                "to": new_status,
                "reason": reason,
            },
            persist=False,
        )

    # ---- Policy helpers

    def _parse_sandbox_policy(self, params: Dict[str, Any], thread: ThreadInfo) -> SandboxPolicy:
        sp = params.get("sandboxPolicy") or {}
        sp_type = sp.get("type") or self.default_sandbox_type
        writable_roots = sp.get("writable_roots") or sp.get("writableRoots") or thread.workspace_roots
        net = sp.get("network_access")
        if net is None:
            net = sp.get("networkAccess")
        if net is None:
            net = self.default_network_access
        return SandboxPolicy(type=sp_type, writable_roots=list(writable_roots), network_access=bool(net))

    # ---- Approvals

    def _load_approvals(self, paths: TransactionPaths) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
        """Return (requests_by_id, decision_by_request_id)."""
        requests: Dict[str, Dict[str, Any]] = {}
        decisions: Dict[str, str] = {}
        for ev in self.store.iter_events(paths):
            et = ev.get("type")
            pl = ev.get("payload") or {}
            if et == "approval/request":
                rid = pl.get("approval_request_id")
                if isinstance(rid, str):
                    requests[rid] = pl
            elif et == "approval/decision":
                rid = pl.get("approval_request_id")
                dec = pl.get("decision")
                if isinstance(rid, str) and dec in ("approve", "deny"):
                    decisions[rid] = dec
        return requests, decisions

    def _decision_by_fingerprint(self, paths: TransactionPaths) -> Dict[str, str]:
        """Compute latest decision by fingerprint (approve/deny)."""
        reqs, decs = self._load_approvals(paths)
        out: Dict[str, str] = {}
        for rid, req in reqs.items():
            fp = req.get("fingerprint")
            if not isinstance(fp, str):
                continue
            dec = decs.get(rid)
            if dec in ("approve", "deny"):
                out[fp] = dec
        return out

    def _request_approval(
        self,
        paths: TransactionPaths,
        *,
        transaction_id: str,
        turn_id: str,
        kind: str,
        item_id: str,
        prompt: str,
        fingerprint: str,
    ) -> str:
        apr_id = f"apr_{uuid.uuid4().hex[:12]}"
        payload = {
            "transaction_id": transaction_id,
            "turn_id": turn_id,
            "approval_request_id": apr_id,
            "kind": kind,
            "item_id": item_id,
            "prompt": prompt,
            "fingerprint": fingerprint,
        }
        self._approval_index[apr_id] = transaction_id
        self._transition_tx_status(paths, "awaiting_approval", reason="approval requested")
        self._emit_event(paths, "approval/request", payload)
        return apr_id

    # ---- Artifact storage

    def _store_artifact(
        self,
        paths: TransactionPaths,
        *,
        kind: str,
        raw_obj: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Store a redacted JSON artifact and emit an artifact/stored event."""
        artifact_id, ref = self.store.store_artifact_json(paths, kind=kind, raw_obj=raw_obj)
        self._emit_event(paths, "artifact/stored", {
            "transaction_id": self.store.read_meta(paths).get("transaction_id"),
            "artifact_id": artifact_id,
            "kind": kind,
            "path": ref.get("path"),
            "content_type": ref.get("content_type"),
            "redacted": True,
        })
        return ref

    def _store_blob_text(
        self,
        paths: TransactionPaths,
        *,
        kind: str,
        raw_text: str,
        content_type: str = "text/plain; charset=utf-8",
    ) -> Dict[str, Any]:
        """Store a text blob (raw+redacted) and emit an artifact/stored event.

        Used for BASE snapshots to enable 3-way merge (Checkpoint 12).
        """
        blob_id, ref = self.store.store_blob_text(paths, kind=kind, raw_text=raw_text, content_type=content_type)
        # Emit artifact/stored referencing the redacted path (never the raw file)
        self._emit_event(paths, "artifact/stored", {
            "transaction_id": self.store.read_meta(paths).get("transaction_id"),
            "artifact_id": blob_id,
            "kind": kind,
            "path": ref.get("path"),
            "content_type": ref.get("content_type"),
            "redacted": True,
        })
        return ref


    # -----------------------------
    # Turn worker (REVIEW phase)
    # -----------------------------

    def _scan_workspace_for_targets(
        self,
        *,
        workspace_root: str,
        enforcer: SecurityEnforcer,
        needle: str,
        exts: Sequence[str] = (".js", ".ts", ".py", ".md", ".txt"),
        max_files: int = 50,
        max_bytes: int = 250_000,
    ) -> List[str]:
        """Best-effort scan for candidate files containing needle.

        This is intentionally conservative:
        - skips common huge dirs
        - skips symlinks
        - caps file count and max bytes
        """
        skip_dirs = {".git", "node_modules", "dist", "build", "venv", ".venv", "__pycache__"}
        found: List[str] = []
        wr = os.path.abspath(workspace_root)

        for root, dirs, files in os.walk(wr):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fn in files:
                if len(found) >= max_files:
                    return found
                if not any(fn.endswith(e) for e in exts):
                    continue
                abs_path = os.path.join(root, fn)
                try:
                    if os.path.islink(abs_path):
                        continue
                    st = os.stat(abs_path)
                    if st.st_size > max_bytes:
                        continue
                except Exception:
                    continue

                rel = os.path.relpath(abs_path, wr).replace("\\", "/")
                try:
                    safe_abs = enforcer.resolve_path(wr, rel)
                    with open(safe_abs, "r", encoding="utf-8") as f:
                        txt = f.read(max_bytes)
                except Exception:
                    continue

                if needle in txt:
                    found.append(rel)

        return found

    def _run_turn_worker(self, turn: TurnInfo, params: Dict[str, Any]) -> None:
        """Run the REVIEW phase: propose patchset + log typed items.

        Checkpoint 9+: this does NOT apply changes.
        Checkpoint 10: can propose a *multi-file* patchset.
        """
        try:
            thread = self.threads[turn.thread_id]
            sandbox = self._parse_sandbox_policy(params, thread)
            approval_policy = (params.get("approvalPolicy") or "on-request")
            workspace_root = params.get("workspaceRoot") or thread.workspace_roots[0]

            enforcer = SecurityEnforcer(
                sandbox=sandbox,
                workspace_roots=thread.workspace_roots,
                config=self.security_config,
            )

            assert turn.tx_paths is not None
            paths = turn.tx_paths

            # Ensure tx is in_progress
            if self.store.read_meta(paths).get("status") != "in_progress":
                self._transition_tx_status(paths, "in_progress", reason="turn started")

            self._emit_event(
                paths,
                "turn/start",
                {
                    "transaction_id": turn.transaction_id,
                    "turn_id": turn.turn_id,
                    "thread_id": turn.thread_id,
                    "input": params.get("input", []),
                    "cwd": params.get("cwd") or thread.cwd,
                    "sandbox_policy": {
                        "type": sandbox.type,
                        "writable_roots": sandbox.writable_roots,
                        "network_access": sandbox.network_access,
                    },
                    "approval_policy": approval_policy,
                    "mode": "review",
                },
            )

            # 1) Plan
            plan_item = {
                "id": "item_plan_1",
                "type": "plan",
                "op": "upsert",
                "status": "completed",
                "explanation": "Review: run safe command; propose patchset; stop (apply is explicit).",
                "steps": [
                    {"id": "step_1", "title": "Run a safe command", "status": "completed"},
                    {"id": "step_2", "title": "Propose patchset", "status": "completed"},
                    {"id": "step_3", "title": "Stop (no apply)", "status": "completed"},
                ],
            }
            turn.items[plan_item["id"]] = plan_item
            self._emit_event(paths, "turn/item", {"transaction_id": turn.transaction_id, "turn_id": turn.turn_id, "item": plan_item})

            if turn.cancelled:
                raise InterruptedError("Turn interrupted")

            # 2) Safe command execution (provenance captured)
            cmd = safe_listdir_command()
            decision: CommandDecision = enforcer.decide_command(cmd)
            exec_item = {
                "id": "item_exec_1",
                "type": "commandExecution",
                "op": "upsert",
                "status": "inProgress",
                "command": cmd,
                "cwd": params.get("cwd") or thread.cwd,
                "classification": classify_command(cmd),
                "metadata": {
                    "policy": {
                        "decision": decision.action,
                        "reason": decision.reason,
                        "allowlisted": decision.allowlisted,
                        "denylisted": decision.denylisted,
                        "network_related": decision.network_related,
                        "sandbox": sandbox.type,
                        "offline": not sandbox.network_access,
                    }
                },
            }
            turn.items[exec_item["id"]] = exec_item
            self._emit_event(paths, "turn/item", {"transaction_id": turn.transaction_id, "turn_id": turn.turn_id, "item": exec_item})

            started = time.time()
            stdout = ""
            stderr = ""
            exit_code = -1
            if decision.action != "allow":
                exec_item["status"] = "failed"
                stderr = f"Not executed in review mode: {decision.action} ({decision.reason})"
            else:
                res = subprocess.run(cmd, cwd=exec_item["cwd"], capture_output=True, text=True, check=False)
                exit_code = int(res.returncode)
                stdout = res.stdout or ""
                stderr = res.stderr or ""
                exec_item["status"] = "completed" if exit_code == 0 else "failed"

            dur_ms = max(0.0, (time.time() - started) * 1000.0)
            exec_item["exitCode"] = exit_code
            exec_item["durationMs"] = dur_ms

            # Store provenance artifact (input + output)
            prov = {
                "kind": "commandExecution",
                "command": cmd,
                "cwd": exec_item["cwd"],
                "exitCode": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "durationMs": dur_ms,
                "decision": {
                    "action": decision.action,
                    "reason": decision.reason,
                    "allowlisted": decision.allowlisted,
                    "denylisted": decision.denylisted,
                    "network_related": decision.network_related,
                },
            }
            artifact_ref = self._store_artifact(paths, kind="tool_provenance:commandExecution", raw_obj=prov)
            exec_item.setdefault("metadata", {})["artifact"] = artifact_ref

            # Keep event text small; UI can open artifact file from disk if desired.
            # (We still allow redacted snippets in aggregatedOutput.)
            agg = (stdout + ("\n" + stderr if stderr else "")).strip()
            redacted_agg, _kinds = redact_text(agg)
            if len(redacted_agg) > 2000:
                redacted_agg = redacted_agg[:2000] + "\n...<truncated>"
            exec_item["aggregatedOutput"] = redacted_agg

            self._emit_event(paths, "turn/item", {"transaction_id": turn.transaction_id, "turn_id": turn.turn_id, "item": exec_item})

            if turn.cancelled:
                raise InterruptedError("Turn interrupted")

            # 3) Propose patchset
            needle = params.get("needle") or "TODO"

            target_files: List[str] = []
            if isinstance(params.get("targetFiles"), list):
                target_files = [str(p) for p in params.get("targetFiles") if isinstance(p, str)]
            elif isinstance(params.get("targetFile"), str):
                target_files = [str(params.get("targetFile"))]
            else:
                target_files = self._scan_workspace_for_targets(
                    workspace_root=str(workspace_root),
                    enforcer=enforcer,
                    needle=str(needle),
                )

            # Read files (guarded)
            old_by_path: Dict[str, str] = {}
            base_sha_by_path: Dict[str, str] = {}
            base_blob_by_path: Dict[str, str] = {}
            for rel in target_files:
                abs_path = enforcer.resolve_path(str(workspace_root), rel)
                with open(abs_path, "r", encoding="utf-8") as f:
                    old = f.read()
                rel_norm = rel.replace("\\", "/")
                old_by_path[rel_norm] = old
                base_sha_by_path[rel_norm] = sha256_hex(old)
                # Store BASE snapshot for 3-way merge (raw+redacted blob; ledger references redacted).
                base_ref = self._store_blob_text(paths, kind="base_snapshot", raw_text=old)
                base_blob_by_path[rel_norm] = str(base_ref.get("blob_id"))
            patchset = propose_patchset_remove_todo_text(old_by_path, needle=str(needle))
            if not patchset.changes:
                msg = {
                    "id": "item_msg_1",
                    "type": "agentMessage",
                    "op": "final",
                    "status": "completed",
                    "content": "No changes proposed: no matching TODO lines found.",
                }
                self._emit_event(paths, "turn/item", {"transaction_id": turn.transaction_id, "turn_id": turn.turn_id, "item": msg})
                self._transition_tx_status(paths, "completed", reason="no-op")
                self._emit_event(paths, "tx/close", {"transaction_id": turn.transaction_id, "status": "completed"})
                turn.status = "completed"
                return

            raw_diff = patchset.unified_diff
            redacted_diff, redaction_kinds = redact_text(raw_diff)

            secret_intros: List[SecretFinding] = detect_secret_introductions_in_diff(raw_diff)
            contains_secret_introductions = len(secret_intros) > 0

            patch_id = self.store.store_patch(
                paths,
                raw_diff,
                redacted_diff=redacted_diff,
                contains_secrets=contains_secret_introductions,
            )
            patch_fp = f"patchset:{patch_id}"

            # Patch proposal provenance artifact
            proposal_prov = {
                "kind": "patchProposal",
                "patch_id": patch_id,
                "fingerprint": patch_fp,
                "needle": str(needle),
                "changed_files": applied_files,
                "base_sha256_by_path": {k: base_sha_by_path.get(k) for k in applied_files},
                "base_snapshot_blob_by_path": {k: base_blob_by_path.get(k) for k in applied_files},
                "secret_introductions": [{"kind": f.kind, "line": f.line} for f in secret_intros],
            }
            proposal_art_ref = self._store_artifact(paths, kind="tool_provenance:fileChange", raw_obj=proposal_prov)

            # fileChange item with per-file diffs (redacted)
            # NOTE: schema v0.1 expresses changes as an *array* with {path, kind, unified_diff}.
            changes: List[Dict[str, Any]] = []
            for ch in patchset.changes:
                d_red, _k = redact_text(ch.unified_diff)
                changes.append({"path": ch.rel_path, "kind": "update", "unified_diff": d_red})

            file_item = {
                "id": "item_patch_1",
                "type": "fileChange",
                "op": "upsert",
                "status": "completed",
                "patchId": patch_id,
                "changes": changes,
                "metadata": {
                    "sandbox": sandbox.type,
                    "applied": False,
                    "patch_id": patch_id,
                    "patch_fingerprint": patch_fp,
                    "base_sha256_by_path": {k: base_sha_by_path.get(k) for k in applied_files},
                    "base_snapshot_blob_by_path": {k: base_blob_by_path.get(k) for k in applied_files},
                    "diff_redacted": True,
                    "redaction_kinds": redaction_kinds,
                    "secret_introductions": [{"kind": f.kind, "line": f.line} for f in secret_intros],
                    "provenance_artifact": proposal_art_ref,
                },
            }
            turn.items[file_item["id"]] = file_item
            self._emit_event(paths, "turn/item", {"transaction_id": turn.transaction_id, "turn_id": turn.turn_id, "item": file_item})

            diff_item = {
                "id": "item_turn_diff_1",
                "type": "turnDiff",
                "op": "upsert",
                "status": "completed",
                "cwd": params.get("cwd") or thread.cwd,
                "unified_diff": redacted_diff,
            }
            turn.items[diff_item["id"]] = diff_item
            turn.diff = redacted_diff
            self._emit_event(paths, "turn/item", {"transaction_id": turn.transaction_id, "turn_id": turn.turn_id, "item": diff_item})

            # Persist proposal pointer
            meta = self.store.read_meta(paths)
            ptr = meta.setdefault("pointers", {})
            ptr["latest_turn"] = turn.turn_id
            ptr["proposal"] = {
                "kind": "remove_todo_multi",
                "workspace_root": os.path.abspath(str(workspace_root)),
                "needle": str(needle),
                "target_files": applied_files,
                "base_sha256_by_path": {k: base_sha_by_path.get(k) for k in applied_files},
                "base_snapshot_blob_by_path": {k: base_blob_by_path.get(k) for k in applied_files},
                "patch_id": patch_id,
                "patch_fingerprint": patch_fp,
                "contains_secret_introductions": contains_secret_introductions,
                "proposal_turn_id": turn.turn_id,
                "proposal_item_id": file_item["id"],
            }
            self.store.write_meta(paths, meta)

            self._transition_tx_status(paths, "proposed", reason="patchset proposed (review complete)")

            turn.status = "completed"
            self._emit_event(paths, "turn/item", {
                "transaction_id": turn.transaction_id,
                "turn_id": turn.turn_id,
                "item": {"id": "item_turn_status_1", "type": "turnStatus", "op": "final", "status": "completed"},
            })

        except InterruptedError:
            if turn.tx_paths is not None:
                self._transition_tx_status(turn.tx_paths, "interrupted", reason="turn interrupted")
                self._emit_event(turn.tx_paths, "tx/close", {"transaction_id": turn.transaction_id, "status": "interrupted"})
            turn.status = "interrupted"
        except Exception as e:
            turn.status = "failed"
            turn.error = {"message": str(e), "type": e.__class__.__name__}
            if turn.tx_paths is not None:
                self._transition_tx_status(turn.tx_paths, "failed", reason="turn failed")
                self._emit_event(turn.tx_paths, "turn/item", {
                    "transaction_id": turn.transaction_id,
                    "turn_id": turn.turn_id,
                    "item": {"id": "item_error_1", "type": "error", "op": "final", "status": "failed", "message": str(e), "errorType": e.__class__.__name__},
                })
                self._emit_event(turn.tx_paths, "tx/close", {"transaction_id": turn.transaction_id, "status": "failed"})

    # -----------------------------
    # Apply phase (explicit)
    # -----------------------------

    def _load_latest_turn_item(self, paths: TransactionPaths, item_id: str) -> Optional[Dict[str, Any]]:
        """Scan events.jsonl and return the latest turn item with the given id.

        This is used to upsert/update items (e.g., mark fileChange as applied)
        without recomputing/redrawing diffs.
        """
        if not item_id:
            return None
        latest: Optional[Dict[str, Any]] = None
        try:
            with open(paths.events_jsonl, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    if ev.get("type") != "turn/item":
                        continue
                    pl = ev.get("payload") or {}
                    it = pl.get("item")
                    if isinstance(it, dict) and it.get("id") == item_id:
                        latest = it
        except FileNotFoundError:
            return None
        return latest

    def _apply_execute(self, txid: str) -> Dict[str, Any]:
        paths = self.store.get_paths(txid)
        meta = self.store.read_meta(paths)

        sandbox_dict = meta.get("sandbox_policy") or {}
        sandbox = SandboxPolicy(
            type=sandbox_dict.get("type") or self.default_sandbox_type,
            writable_roots=list(
                sandbox_dict.get("writable_roots")
                or sandbox_dict.get("writableRoots")
                or meta.get("workspace_roots")
                or []
            ),
            network_access=bool(
                sandbox_dict.get("network_access")
                if sandbox_dict.get("network_access") is not None
                else sandbox_dict.get("networkAccess", False)
            ),
        )

        approval_policy = meta.get("approval_policy") or "on-request"
        workspace_roots = meta.get("workspace_roots") or []

        enforcer = SecurityEnforcer(
            sandbox=sandbox,
            workspace_roots=workspace_roots,
            config=self.security_config,
        )

        ptr = (meta.get("pointers") or {})
        proposal = ptr.get("proposal")
        if not isinstance(proposal, dict):
            raise ValueError("No proposal found for transaction; run turn/start first.")

        if sandbox.type == "read-only":
            raise SandboxViolation("Sandbox is read-only: apply/execute is not permitted.")

        workspace_root = proposal.get("workspace_root") or (workspace_roots[0] if workspace_roots else "")
        target_files = proposal.get("target_files")
        base_map = proposal.get("base_sha256_by_path")
        base_blob_map = proposal.get("base_snapshot_blob_by_path") or {}
        expected_patch_id = proposal.get("patch_id")
        patch_fp = proposal.get("patch_fingerprint")
        proposal_turn_id = proposal.get("proposal_turn_id")
        proposal_item_id = proposal.get("proposal_item_id")

        if not (
            isinstance(workspace_root, str)
            and isinstance(target_files, list)
            and isinstance(base_map, dict)
            and isinstance(expected_patch_id, str)
            and isinstance(patch_fp, str)
        ):
            raise ValueError("Invalid proposal metadata; cannot apply.")

        # Load stored raw diff (do NOT recompute); verify patch_id matches proposal.
        raw_diff = self.store.read_patch_raw(paths, str(expected_patch_id))
        patch_id = sha256_hex(raw_diff)
        if patch_id != expected_patch_id:
            raise ValueError("Stored patch content does not match expected patch_id; refusing to apply.")

        # Parse stored diff into per-file patches.
        file_patches = parse_unified_diff(raw_diff)

        # Planned files list (for apply/start)
        planned_files: List[str] = []
        for fp in file_patches:
            rel_path = fp.new_path if not fp.is_delete else fp.old_path
            if rel_path and rel_path != "/dev/null":
                planned_files.append(rel_path)
        planned_files = sorted(set(planned_files))

        # Guardrail: secret introductions must be explicitly overridden.
        secret_intros: List[SecretFinding] = detect_secret_introductions_in_diff(raw_diff)
        contains_secret_introductions = len(secret_intros) > 0
        secret_override_fp = f"secret:{patch_fp}"
        decisions = self._decision_by_fingerprint(paths)

        required_fps: List[Tuple[str, str, str]] = []
        if contains_secret_introductions:
            required_fps.append(
                (
                    secret_override_fp,
                    "secrets_override",
                    "Potential secret introduction detected. Approve apply anyway?",
                )
            )
        required_fps.append((patch_fp, "fileChange", f"Apply patchset ({len(planned_files)} files)?"))

        missing: List[Dict[str, Any]] = []
        denied: List[str] = []
        for fp, kind, prompt in required_fps:
            dec = decisions.get(fp)
            if dec == "approve":
                continue
            if dec == "deny":
                denied.append(fp)
                continue
            missing.append({"fingerprint": fp, "kind": kind, "prompt": prompt})

        if denied:
            raise ValueError("Apply blocked: required approval previously denied.")

        if missing:
            if approval_policy == "never":
                raise ValueError("Apply requires approvals but approval_policy is 'never'.")
            self._transition_tx_status(paths, "awaiting_approval", reason="apply requires approval")
            pending: List[Dict[str, Any]] = []
            for m in missing:
                apr_id = self._request_approval(
                    paths,
                    transaction_id=txid,
                    turn_id=str(proposal_turn_id or meta.get("current_turn_id") or ""),
                    kind=str(m["kind"]),
                    item_id=str(proposal_item_id or "item_patch_1"),
                    prompt=str(m["prompt"]),
                    fingerprint=str(m["fingerprint"]),
                )
                pending.append({"approval_request_id": apr_id, **m})
            return {"ok": False, "pendingApprovals": pending}

        # All approvals satisfied: apply
        apply_id = f"apply_{uuid.uuid4().hex[:12]}"

        self._emit_event(
            paths,
            "apply/start",
            {
                "transaction_id": txid,
                "apply_id": apply_id,
                "patch_ids": [expected_patch_id],
                "turn_id": proposal_turn_id,
                "sandbox": sandbox.type,
                "files": planned_files,
            },
        )

        before_sha: Dict[str, str] = {}
        after_sha: Dict[str, str] = {}
        applied_files: List[str] = []
        conflicted_files: List[str] = []
        merge_used_files: List[str] = []

        # Apply each file patch from the stored diff.
        for fp in file_patches:
            rel_path = fp.new_path if not fp.is_delete else fp.old_path
            if rel_path == "/dev/null":
                continue

            abs_path = enforcer.resolve_path(str(workspace_root), rel_path)

            if fp.is_delete:
                enforcer.assert_can_write(abs_path)
                if os.path.exists(abs_path):
                    with open(abs_path, "r", encoding="utf-8") as f:
                        before_txt = f.read()
                    before_sha[rel_path] = sha256_hex(before_txt)
                    os.remove(abs_path)
                else:
                    before_sha[rel_path] = "MISSING"
                after_sha[rel_path] = "DELETED"
                applied_files.append(rel_path)
                continue

            # Read current workspace content (empty for new files)
            old_text = ""
            if os.path.exists(abs_path):
                with open(abs_path, "r", encoding="utf-8") as f:
                    old_text = f.read()
                before_sha[rel_path] = sha256_hex(old_text)
            else:
                before_sha[rel_path] = "MISSING"

            expected_base = base_map.get(rel_path)

            # Try direct apply first (fast path). If it fails and the base hash mismatched,
            # fall back to 3-way merge using the BASE snapshot captured at proposal time.
            new_text: str
            try:
                new_text = apply_file_patch(old_text, fp)
            except Exception:
                if not expected_base:
                    raise
                # only attempt 3-way merge if the workspace diverged from the proposal base
                if before_sha[rel_path] == expected_base:
                    # base matches but apply failed: treat as a real error
                    raise

                blob_id = base_blob_map.get(rel_path)
                if not isinstance(blob_id, str) or not blob_id:
                    raise ValueError(f"Base snapshot missing for {rel_path}; cannot 3-way merge.")

                base_text = self.store.read_blob_raw(paths, blob_id)
                try:
                    target_text = apply_file_patch(base_text, fp)
                except Exception as e:
                    raise ValueError(f"Cannot apply patch to BASE snapshot for {rel_path}: {e}") from e

                merged_text, had_conflicts = merge3_text(base_text, old_text, target_text)
                new_text = merged_text
                merge_used_files.append(rel_path)
                if had_conflicts:
                    conflicted_files.append(rel_path)

            enforcer.assert_can_write(abs_path)
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            with open(abs_path, "w", encoding="utf-8") as f:
                f.write(new_text)

            after_sha[rel_path] = sha256_hex(new_text)
            applied_files.append(rel_path)

        # Apply provenance artifact
        apply_prov = {
            "kind": "applyResult",
            "apply_id": apply_id,
            "patch_id": expected_patch_id,
            "files": applied_files,
            "planned_files": planned_files,
            "base_sha256_by_path": {p: base_map.get(p) for p in applied_files},
            "before_sha256_by_path": before_sha,
            "after_sha256_by_path": after_sha,
            "merge_used_files": merge_used_files,
            "conflicted_files": conflicted_files,
            "secret_introductions": [{"kind": f.kind, "line": f.line} for f in secret_intros],
        }
        apply_art_ref = self._store_artifact(paths, kind="tool_provenance:apply", raw_obj=apply_prov)

        success = len(conflicted_files) == 0
        self._emit_event(
            paths,
            "apply/complete",
            {
                "transaction_id": txid,
                "apply_id": apply_id,
                "success": success,
                "turn_id": proposal_turn_id,
                "conflicts": bool(conflicted_files),
                "conflicted_files": conflicted_files,
                "apply_artifact": apply_art_ref,
            },
        )

        # Upsert the original fileChange item to mark applied/conflicted.
        if isinstance(proposal_item_id, str) and proposal_item_id:
            orig = self._load_latest_turn_item(paths, proposal_item_id)
            if isinstance(orig, dict) and orig.get("type") == "fileChange":
                meta0 = dict(orig.get("metadata") or {})
                meta0["applied"] = success
                meta0["conflicts"] = bool(conflicted_files)
                meta0["conflicted_files"] = conflicted_files
                meta0["apply_artifact"] = apply_art_ref
                meta0["sandbox"] = sandbox.type
                applied_item = dict(orig)
                applied_item["op"] = "upsert"
                applied_item["status"] = "completed"
                applied_item["metadata"] = meta0
                self._emit_event(paths, "turn/item", {"transaction_id": txid, "turn_id": proposal_turn_id, "item": applied_item})

        if not success:
            # Conflicts are a terminal condition for this apply attempt, but not a "failed" transaction.
            # The workspace now contains conflict markers; user can resolve manually and start a new tx.
            self._transition_tx_status(paths, "conflicted", reason="merge conflicts")
            return {
                "ok": False,
                "conflicts": True,
                "conflictedFiles": conflicted_files,
                "appliedFiles": applied_files,
                "apply_artifact": apply_art_ref,
            }

        self._transition_tx_status(paths, "applied", reason="apply complete")
        self._transition_tx_status(paths, "completed", reason="transaction complete")
        self._emit_event(paths, "tx/close", {"transaction_id": txid, "status": "completed"})
        return {"ok": True, "appliedFiles": applied_files, "apply_artifact": apply_art_ref}

    def handle(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if req.get("jsonrpc") != "2.0":
            return self._error(req.get("id"), -32600, "Invalid Request")
        if "method" not in req:
            return self._error(req.get("id"), -32600, "Invalid Request")

        method = req["method"]
        params = req.get("params") or {}
        req_id = req.get("id")

        try:
            if method == "system/capabilities":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "sandbox_modes": ["read-only", "workspace-write", "full/danger"],
                        "danger_enabled": self.security_config.danger_enabled,
                        "allow_sensitive_roots": self.security_config.allow_sensitive_roots,
                        "allow_denylisted_commands": self.security_config.allow_denylisted_commands,
                        "default_sandbox": self.default_sandbox_type,
                        "default_network_access": self.default_network_access,
                        "checkpoint": 10,
                        "semantics": {
                            "review": True,
                            "explicit_apply": True,
                            "resume": True,
                            "multi_file_patchsets": True,
                            "tool_provenance_artifacts": True,
                        },
                    },
                }

            if method == "thread/list":
                data = []
                for t in self.threads.values():
                    data.append({"id": t.thread_id, "preview": f"{t.cwd} ({len(t.workspace_roots)} roots)"})
                return {"jsonrpc": "2.0", "id": req_id, "result": {"data": data, "cursor": None}}

            if method == "thread/start":
                workspace_roots = params.get("workspaceRoots") or []
                if not workspace_roots:
                    return self._error(req_id, -32602, "workspaceRoots required")
                cwd = params.get("cwd") or workspace_roots[0]
                thread_id = f"thread_{uuid.uuid4().hex[:12]}"
                self.threads[thread_id] = ThreadInfo(
                    thread_id=thread_id,
                    created_at=utc_now_iso(),
                    workspace_roots=workspace_roots,
                    cwd=cwd,
                )
                return {"jsonrpc": "2.0", "id": req_id, "result": {"threadId": thread_id}}

            if method == "transaction/list":
                limit = int(params.get("limit") or 50)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"data": self.store.list_transactions(limit=limit)}}

            if method in ("transaction/get", "transaction/resume"):
                txid = params.get("transactionId")
                if not isinstance(txid, str):
                    return self._error(req_id, -32602, "transactionId required")
                paths = self.store.get_paths(txid)
                meta = self.store.read_meta(paths)
                reqs, decs = self._load_approvals(paths)
                pending = []
                for rid, reqp in reqs.items():
                    if rid not in decs:
                        pending.append(reqp)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"transaction": meta, "pendingApprovals": pending},
                }

            if method == "turn/start":
                thread_id = params.get("threadId")
                if not isinstance(thread_id, str) or thread_id not in self.threads:
                    return self._error(req_id, -32602, f"Unknown threadId: {thread_id}")

                thread = self.threads[thread_id]
                turn_id = f"turn_{uuid.uuid4().hex[:12]}"
                sandbox = self._parse_sandbox_policy(params, thread)
                approval_policy = params.get("approvalPolicy") or "on-request"

                txid, paths = self.store.create_transaction(
                    workspace_roots=thread.workspace_roots,
                    cwd=params.get("cwd") or thread.cwd,
                    sandbox_policy={
                        "type": sandbox.type,
                        "writable_roots": sandbox.writable_roots,
                        "network_access": sandbox.network_access,
                    },
                    approval_policy=approval_policy,
                    description=params.get("description") or "turn/start",
                    thread_id=thread_id,
                )

                # Mirror initial persisted events to the client without re-persisting.
                self._emit_event(
                    None,
                    "tx/meta",
                    {
                        "transaction_id": txid,
                        "workspace_roots": thread.workspace_roots,
                        "cwd": params.get("cwd") or thread.cwd,
                        "sandbox_policy": {
                            "type": sandbox.type,
                            "writable_roots": sandbox.writable_roots,
                            "network_access": sandbox.network_access,
                        },
                        "approval_policy": approval_policy,
                        "description": params.get("description") or "turn/start",
                        "labels": {},
                    },
                    persist=False,
                )
                self._emit_event(
                    None,
                    "tx/status",
                    {"transaction_id": txid, "from": "created", "to": "in_progress", "reason": "created"},
                    persist=False,
                )

                turn = TurnInfo(
                    turn_id=turn_id,
                    thread_id=thread_id,
                    transaction_id=txid,
                    created_at=utc_now_iso(),
                    tx_paths=paths,
                )
                self.turns[turn_id] = turn

                th = threading.Thread(target=self._run_turn_worker, args=(turn, params), daemon=True)
                th.start()

                return {"jsonrpc": "2.0", "id": req_id, "result": {"turnId": turn_id, "transactionId": txid}}

            if method == "turn/get":
                turn_id = params.get("turnId")
                if not isinstance(turn_id, str) or turn_id not in self.turns:
                    return self._error(req_id, -32602, f"Unknown turnId: {turn_id}")
                t = self.turns[turn_id]
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "turnId": t.turn_id,
                        "threadId": t.thread_id,
                        "transactionId": t.transaction_id,
                        "status": t.status,
                        "diff": t.diff,
                        "error": t.error,
                        "items": list(t.items.values()),
                    },
                }

            if method == "turn/interrupt":
                turn_id = params.get("turnId")
                if not isinstance(turn_id, str) or turn_id not in self.turns:
                    return self._error(req_id, -32602, f"Unknown turnId: {turn_id}")
                t = self.turns[turn_id]
                t.cancelled = True
                t.status = "interrupted"
                return {"jsonrpc": "2.0", "id": req_id, "result": {"ok": True}}

            if method == "approval/respond":
                apr_id = params.get("approvalRequestId")
                decision = params.get("decision")
                txid = params.get("transactionId") or self._approval_index.get(str(apr_id))
                if not isinstance(apr_id, str) or not apr_id:
                    return self._error(req_id, -32602, "approvalRequestId required")
                if decision not in ("approve", "deny"):
                    return self._error(req_id, -32602, f"Invalid decision: {decision}")
                if not isinstance(txid, str) or not txid:
                    return self._error(req_id, -32602, "transactionId required for approval/respond")

                paths = self.store.get_paths(txid)
                reqs, decs = self._load_approvals(paths)
                if apr_id not in reqs:
                    return self._error(req_id, -32602, f"Unknown approvalRequestId: {apr_id}")
                if apr_id in decs:
                    return self._error(req_id, -32602, f"approvalRequestId already decided: {apr_id}")

                reqp = reqs[apr_id]
                payload = {
                    "transaction_id": txid,
                    "turn_id": reqp.get("turn_id"),
                    "approval_request_id": apr_id,
                    "decision": decision,
                    "kind": reqp.get("kind"),
                    "fingerprint": reqp.get("fingerprint"),
                }
                self._emit_event(paths, "approval/decision", payload)
                if self.store.read_meta(paths).get("status") == "awaiting_approval":
                    self._transition_tx_status(paths, "proposed", reason="approval recorded")
                return {"jsonrpc": "2.0", "id": req_id, "result": {"ok": True}}

            if method == "apply/execute":
                txid = params.get("transactionId")
                if not isinstance(txid, str) or not txid:
                    return self._error(req_id, -32602, "transactionId required")
                try:
                    result = self._apply_execute(txid)
                except Exception as e:
                    return self._error(req_id, -32603, f"Apply failed: {e}")
                return {"jsonrpc": "2.0", "id": req_id, "result": result}

            if method == "tx/close":
                txid = params.get("transactionId")
                if not isinstance(txid, str) or not txid:
                    return self._error(req_id, -32602, "transactionId required")
                status = params.get("status") or "completed"
                if status not in ("completed", "interrupted", "failed"):
                    return self._error(req_id, -32602, f"Invalid close status: {status}")
                paths = self.store.get_paths(txid)
                self._transition_tx_status(paths, status, reason="explicit close")
                self._emit_event(paths, "tx/close", {"transaction_id": txid, "status": status})
                return {"jsonrpc": "2.0", "id": req_id, "result": {"ok": True}}

            return self._error(req_id, -32601, f"Method not found: {method}")

        except KeyError as ke:
            return self._error(req_id, -32602, f"Missing param: {ke}")
        except FileNotFoundError as fe:
            return self._error(req_id, -32602, str(fe))
        except Exception as e:
            return self._error(req_id, -32603, f"Internal error: {e}")

    def _error(self, req_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def main() -> None:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    default_state = os.path.join(repo_root, "state")

    ap = argparse.ArgumentParser(description="codex_like_mvp backend (Checkpoint 10).")
    ap.add_argument(
        "--state-dir",
        default=default_state,
        help="State directory for transactions (default: codex_like_mvp/state)",
    )
    ap.add_argument("--danger", action="store_true", help="Enable full/danger sandbox mode (explicit opt-in).")
    ap.add_argument("--allow-sensitive-roots", action="store_true", help="Allow filesystem access to sensitive roots (VERY UNSAFE).")
    ap.add_argument("--allow-denylisted-commands", action="store_true", help="Allow executing denylisted commands (VERY UNSAFE).")
    ap.add_argument(
        "--default-sandbox",
        default="workspace-write",
        choices=["read-only", "workspace-write", "full/danger"],
        help="Default sandbox type.",
    )
    ap.add_argument("--online", action="store_true", help="Enable network_access by default (unsafe; prefer per-turn sandboxPolicy).")

    args = ap.parse_args()

    if args.danger:
        sys.stderr.write(
            "\n*** DANGER MODE ENABLED ***\n"
            "This server may allow operations outside the workspace.\n"
            "Sensitive roots are still blocked unless --allow-sensitive-roots is set.\n"
            "Proceed only if you understand the risks.\n\n"
        )
        sys.stderr.flush()

    cfg = SecurityConfig(
        danger_enabled=bool(args.danger),
        allow_sensitive_roots=bool(args.allow_sensitive_roots),
        allow_denylisted_commands=bool(args.allow_denylisted_commands),
    )

    backend = Backend(
        state_dir=os.path.abspath(args.state_dir),
        security_config=cfg,
        default_sandbox_type=args.default_sandbox,
        default_network_access=bool(args.online),
    )

    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            backend.transport.send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        resp = backend.handle(req)
        if resp is not None:
            backend.transport.send(resp)


if __name__ == "__main__":
    main()