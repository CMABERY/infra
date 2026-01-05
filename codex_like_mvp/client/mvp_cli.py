"""mvp_cli.py — minimal client for codex_like_mvp

Checkpoint 9 CLI:
  - REVIEW is default: `demo` proposes a patch and stops.
  - APPLY is explicit: pass `--apply` or use `apply --tx ...`.
  - RESUME is supported: `resume --tx ...` shows status + can apply.

The client:
  - spawns the backend as a subprocess
  - sends JSON-RPC requests
  - prints streaming typed events
  - handles approvals (interactive or auto)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class RpcResponse:
    id: Any
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    _event: threading.Event = field(default_factory=threading.Event)


class Client:
    def __init__(
        self,
        backend_cmd: list[str],
        *,
        auto_approve: bool = False,
        auto_approve_secrets: bool = False,
    ) -> None:
        self.backend_cmd = backend_cmd
        self.auto_approve = auto_approve
        self.auto_approve_secrets = auto_approve_secrets
        self.proc = subprocess.Popen(
            backend_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert self.proc.stdin and self.proc.stdout and self.proc.stderr
        self._id = 0
        self._lock = threading.Lock()
        self._pending: Dict[Any, RpcResponse] = {}
        self._stop = threading.Event()

        self._t_out = threading.Thread(target=self._reader, args=(self.proc.stdout,), daemon=True)
        self._t_err = threading.Thread(target=self._stderr_reader, args=(self.proc.stderr,), daemon=True)
        self._t_out.start()
        self._t_err.start()

    def _stderr_reader(self, fp) -> None:
        for line in fp:
            if not line:
                break
            sys.stderr.write(line)
            sys.stderr.flush()

    def _reader(self, fp) -> None:
        for line in fp:
            if self._stop.is_set():
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue

            if msg.get("method") == "event":
                event = msg.get("params", {}).get("event")
                if isinstance(event, dict):
                    self._handle_event(event)
                continue

            resp_id = msg.get("id")
            with self._lock:
                slot = self._pending.get(resp_id)

            # Important: do not create new slots in the reader thread.
            # If we didn't register this id (e.g., fire-and-forget approval/respond), ignore.
            if slot is None:
                continue

            if "result" in msg:
                slot.result = msg["result"]
            if "error" in msg:
                slot.error = msg["error"]
            slot._event.set()

    def _handle_event(self, event: Dict[str, Any]) -> None:
        et = event.get("type")
        payload = event.get("payload") or {}

        if et == "approval/request":
            kind = payload.get("kind")
            txid = payload.get("transaction_id")
            prompt = payload.get("prompt")
            apr_id = payload.get("approval_request_id")
            print("\n[approval/request]", f"tx={txid}", f"kind={kind}")
            if prompt:
                print(" ", prompt)

            if not (apr_id and txid):
                return

            if self.auto_approve and (kind != "secrets_override" or self.auto_approve_secrets):
                print("  auto-approving\n")
                self.send_no_wait("approval/respond", {"transactionId": txid, "approvalRequestId": apr_id, "decision": "approve"})
            else:
                # Never block the reader thread on input() or a synchronous RPC call.
                def _prompt_and_send() -> None:
                    ans = input("Approve? (y/N): ").strip().lower()
                    decision = "approve" if ans == "y" else "deny"
                    self.send_no_wait("approval/respond", {"transactionId": txid, "approvalRequestId": apr_id, "decision": decision})

                threading.Thread(target=_prompt_and_send, daemon=True).start()

        elif et == "turn/item":
            item = payload.get("item") or {}
            it = item.get("type")
            st = item.get("status")
            iid = item.get("id")
            if it == "fileChange":
                changes = item.get("changes") or []
                n = len(changes) if isinstance(changes, list) else 0
                patch_id = item.get("patchId") or (item.get("metadata") or {}).get("patch_id")
                print(f"[turn/item] fileChange {st} id={iid} files={n} patch_id={patch_id}")
            elif it == "commandExecution":
                ec = item.get("exitCode")
                art = ((item.get("metadata") or {}).get("artifact") or {}).get("artifact_id")
                print(f"[turn/item] commandExecution {st} id={iid} exitCode={ec} artifact={art}")
            else:
                print(f"[turn/item] {it} {st} id={iid}")
        elif et == "artifact/stored":
            print(f"[artifact] stored kind={payload.get('kind')} id={payload.get('artifact_id')} path={payload.get('path')}")
        else:
            print(f"[{et}]", payload)

    def call(self, method: str, params: Dict[str, Any]) -> RpcResponse:
        with self._lock:
            self._id += 1
            rid = self._id
            slot = RpcResponse(id=rid)
            self._pending[rid] = slot

        req = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()

        slot._event.wait(timeout=60.0)
        with self._lock:
            self._pending.pop(rid, None)
        return slot

    def send_no_wait(self, method: str, params: Dict[str, Any]) -> Any:
        """Send a request but do not wait for the response.

        Used for approval/respond from the event reader thread to avoid deadlock.
        """
        with self._lock:
            self._id += 1
            rid = self._id

        req = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        return rid

    def close(self) -> None:
        self._stop.set()
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
        except Exception:
            pass


def _backend_cmd(*, backend_flags: list[str]) -> list[str]:
    return [sys.executable, "-m", "codex_like_mvp.backend.mvp_server", *backend_flags]


def apply_transaction(c: Client, txid: str) -> bool:
    for _ in range(20):
        r = c.call("apply/execute", {"transactionId": txid})
        if r.error:
            print("apply/execute error:", r.error)
            return False
        if not r.result:
            print("apply/execute: no result")
            return False
        if r.result.get("ok") is True:
            print("apply/execute: applied")
            return True
        pending = r.result.get("pendingApprovals") or []
        if pending:
            time.sleep(0.05)
            continue
        print("apply/execute: not ok, no pending approvals")
        return False
    print("apply/execute: too many retries")
    return False


def run_demo(*, sandbox_type: str, backend_flags: list[str], auto_approve: bool, auto_approve_secrets: bool, do_apply: bool) -> int:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    demo_root = os.path.join(repo_root, "demo_workspace")

    c = Client(backend_cmd=_backend_cmd(backend_flags=backend_flags), auto_approve=auto_approve, auto_approve_secrets=auto_approve_secrets)

    resp = c.call("thread/start", {"workspaceRoots": [demo_root], "cwd": demo_root})
    if resp.error:
        print("thread/start error:", resp.error)
        return 1
    thread_id = resp.result["threadId"]

    instruction = "Remove TODO line(s) from demo workspace files (multi-file patchset; review only)."
    sandbox_policy = {"type": sandbox_type, "writable_roots": [demo_root], "network_access": False}

    resp2 = c.call("turn/start", {
        "threadId": thread_id,
        "description": "demo review turn",
        "cwd": demo_root,
        "approvalPolicy": "on-request",
        "sandboxPolicy": sandbox_policy,
        "input": [{"type": "input_text", "text": instruction}],
        "targetFiles": ["example.js", "utils.js", "notes.md"],
        "workspaceRoot": demo_root,
        "needle": "TODO",
    })
    if resp2.error:
        print("turn/start error:", resp2.error)
        return 1

    turn_id = resp2.result["turnId"]
    txid = resp2.result["transactionId"]
    print(f"\nStarted REVIEW turn {turn_id} transaction {txid}\n")

    while True:
        r = c.call("turn/get", {"turnId": turn_id})
        if r.result and r.result.get("status") in ("completed", "failed", "interrupted"):
            print("\nFinal turn status:", r.result["status"])
            if r.result.get("diff"):
                print("\nProposed diff (redacted if needed):\n")
                print(r.result["diff"])
            break
        time.sleep(0.05)

    if do_apply:
        print("\n--- APPLY (explicit) ---\n")
        apply_transaction(c, txid)
    else:
        print("\n(No apply performed; transaction remains in 'proposed' status.)\n")

    print(f"\nLedger under: {os.path.join(repo_root, 'state', 'transactions')}\n")
    c.close()
    return 0


def run_apply(*, txid: str, backend_flags: list[str], auto_approve: bool, auto_approve_secrets: bool) -> int:
    c = Client(backend_cmd=_backend_cmd(backend_flags=backend_flags), auto_approve=auto_approve, auto_approve_secrets=auto_approve_secrets)
    ok = apply_transaction(c, txid)
    c.close()
    return 0 if ok else 1


def run_resume(*, txid: str, backend_flags: list[str], auto_approve: bool, auto_approve_secrets: bool, do_apply: bool) -> int:
    c = Client(backend_cmd=_backend_cmd(backend_flags=backend_flags), auto_approve=auto_approve, auto_approve_secrets=auto_approve_secrets)
    r = c.call("transaction/resume", {"transactionId": txid})
    if r.error:
        print("transaction/resume error:", r.error)
        c.close()
        return 1
    tx = (r.result or {}).get("transaction") or {}
    pending = (r.result or {}).get("pendingApprovals") or []
    print("\n[resume] status:", tx.get("status"))
    if pending:
        print("[resume] pending approvals:", len(pending))
        for p in pending:
            print(" -", p.get("approval_request_id"), p.get("kind"), p.get("prompt"))
    else:
        print("[resume] pending approvals: 0")

    if do_apply:
        print("\n--- APPLY (explicit) ---\n")
        ok = apply_transaction(c, txid)
        c.close()
        return 0 if ok else 1

    c.close()
    return 0


def run_list(*, backend_flags: list[str]) -> int:
    c = Client(backend_cmd=_backend_cmd(backend_flags=backend_flags))
    r = c.call("transaction/list", {"limit": 25})
    if r.error:
        print("transaction/list error:", r.error)
        c.close()
        return 1
    data = (r.result or {}).get("data") or []
    print("\nRecent transactions:\n")
    for row in data:
        print("-", row.get("transaction_id"), row.get("status"), row.get("created_at"), row.get("pointers", {}).get("latest_diff"))
    c.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")

    def add_backend_flags(p):
        p.add_argument("--danger", action="store_true", help="Start backend with --danger (required for full/danger sandbox).")
        p.add_argument("--online", action="store_true", help="Start backend with --online (unsafe).")
        p.add_argument("--allow-sensitive-roots", action="store_true", help="Start backend allowing sensitive roots (unsafe).")
        p.add_argument("--allow-denylisted-commands", action="store_true", help="Start backend allowing denylisted commands (unsafe).")
        p.add_argument("--auto-approve", action="store_true", help="Auto-approve approvals (convenience; not for secrets_override).")
        p.add_argument("--auto-approve-secrets", action="store_true", help="Auto-approve secrets_override approvals (unsafe).")

    demo = sub.add_parser("demo", help="Run the built-in demo review turn.")
    demo.add_argument("--sandbox", default="workspace-write", choices=["read-only", "workspace-write", "full/danger"], help="Sandbox type sent to backend per turn.")
    demo.add_argument("--apply", action="store_true", help="Explicitly apply after review (calls apply/execute).")
    add_backend_flags(demo)

    apply_cmd = sub.add_parser("apply", help="Apply an existing transaction by id.")
    apply_cmd.add_argument("--tx", required=True, help="Transaction id")
    add_backend_flags(apply_cmd)

    resume_cmd = sub.add_parser("resume", help="Resume an existing transaction (show status, optionally apply).")
    resume_cmd.add_argument("--tx", required=True, help="Transaction id")
    resume_cmd.add_argument("--apply", action="store_true", help="Explicitly apply after resume.")
    add_backend_flags(resume_cmd)

    list_cmd = sub.add_parser("list", help="List recent transactions.")
    add_backend_flags(list_cmd)

    args = ap.parse_args()

    flags: list[str] = []
    if getattr(args, "danger", False):
        flags.append("--danger")
    if getattr(args, "online", False):
        flags.append("--online")
    if getattr(args, "allow_sensitive_roots", False):
        flags.append("--allow-sensitive-roots")
    if getattr(args, "allow_denylisted_commands", False):
        flags.append("--allow-denylisted-commands")

    auto_approve = bool(getattr(args, "auto_approve", False))
    auto_approve_secrets = bool(getattr(args, "auto_approve_secrets", False))

    if args.cmd == "demo":
        return run_demo(sandbox_type=args.sandbox, backend_flags=flags, auto_approve=auto_approve, auto_approve_secrets=auto_approve_secrets, do_apply=bool(args.apply))
    if args.cmd == "apply":
        return run_apply(txid=str(args.tx), backend_flags=flags, auto_approve=auto_approve, auto_approve_secrets=auto_approve_secrets)
    if args.cmd == "resume":
        return run_resume(txid=str(args.tx), backend_flags=flags, auto_approve=auto_approve, auto_approve_secrets=auto_approve_secrets, do_apply=bool(args.apply))
    if args.cmd == "list":
        return run_list(backend_flags=flags)

    print("Try one of: demo, apply, resume, list")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
