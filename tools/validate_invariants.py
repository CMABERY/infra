"""validate_invariants.py

Checkpoint 10: validate transaction ledger invariants.

This validator is intentionally dependency-light (standard library only).
It checks event sequencing and referential integrity constraints so that
"illegal" traces are caught automatically.

Usage:
  python tools/validate_invariants.py            # validate most-recent transaction
  python tools/validate_invariants.py --tx <id>  # validate a specific transaction

Exit codes:
  0 = OK
  2 = invariant violations found
  1 = runtime error (validator itself)
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _find_tx_dir(tx_root: Path, txid: str) -> Optional[Path]:
    for p in tx_root.rglob(txid):
        # Expect .../YYYY/MM/DD/<txid>
        if p.is_dir() and p.name == txid and (p / "transaction.json").exists():
            return p
    return None


def _latest_events_file(tx_root: Path) -> Optional[Path]:
    events = sorted(tx_root.rglob("events.jsonl"), key=lambda p: p.stat().st_mtime)
    return events[-1] if events else None


def _read_events(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except Exception:
            # ignore malformed lines; they are already a problem, but keep validator robust
            out.append({"type": "_parse_error", "payload": {"line": ln}})
    return out


class Violations:
    def __init__(self) -> None:
        self.errors: List[str] = []

    def add(self, msg: str) -> None:
        self.errors.append(msg)

    def ok(self) -> bool:
        return not self.errors


def _rel_exists(tx_dir: Path, rel: str) -> bool:
    try:
        p = (tx_dir / rel).resolve()
        # do not allow escaping the tx_dir in case rel is malicious
        txr = tx_dir.resolve()
        if txr != p and not str(p).startswith(str(txr) + os.sep):
            return False
        return p.exists()
    except Exception:
        return False


def validate_transaction(tx_dir: Path) -> Tuple[bool, List[str]]:
    v = Violations()

    meta_path = tx_dir / "transaction.json"
    events_path = tx_dir / "events.jsonl"
    if not meta_path.exists():
        return False, [f"Missing transaction.json in {tx_dir}"]
    if not events_path.exists():
        return False, [f"Missing events.jsonl in {tx_dir}"]

    meta = _load_json(meta_path)
    txid = meta.get("transaction_id")

    events = _read_events(events_path)
    if not events:
        v.add("Ledger is empty")
        return False, v.errors

    # Invariant I1: first event is tx/meta
    if events[0].get("type") != "tx/meta":
        v.add(f"I1: first event must be tx/meta (got {events[0].get('type')})")

    # Tracking
    seen_turns: set[str] = set()
    approvals: dict[str, Dict[str, Any]] = {}
    decisions: set[str] = set()
    in_apply: Optional[str] = None
    closed = False

    last_status: Optional[str] = None

    for i, ev in enumerate(events):
        et = ev.get("type")
        pl = ev.get("payload") or {}

        if closed:
            v.add(f"I9: events after tx/close are illegal (line {i+1}, type={et})")
            break

        if et == "_parse_error":
            v.add(f"Parse error line {i+1}")
            continue

        if et == "tx/meta":
            if txid and pl.get("transaction_id") != txid:
                v.add(f"I2: tx/meta.transaction_id mismatch (meta={txid}, event={pl.get('transaction_id')})")

        elif et == "tx/status":
            frm = pl.get("from")
            to = pl.get("to")
            if last_status is None:
                # first status should originate from 'created' typically
                last_status = to
            else:
                if frm != last_status:
                    v.add(f"I3: tx/status from mismatch at line {i+1} (expected from={last_status}, got from={frm})")
                last_status = to

        elif et == "turn/start":
            tid = pl.get("turn_id")
            if not isinstance(tid, str) or not tid:
                v.add(f"I4: turn/start missing turn_id (line {i+1})")
            else:
                if tid in seen_turns:
                    v.add(f"I4: duplicate turn_id {tid} (line {i+1})")
                seen_turns.add(tid)

        elif et == "turn/item":
            tid = pl.get("turn_id")
            item = pl.get("item") or {}
            if not isinstance(tid, str) or tid not in seen_turns:
                v.add(f"I5: turn/item references unknown turn_id {tid!r} (line {i+1})")
            if not isinstance(item, dict) or not item.get("id") or not item.get("type"):
                v.add(f"I5: turn/item missing id/type (line {i+1})")

            # Referential integrity checks
            it = item.get("type")
            md = item.get("metadata") or {}

            if it == "fileChange":
                patch_id = md.get("patch_id")
                if isinstance(patch_id, str):
                    if not _rel_exists(tx_dir, f"patches/raw/{patch_id}.diff"):
                        v.add(f"I11: missing patch raw file patches/raw/{patch_id}.diff (line {i+1})")
                    if not _rel_exists(tx_dir, f"patches/redacted/{patch_id}.diff"):
                        v.add(f"I11: missing patch redacted file patches/redacted/{patch_id}.diff (line {i+1})")

            if it == "commandExecution" and item.get("status") in ("completed", "failed"):
                art = (md.get("artifact") or {}).get("artifact_id")
                if isinstance(art, str):
                    if not _rel_exists(tx_dir, f"artifacts/{art}.json"):
                        v.add(f"I12: missing command artifact artifacts/{art}.json (line {i+1})")

        elif et == "artifact/stored":
            rel = pl.get("path")
            if isinstance(rel, str):
                if not _rel_exists(tx_dir, rel):
                    v.add(f"I10: artifact/stored references missing path {rel} (line {i+1})")
            else:
                v.add(f"I10: artifact/stored missing path (line {i+1})")

        elif et == "approval/request":
            rid = pl.get("approval_request_id")
            if not isinstance(rid, str) or not rid:
                v.add(f"I6: approval/request missing approval_request_id (line {i+1})")
            else:
                if rid in approvals:
                    v.add(f"I6: duplicate approval_request_id {rid} (line {i+1})")
                approvals[rid] = pl

        elif et == "approval/decision":
            rid = pl.get("approval_request_id")
            if not isinstance(rid, str) or not rid:
                v.add(f"I6: approval/decision missing approval_request_id (line {i+1})")
            else:
                if rid not in approvals:
                    v.add(f"I6: approval/decision references unknown request {rid} (line {i+1})")
                if rid in decisions:
                    v.add(f"I6: approval/decision duplicated for {rid} (line {i+1})")
                decisions.add(rid)

        elif et == "apply/start":
            aid = pl.get("apply_id")
            if not isinstance(aid, str) or not aid:
                v.add(f"I7: apply/start missing apply_id (line {i+1})")
            if in_apply is not None:
                v.add(f"I7: nested apply/start not allowed (line {i+1})")
            in_apply = str(aid)

        elif et == "apply/complete":
            aid = pl.get("apply_id")
            if in_apply is None:
                v.add(f"I8: apply/complete without apply/start (line {i+1})")
            else:
                if str(aid) != str(in_apply):
                    v.add(f"I8: apply_id mismatch (start={in_apply}, complete={aid}) (line {i+1})")
            in_apply = None

        elif et == "tx/close":
            closed = True

    # Invariant: if apply/start occurred, apply/complete must also occur
    if in_apply is not None:
        v.add(f"I8: apply started ({in_apply}) but never completed")

    return v.ok(), v.errors


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate transaction ledger invariants (Checkpoint 10).")
    ap.add_argument("--tx", dest="txid", default=None, help="Transaction id to validate")
    ap.add_argument("--state", default=None, help="Override state dir (default: project codex_like_mvp/state)")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    state_root = Path(args.state) if args.state else (repo_root / "codex_like_mvp" / "state")
    tx_root = state_root / "transactions"

    if args.txid:
        tx_dir = _find_tx_dir(tx_root, args.txid)
        if not tx_dir:
            print("transaction not found:", args.txid)
            return 1
    else:
        latest = _latest_events_file(tx_root)
        if not latest:
            print("No transactions found under:", tx_root)
            return 1
        tx_dir = latest.parent

    ok, errors = validate_transaction(tx_dir)
    if ok:
        print("Invariant validation OK for:", tx_dir)
        return 0
    print("Invariant validation FAILED for:", tx_dir)
    for e in errors[:200]:
        print(" -", e)
    if len(errors) > 200:
        print(f"... and {len(errors)-200} more")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
