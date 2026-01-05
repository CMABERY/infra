"""
validate_latest_transaction.py

Validate the most recent transaction ledger under codex_like_mvp/state/transactions/
against the TurnItem schema.

Usage:
  python tools/validate_latest_transaction.py
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from jsonschema import Draft202012Validator  # type: ignore

def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    schema_path = repo_root / "specs" / "turn_item_schema_v0.1.json"
    schema = _load_json(schema_path)
    validator = Draft202012Validator(schema)

    tx_root = repo_root / "codex_like_mvp" / "state" / "transactions"
    events_files = sorted(tx_root.rglob("events.jsonl"), key=lambda p: p.stat().st_mtime)
    if not events_files:
        print("No transactions found under:", tx_root)
        return 1
    latest = events_files[-1]
    errors = []
    for i, line in enumerate(latest.read_text(encoding="utf-8").splitlines()):
        ev = json.loads(line)
        if ev.get("type") == "turn/item":
            item = ev.get("payload", {}).get("item")
            for err in validator.iter_errors(item):
                errors.append((i, err.message))
    if errors:
        print("Validation FAILED for:", latest)
        for i, msg in errors[:50]:
            print(f"  line {i+1}: {msg}")
        return 2
    print("Validation OK for:", latest)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
