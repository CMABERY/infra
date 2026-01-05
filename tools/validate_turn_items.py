#!/usr/bin/env python3
"""
Validate 'turn/item' events in a transaction/event JSONL file against a Turn Item JSON Schema.

Usage:
  python validate_turn_items.py --schema turn_item_schema_v0.1.json --jsonl events.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from jsonschema import Draft202012Validator

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield i, json.loads(line)
            except json.JSONDecodeError as e:
                yield i, {"__parse_error__": str(e), "__raw__": line}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", required=True, help="Path to turn item JSON Schema.")
    ap.add_argument("--jsonl", required=True, help="Path to JSONL file containing events.")
    ap.add_argument("--event-type", default="turn/item", help="Event type to validate (default: turn/item).")
    args = ap.parse_args()

    schema_path = Path(args.schema)
    jsonl_path = Path(args.jsonl)

    if not schema_path.exists():
        print(f"Schema not found: {schema_path}", file=sys.stderr)
        return 2
    if not jsonl_path.exists():
        print(f"JSONL not found: {jsonl_path}", file=sys.stderr)
        return 2

    schema = load_json(schema_path)
    validator = Draft202012Validator(schema)

    total = 0
    validated = 0
    invalid = 0
    parse_errors = 0
    invalid_examples = []

    for lineno, event in iter_jsonl(jsonl_path):
        total += 1
        if "__parse_error__" in event:
            parse_errors += 1
            invalid_examples.append({"lineno": lineno, "error": event["__parse_error__"]})
            continue

        if event.get("type") != args.event_type:
            continue

        payload = event.get("payload", {})
        item = payload.get("item")
        if item is None:
            invalid += 1
            invalid_examples.append({"lineno": lineno, "error": "Missing payload.item"})
            continue

        validated += 1
        errs = sorted(validator.iter_errors(item), key=lambda e: e.path)
        if errs:
            invalid += 1
            invalid_examples.append({
                "lineno": lineno,
                "item_id": item.get("id"),
                "item_type": item.get("type"),
                "errors": [{
                    "path": "/".join(map(str, e.path)),
                    "message": e.message
                } for e in errs[:10]]
            })

    report = {
        "schema": str(schema_path),
        "jsonl": str(jsonl_path),
        "event_type": args.event_type,
        "total_lines": total,
        "validated_events": validated,
        "invalid_events": invalid,
        "parse_errors": parse_errors,
        "ok": (invalid == 0 and parse_errors == 0),
        "invalid_examples": invalid_examples[:20],
    }

    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
