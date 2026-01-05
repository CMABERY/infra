#!/usr/bin/env python3
"""
validate_rollout.py

Validate a Codex-style rollout JSONL file against a JSON Schema.

Usage:
  python validate_rollout.py /path/to/rollout.jsonl --schema /path/to/rollout_schema_v0.json --report /path/to/report.json

Exit codes:
  0 = valid
  1 = validation errors or parse errors
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from jsonschema import Draft202012Validator, FormatChecker

@dataclass
class Issue:
    line: int
    kind: str  # "parse_error" | "schema_error"
    message: str
    path: str

def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def validate_jsonl(jsonl_path: Path, schema: Dict[str, Any]) -> Dict[str, Any]:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    issues: List[Issue] = []
    counts: Counter[str] = Counter()
    total = 0

    with jsonl_path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue
            total += 1
            try:
                obj = json.loads(raw)
            except Exception as e:
                issues.append(Issue(
                    line=idx,
                    kind="parse_error",
                    message=str(e),
                    path="",
                ))
                continue

            # Count event types if present
            t = obj.get("type")
            if isinstance(t, str):
                counts[t] += 1
            else:
                counts["<missing_or_nonstring_type>"] += 1

            for err in validator.iter_errors(obj):
                # Build a dotted path like "payload.sandbox_policy.network_access"
                if err.absolute_path:
                    p = ".".join(str(x) for x in err.absolute_path)
                else:
                    p = ""
                issues.append(Issue(
                    line=idx,
                    kind="schema_error",
                    message=err.message,
                    path=p,
                ))

    return {
        "file": str(jsonl_path),
        "total_records": total,
        "type_counts": dict(counts),
        "valid": len(issues) == 0,
        "issues": [asdict(i) for i in issues],
    }

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", type=Path, help="Path to rollout .jsonl file")
    ap.add_argument("--schema", type=Path, required=True, help="Path to JSON Schema")
    ap.add_argument("--report", type=Path, default=None, help="Optional path to write JSON report")
    args = ap.parse_args()

    if not args.jsonl.exists():
        print(f"ERROR: JSONL not found: {args.jsonl}", file=sys.stderr)
        return 1
    if not args.schema.exists():
        print(f"ERROR: Schema not found: {args.schema}", file=sys.stderr)
        return 1

    schema = load_json(args.schema)
    report = validate_jsonl(args.jsonl, schema)

    # Human-readable summary
    print(f"File: {report['file']}")
    print(f"Records: {report['total_records']}")
    print("Type counts:")
    for k, v in sorted(report["type_counts"].items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {k}: {v}")
    print(f"Valid: {report['valid']}")

    if not report["valid"]:
        print(f"Issues: {len(report['issues'])}")
        # Print first N issues for convenience
        N = 25
        for i, issue in enumerate(report["issues"][:N], start=1):
            loc = f"line {issue['line']}"
            path = f" path={issue['path']}" if issue["path"] else ""
            print(f"  {i}. {loc}{path}: {issue['kind']}: {issue['message']}")
        if len(report["issues"]) > N:
            print(f"  ... ({len(report['issues']) - N} more)")
    else:
        print("No issues found.")

    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"Wrote report: {args.report}")

    return 0 if report["valid"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
