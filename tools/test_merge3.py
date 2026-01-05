"""test_merge3.py

Checkpoint 12: basic tests for 3-way merge with conflict markers.

Run:
  python -m tools.test_merge3
"""

from codex_like_mvp.backend.merge3 import merge3_text


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def test_no_conflict_when_only_patch_changes() -> None:
    base = "a\nkeep\n"
    ws = base
    pt = "a\nkeep\nPATCH\n"
    merged, conflicts = merge3_text(base, ws, pt)
    _assert(not conflicts, "expected no conflicts")
    _assert(merged == pt, "expected patch version")


def test_no_conflict_when_only_workspace_changes() -> None:
    base = "a\nkeep\n"
    ws = "a\nkeep\nWS\n"
    pt = base
    merged, conflicts = merge3_text(base, ws, pt)
    _assert(not conflicts, "expected no conflicts")
    _assert(merged == ws, "expected workspace version")


def test_conflict_when_both_change_differently() -> None:
    base = "a\nkeep\n"
    ws = "a\nkeep\nWS\n"
    pt = "a\nkeep\nPATCH\n"
    merged, conflicts = merge3_text(base, ws, pt)
    _assert(conflicts, "expected conflicts")
    _assert("<<<<<<< WORKSPACE" in merged, "missing conflict marker")
    _assert("=======" in merged, "missing separator")
    _assert(">>>>>>> PATCH" in merged, "missing end marker")
    _assert("WS" in merged and "PATCH" in merged, "missing sides")


def main() -> None:
    test_no_conflict_when_only_patch_changes()
    test_no_conflict_when_only_workspace_changes()
    test_conflict_when_both_change_differently()
    print("OK")


if __name__ == "__main__":
    main()
