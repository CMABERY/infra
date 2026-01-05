"""Self-test for Checkpoint 8 secret introduction detection.

Run:
  python tools/test_secret_guardrails.py
"""

from __future__ import annotations

from codex_like_mvp.backend.redaction import detect_secret_introductions_in_diff


def main() -> None:
    # Secret in context line (leading space) should NOT count as an introduction.
    diff_context = """--- a/file.txt
+++ b/file.txt
@@
-foo
+bar
 const OPENAI_KEY = \"sk-1234567890abcdefghijklmnopqrstuv\"\n"""
    f1 = detect_secret_introductions_in_diff(diff_context)
    assert not f1, f"expected no findings, got {f1}"

    # Secret in added line should be detected.
    diff_added = """--- a/file.txt
+++ b/file.txt
@@
 foo
+const OPENAI_KEY = \"sk-1234567890abcdefghijklmnopqrstuv\"\n"""
    f2 = detect_secret_introductions_in_diff(diff_added)
    assert f2, "expected findings for secret introduced in added line"

    kinds = sorted({x.kind for x in f2})
    assert "openai_key" in kinds, f"expected openai_key kind, got {kinds}"

    print("OK: secret introduction detection")


if __name__ == "__main__":
    main()
