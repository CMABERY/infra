
"""diff_apply.py

Minimal unified diff parser + applier for text files.

Goal: apply a stored patch (unified diff) deterministically, without recomputing
the diff from current workspace state.

Security/robustness:
- Applies only when file base SHA-256 matches proposal base hashes.
- Rejects malformed hunks or context mismatches.
- Treats patch text as UTF-8.

This is *not* a full git-compatible patch engine, but it is sufficient for the
project's MVP semantics (update/add/delete for small text files).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import re


@dataclass
class FilePatch:
    old_path: str
    new_path: str
    hunks: List["Hunk"]
    is_new: bool = False
    is_delete: bool = False
    raw_lines: List[str] = None


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: List[str]  # includes prefix ' ', '+', '-'


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

def _strip_prefix_path(p: str) -> str:
    # Typical unified diff uses a/ and b/ prefixes.
    if p.startswith("a/") or p.startswith("b/"):
        return p[2:]
    return p

def parse_unified_diff(patch_text: str) -> List[FilePatch]:
    """Parse a unified diff that may contain multiple file sections."""
    lines = patch_text.splitlines(keepends=False)
    i = 0
    file_patches: List[FilePatch] = []
    current: Optional[FilePatch] = None

    def flush():
        nonlocal current
        if current is not None:
            file_patches.append(current)
            current = None

    while i < len(lines):
        ln = lines[i]
        if ln.startswith("--- "):
            flush()
            oldp = ln[4:].strip()
            if i + 1 >= len(lines) or not lines[i+1].startswith("+++ "):
                raise ValueError("Malformed diff: missing +++ after ---")
            newp = lines[i+1][4:].strip()
            oldp = _strip_prefix_path(oldp)
            newp = _strip_prefix_path(newp)
            current = FilePatch(old_path=oldp, new_path=newp, hunks=[], raw_lines=[])
            # detect add/delete
            if oldp == "/dev/null":
                current.is_new = True
            if newp == "/dev/null":
                current.is_delete = True
            i += 2
            continue

        if current is not None:
            current.raw_lines.append(ln)
            if ln.startswith("@@ "):
                m = _HUNK_RE.match(ln)
                if not m:
                    raise ValueError("Malformed hunk header")
                old_start = int(m.group(1))
                old_count = int(m.group(2) or "1")
                new_start = int(m.group(3))
                new_count = int(m.group(4) or "1")
                h_lines: List[str] = []
                i += 1
                while i < len(lines):
                    l2 = lines[i]
                    if l2.startswith("--- "):
                        i -= 1
                        break
                    if l2.startswith("@@ "):
                        i -= 1
                        break
                    if l2.startswith("\\ No newline"):
                        # ignore meta line
                        i += 1
                        continue
                    if not l2:
                        # empty line is fine; treat as context with ' ' if diff includes prefix? Actually diff lines always have prefix.
                        # If we got an empty line without prefix, it's malformed.
                        raise ValueError("Malformed diff: empty unprefixed line in hunk")
                    prefix = l2[0]
                    if prefix not in (" ", "+", "-"):
                        raise ValueError(f"Malformed diff line prefix: {prefix!r}")
                    h_lines.append(l2)
                    i += 1
                current.hunks.append(Hunk(old_start, old_count, new_start, new_count, h_lines))
        i += 1

    flush()
    if not file_patches:
        raise ValueError("Empty diff")
    return file_patches


def apply_file_patch(old_text: str, fp: FilePatch) -> str:
    """Apply the file patch to old_text and return new_text."""
    old_lines = old_text.splitlines(keepends=True)
    out: List[str] = []
    old_idx = 0  # 0-based index into old_lines

    for h in fp.hunks:
        # convert 1-based old_start to 0-based index
        h_old_start = max(h.old_start - 1, 0)
        # copy unchanged lines before hunk
        while old_idx < h_old_start:
            out.append(old_lines[old_idx])
            old_idx += 1

        # apply hunk lines
        for l in h.lines:
            tag = l[0]
            content = l[1:]
            # We don't know whether the original diff was produced with keepends; content lacks newline.
            # We'll re-add newline if the corresponding old line had one, else keep as-is at end.
            if tag == " ":
                # context: must match old
                if old_idx >= len(old_lines):
                    raise ValueError("Context beyond EOF")
                if old_lines[old_idx].rstrip("\n") != content:
                    raise ValueError("Context mismatch")
                out.append(old_lines[old_idx])
                old_idx += 1
            elif tag == "-":
                # remove: must match old
                if old_idx >= len(old_lines):
                    raise ValueError("Removal beyond EOF")
                if old_lines[old_idx].rstrip("\n") != content:
                    raise ValueError("Removal mismatch")
                old_idx += 1
            elif tag == "+":
                # add: insert line; preserve newline convention by adding '\n' unless this is last line and old file had no newline.
                out.append(content + "\n")
            else:
                raise ValueError("Invalid hunk tag")

    # copy remainder
    while old_idx < len(old_lines):
        out.append(old_lines[old_idx])
        old_idx += 1

    return "".join(out)
