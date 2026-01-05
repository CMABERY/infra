"""merge3.py

Checkpoint 12: 3-way merge with conflict markers.

Goal:
  When the workspace has changed since a proposal (base hash mismatch),
  we attempt a *3-way merge* using:
    - BASE: snapshot captured at proposal time
    - WORKSPACE: current file content at apply time
    - PATCH: the proposed target content (BASE + stored diff)

If both WORKSPACE and PATCH changed the same region of BASE differently,
we emit conflict markers:

<<<<<<< WORKSPACE
...workspace version...
=======
...patch version...
>>>>>>> PATCH

Notes:
- This is a pragmatic, line-based diff3-style merge using difflib.SequenceMatcher.
- It favors safety and transparency over perfectly reproducing git's behavior.
- It never reads outside the workspace roots; the BASE snapshot is loaded from
  the transaction's internal blob store.

This module has no external dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import List, Tuple


@dataclass(frozen=True)
class Mod:
    start: int  # base index
    end: int    # base index (exclusive)
    lines: List[str]  # replacement/insert lines (with newlines preserved)


def _compute_mods(base: List[str], other: List[str]) -> List[Mod]:
    """Return non-equal modifications that transform base -> other."""
    sm = SequenceMatcher(a=base, b=other)
    mods: List[Mod] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        # insert is i1==i2
        mods.append(Mod(start=i1, end=i2, lines=other[j1:j2]))
    return mods


def _ensure_nl(s: str) -> str:
    return s if s.endswith("\n") else (s + "\n")


def _conflict_block(a_lines: List[str], b_lines: List[str], label_a: str, label_b: str) -> List[str]:
    out: List[str] = []
    out.append(_ensure_nl(f"<<<<<<< {label_a}"))
    out.extend(a_lines)
    if out and not out[-1].endswith("\n"):
        out[-1] = out[-1] + "\n"
    out.append(_ensure_nl("======="))
    out.extend(b_lines)
    if out and not out[-1].endswith("\n"):
        out[-1] = out[-1] + "\n"
    out.append(_ensure_nl(f">>>>>>> {label_b}"))
    return out


def _render_side(base: List[str], start: int, end: int, mods: List[Mod]) -> List[str]:
    """Render a side's version for base[start:end] applying mods within that window."""
    out: List[str] = []
    pos = start
    for m in mods:
        if m.start >= end:
            break
        if m.start < start:
            continue
        # unchanged chunk
        if m.start > pos:
            out.extend(base[pos:m.start])
            pos = m.start
        # apply mod
        if m.start == m.end:
            # insert (pos does not advance)
            out.extend(m.lines)
        else:
            out.extend(m.lines)
            pos = m.end
    if pos < end:
        out.extend(base[pos:end])
    return out


def merge3_text(
    base_text: str,
    workspace_text: str,
    patch_text: str,
    *,
    label_workspace: str = "WORKSPACE",
    label_patch: str = "PATCH",
) -> Tuple[str, bool]:
    """3-way merge. Returns (merged_text, had_conflicts)."""
    base = base_text.splitlines(keepends=True)
    ws = workspace_text.splitlines(keepends=True)
    pt = patch_text.splitlines(keepends=True)

    mods_ws = _compute_mods(base, ws)
    mods_pt = _compute_mods(base, pt)

    i_ws = 0
    i_pt = 0
    pos = 0
    out: List[str] = []
    conflicts = False

    def next_start() -> int:
        s1 = mods_ws[i_ws].start if i_ws < len(mods_ws) else len(base)
        s2 = mods_pt[i_pt].start if i_pt < len(mods_pt) else len(base)
        return min(s1, s2)

    while True:
        ns = next_start()
        if ns > pos:
            out.extend(base[pos:ns])
            pos = ns

        if pos >= len(base) and i_ws >= len(mods_ws) and i_pt >= len(mods_pt):
            break

        # collect insertions at pos
        ins_ws: List[str] = []
        while i_ws < len(mods_ws) and mods_ws[i_ws].start == pos and mods_ws[i_ws].start == mods_ws[i_ws].end:
            ins_ws.extend(mods_ws[i_ws].lines)
            i_ws += 1
        ins_pt: List[str] = []
        while i_pt < len(mods_pt) and mods_pt[i_pt].start == pos and mods_pt[i_pt].start == mods_pt[i_pt].end:
            ins_pt.extend(mods_pt[i_pt].lines)
            i_pt += 1

        if ins_ws or ins_pt:
            if ins_ws and ins_pt:
                if ins_ws == ins_pt:
                    out.extend(ins_ws)
                else:
                    conflicts = True
                    out.extend(_conflict_block(ins_ws, ins_pt, label_workspace, label_patch))
            else:
                out.extend(ins_ws or ins_pt)

        # replacement mods starting at pos (end>start)
        rep_ws = i_ws < len(mods_ws) and mods_ws[i_ws].start == pos and mods_ws[i_ws].end > mods_ws[i_ws].start
        rep_pt = i_pt < len(mods_pt) and mods_pt[i_pt].start == pos and mods_pt[i_pt].end > mods_pt[i_pt].start

        if not rep_ws and not rep_pt:
            # no replacement at this position; proceed to next boundary
            if pos >= len(base):
                break
            # ensure progress: if next_start() == pos and no mods at pos, advance by one base line
            if next_start() == pos:
                out.append(base[pos])
                pos += 1
            continue

        if rep_ws and not rep_pt:
            m = mods_ws[i_ws]
            out.extend(m.lines)
            pos = m.end
            i_ws += 1
            continue

        if rep_pt and not rep_ws:
            m = mods_pt[i_pt]
            out.extend(m.lines)
            pos = m.end
            i_pt += 1
            continue

        # both sides replace overlapping base region: create a conflict union block
        conflict_start = pos
        conflict_end = max(mods_ws[i_ws].end, mods_pt[i_pt].end)
        # Expand to include any mods that start before conflict_end.
        prev_end = -1
        while prev_end != conflict_end:
            prev_end = conflict_end
            j = i_ws
            while j < len(mods_ws) and mods_ws[j].start < conflict_end:
                if mods_ws[j].end > conflict_end:
                    conflict_end = mods_ws[j].end
                j += 1
            j = i_pt
            while j < len(mods_pt) and mods_pt[j].start < conflict_end:
                if mods_pt[j].end > conflict_end:
                    conflict_end = mods_pt[j].end
                j += 1

        ws_block = [m for m in mods_ws[i_ws:] if m.start < conflict_end]
        pt_block = [m for m in mods_pt[i_pt:] if m.start < conflict_end]

        ws_version = _render_side(base, conflict_start, conflict_end, ws_block)
        pt_version = _render_side(base, conflict_start, conflict_end, pt_block)

        if ws_version == pt_version:
            out.extend(ws_version)
        else:
            conflicts = True
            out.extend(_conflict_block(ws_version, pt_version, label_workspace, label_patch))

        # consume mods inside block
        while i_ws < len(mods_ws) and mods_ws[i_ws].start < conflict_end:
            i_ws += 1
        while i_pt < len(mods_pt) and mods_pt[i_pt].start < conflict_end:
            i_pt += 1
        pos = conflict_end

    return "".join(out), conflicts
