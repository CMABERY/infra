"""agent.py — deterministic demo agent logic

This project intentionally avoids calling an external LLM. The goal is to
exercise the *runtime contracts* (turn items, approvals, apply, ledger), not
model quality.

Checkpoint 10 adds multi-file patchsets:
- propose a patchset that updates multiple files in one transaction

Security note:
- File I/O should remain owned by the server (mvp_server.py) so sandbox rules
  are enforced centrally.
"""

from __future__ import annotations

import difflib
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Sequence


@dataclass
class ProposedChange:
    rel_path: str
    old_text: str
    new_text: str
    unified_diff: str


@dataclass
class ProposedPatchset:
    changes: List[ProposedChange]
    unified_diff: str

    @property
    def rel_paths(self) -> List[str]:
        return [c.rel_path for c in self.changes]


def remove_lines_containing(text: str, needle: str) -> str:
    old_lines = text.splitlines(keepends=True)
    new_lines = [ln for ln in old_lines if needle not in ln]
    return "".join(new_lines)


def propose_change_remove_todo_text(rel_path: str, old_text: str, needle: str = "TODO") -> ProposedChange:
    """Pure function: compute a TODO-removal patch from input text."""
    new_text = remove_lines_containing(old_text, needle=needle)

    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)

    fromfile = f"a/{rel_path}"
    tofile = f"b/{rel_path}"
    diff_lines = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=fromfile,
            tofile=tofile,
            lineterm="\n",
        )
    )
    unified_diff = "".join(diff_lines)

    return ProposedChange(rel_path=rel_path, old_text=old_text, new_text=new_text, unified_diff=unified_diff)


def propose_patchset_remove_todo_text(files: Dict[str, str], needle: str = "TODO") -> ProposedPatchset:
    """Pure function: propose a multi-file patchset.

    Only files that actually change are included.
    """
    changes: List[ProposedChange] = []
    diffs: List[str] = []

    for rel_path in sorted(files.keys()):
        old_text = files[rel_path]
        pc = propose_change_remove_todo_text(rel_path=rel_path, old_text=old_text, needle=needle)
        if pc.new_text != pc.old_text:
            changes.append(pc)
            diffs.append(pc.unified_diff)

    return ProposedPatchset(changes=changes, unified_diff="".join(diffs))


def safe_listdir_command() -> List[str]:
    """A safe, cross-platform command executed via Python itself."""
    return [sys.executable, "-c", "import os; print('\\n'.join(sorted(os.listdir('.'))))"]


def classify_command(argv: Sequence[str]) -> str:
    """Very small classification helper for UI display."""
    if not argv:
        return "unknown"
    exe = os.path.basename(argv[0]).lower()
    if exe in {"ls", "dir"}:
        return "list_files"
    if exe == "git" and len(argv) >= 2:
        return f"git_{argv[1].lower()}"
    if exe in {"cat", "type"}:
        return "read_file"
    if exe.startswith("python"):
        return "python"
    return "unknown"
