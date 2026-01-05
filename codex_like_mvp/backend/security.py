"""security.py — sandbox and policy enforcement for codex_like_mvp

Implements Checkpoint 7 (Sandbox & Approval Hardening):
- sandbox modes: read-only, workspace-write, full/danger
- path guards: traversal/absolute path checks + sensitive root blocks
- command policy: allowlist/denylist + offline network policy

This is an *application-level* policy layer. It is not an OS sandbox.
Treat "full/danger" as truly dangerous.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import List, Optional, Sequence


class SecurityError(Exception):
    """Base class for security enforcement errors."""


class DangerNotEnabled(SecurityError):
    pass


class SandboxViolation(SecurityError):
    pass


class CommandDenied(SecurityError):
    pass


_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def _real(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))


def _is_within(child: str, parent: str) -> bool:
    """Return True if child is within parent directory (or equals parent). Both real paths."""
    parent = parent.rstrip(os.sep)
    child = child.rstrip(os.sep)
    return child == parent or child.startswith(parent + os.sep)


def is_absolute_like(path: str) -> bool:
    """Cross-platform absolute-ish path detection, including Windows drive paths."""
    if not path:
        return False
    if path.startswith("\\\\"):
        return True
    if _DRIVE_RE.match(path):
        return True
    return os.path.isabs(path)


def sanitize_rel_path(rel_path: str) -> str:
    """Normalize and validate a relative path. Raises SandboxViolation if unsafe."""
    if rel_path is None:
        raise SandboxViolation("Missing path")
    p = rel_path.replace("\\", "/").strip()

    if "\x00" in p:
        raise SandboxViolation("NUL byte in path")
    while p.startswith("./"):
        p = p[2:]

    if is_absolute_like(p) or p.startswith("/"):
        raise SandboxViolation(f"Absolute paths are not allowed here: {rel_path!r}")

    pp = PurePosixPath(p)
    if pp.is_absolute():
        raise SandboxViolation(f"Absolute paths are not allowed here: {rel_path!r}")
    if any(part == ".." for part in pp.parts):
        raise SandboxViolation(f"Path traversal is not allowed: {rel_path!r}")
    if any(part == "" for part in pp.parts):
        raise SandboxViolation(f"Invalid empty path segment: {rel_path!r}")
    if _DRIVE_RE.match(p):
        raise SandboxViolation(f"Windows drive paths are not allowed here: {rel_path!r}")

    return str(pp)


def default_sensitive_roots() -> List[str]:
    """Sensitive roots to block unless explicitly overridden."""
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".ssh"),
        os.path.join(home, ".aws"),
        os.path.join(home, ".gnupg"),
        os.path.join(home, ".kube"),
        os.path.join(home, ".config", "gcloud"),
        os.path.join(home, ".config", "gh"),
        os.path.join(home, ".docker"),
        os.path.join(home, ".pypirc"),
        os.path.join(home, ".npmrc"),
    ]
    roots: List[str] = []
    for c in candidates:
        try:
            r = _real(c)
        except Exception:
            continue
        if r not in roots:
            roots.append(r)
    return roots


@dataclass(frozen=True)
class SandboxPolicy:
    type: str  # "read-only" | "workspace-write" | "full/danger"
    writable_roots: List[str]
    network_access: bool = False


@dataclass(frozen=True)
class SecurityConfig:
    danger_enabled: bool = False
    allow_sensitive_roots: bool = False
    allow_denylisted_commands: bool = False


@dataclass(frozen=True)
class CommandDecision:
    action: str  # "allow" | "require_approval" | "deny"
    reason: str
    allowlisted: bool = False
    denylisted: bool = False
    network_related: bool = False


class SecurityEnforcer:
    def __init__(
        self,
        *,
        sandbox: SandboxPolicy,
        workspace_roots: List[str],
        config: SecurityConfig,
        sensitive_roots: Optional[List[str]] = None,
    ) -> None:
        self.sandbox = sandbox
        self.workspace_roots = [_real(r) for r in workspace_roots]
        self.config = config
        self.sensitive_roots = sensitive_roots or default_sensitive_roots()

        if self.sandbox.type == "full/danger" and not self.config.danger_enabled:
            raise DangerNotEnabled("Sandbox 'full/danger' requested but server is not started with --danger.")

    # -----------------------------
    # Filesystem guards
    # -----------------------------

    def resolve_path(self, workspace_root: str, target_path: str) -> str:
        """Resolve target_path to an absolute real path, enforcing sandbox rules."""
        wr = _real(workspace_root)

        if self.sandbox.type in ("read-only", "workspace-write"):
            rel = sanitize_rel_path(target_path)
            abs_path = _real(os.path.join(wr, rel))
            if not _is_within(abs_path, wr):
                raise SandboxViolation(f"Refusing path outside workspaceRoot: {abs_path}")
        else:
            # full/danger: allow absolute, otherwise treat as relative to workspace_root
            if is_absolute_like(target_path):
                abs_path = _real(target_path)
            else:
                rel = sanitize_rel_path(target_path)
                abs_path = _real(os.path.join(wr, rel))

        if not self.config.allow_sensitive_roots:
            for sroot in self.sensitive_roots:
                if _is_within(abs_path, sroot):
                    raise SandboxViolation(
                        f"Refusing access to sensitive root {sroot!r}. "
                        f"Start server with --allow-sensitive-roots to override."
                    )

        return abs_path

    def assert_can_write(self, abs_path: str) -> None:
        if self.sandbox.type == "read-only":
            raise SandboxViolation("Sandbox is read-only: writes are disabled.")
        if self.sandbox.type == "workspace-write":
            roots = self.sandbox.writable_roots or self.workspace_roots
            roots_real = [_real(r) for r in roots]
            if not any(_is_within(abs_path, rr) for rr in roots_real):
                raise SandboxViolation(f"Refusing write outside writable roots: {abs_path}")

    # -----------------------------
    # Command policy
    # -----------------------------

    def decide_command(self, argv: Sequence[str]) -> CommandDecision:
        """Decide whether a command can be executed under current policy."""
        if self.sandbox.type == "read-only":
            return CommandDecision(action="deny", reason="read-only sandbox")

        if not argv:
            return CommandDecision(action="deny", reason="empty argv")

        exe = os.path.basename(argv[0]).lower()

        denylisted = exe in {
            "curl", "wget", "ssh", "scp", "sftp",
            "nc", "ncat", "netcat", "telnet",
            "powershell", "pwsh", "cmd.exe", "cmd",
            "bash", "sh", "zsh", "fish",
        }

        # Block deletion primitives by default (you can still remove files via patch apply)
        denylisted = denylisted or (exe in {"rm", "rmdir", "del", "erase"})

        network_related = exe in {"curl", "wget", "ssh", "scp", "sftp", "nc", "ncat", "netcat", "telnet"}
        if any(_URL_RE.match(a) for a in argv[1:]):
            network_related = True
        if exe == "git" and len(argv) >= 2:
            sub = argv[1].lower()
            if sub in {"clone", "fetch", "pull", "push", "submodule", "ls-remote"}:
                network_related = True

        if denylisted and not self.config.allow_denylisted_commands:
            return CommandDecision(action="deny", reason=f"denylisted command: {exe}", denylisted=True, network_related=network_related)

        if (not self.sandbox.network_access) and network_related:
            return CommandDecision(action="deny", reason="offline mode: network-related command", denylisted=denylisted, network_related=True)

        allowlisted = self._is_allowlisted(argv, exe)
        if allowlisted:
            return CommandDecision(action="allow", reason="allowlisted", allowlisted=True, denylisted=denylisted, network_related=network_related)

        return CommandDecision(action="require_approval", reason="not allowlisted", denylisted=denylisted, network_related=network_related)

    def _is_allowlisted(self, argv: Sequence[str], exe: str) -> bool:
        if exe in {"ls", "dir"}:
            return True

        if exe == "git" and len(argv) >= 2:
            sub = argv[1].lower()
            return sub in {"status", "diff", "log", "rev-parse", "branch", "show", "grep"}

        if exe in {"cat", "type"} and len(argv) == 2:
            try:
                sanitize_rel_path(argv[1])
                return True
            except SandboxViolation:
                return False

        # Allow only the specific safe python listdir command:
        # python -c "import os; print('\n'.join(sorted(os.listdir('.'))))"
        if exe.startswith("python") or exe in {"python.exe", "python3", "python3.exe"}:
            if len(argv) >= 3 and argv[1] == "-c":
                code = argv[2].strip()
                safe = "import os; print('\\n'.join(sorted(os.listdir('.'))))"
                return code == safe

        return False
