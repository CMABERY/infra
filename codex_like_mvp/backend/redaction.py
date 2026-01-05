"""redaction.py — Secret redaction & guardrails (Checkpoint 8)

This module provides two related capabilities:

1) Redaction: remove or mask high-risk secrets from any text before it is
   emitted to the UI or persisted to the transaction ledger.

2) Guardrails: detect *introductions* of secrets in proposed patches.

Design goals:
- Safe-by-default: logs and UI events must not leak secrets.
- Dependency-light: standard library only.
- Deterministic: no probabilistic classifiers.

Important: This is an application-level filter. It is not perfect. Treat it as
an additional layer, not your only layer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple


# -----------------------------
# Findings model
# -----------------------------


@dataclass(frozen=True)
class SecretFinding:
    kind: str
    line: int


# -----------------------------
# High-confidence patterns
# -----------------------------


# NOTE: Keep patterns conservative to avoid false positives.
_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    # Private key blocks (PEM / OpenSSH)
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:OPENSSH|RSA|DSA|EC|PGP|PRIVATE) KEY-----.*?-----END (?:OPENSSH|RSA|DSA|EC|PGP|PRIVATE) KEY-----",
            re.DOTALL,
        ),
    ),
    # OpenAI-style keys
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    # GitHub personal access tokens (classic + fine-grained)
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("github_finegrained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    # AWS access key IDs
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    # Google API key
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    # Slack tokens
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    # JWTs (very common bearer format)
    ("jwt", re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b")),
]

# Generic bearer token (moderate confidence). We only redact if token looks long.
_BEARER_RE = re.compile(r"\bBearer\s+([A-Za-z0-9_\-\.=]{20,})\b")

# Common "key=value" patterns (low confidence) — only used for *detection* on added lines.
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*([^\s'\"]{12,})"
)


def _token_looks_secret(value: str) -> bool:
    """Heuristic gate for low-confidence tokens."""
    v = value.strip()
    if len(v) < 20:
        return False
    # Must contain at least two character classes.
    classes = 0
    classes += any(c.islower() for c in v)
    classes += any(c.isupper() for c in v)
    classes += any(c.isdigit() for c in v)
    classes += any(not c.isalnum() for c in v)
    return classes >= 2


# -----------------------------
# Redaction
# -----------------------------


def redact_text(text: str) -> Tuple[str, List[str]]:
    """Return (redacted_text, kinds). Does not include secret values."""
    if not text:
        return text, []
    redacted = text
    kinds: List[str] = []

    for kind, pat in _PATTERNS:
        if pat.search(redacted):
            redacted = pat.sub(f"<REDACTED:{kind}>", redacted)
            kinds.append(kind)

    # Bearer token: redact token group, keep prefix.
    def _bearer_sub(m: re.Match[str]) -> str:
        kinds.append("bearer_token")
        return "Bearer <REDACTED:bearer_token>"

    if _BEARER_RE.search(redacted):
        redacted = _BEARER_RE.sub(_bearer_sub, redacted)

    return redacted, sorted(set(kinds))


def redact_obj(obj: Any) -> Tuple[Any, List[str]]:
    """Recursively redact secrets in a JSON-serializable object."""
    kinds: List[str] = []
    if obj is None:
        return obj, []
    if isinstance(obj, str):
        s, k = redact_text(obj)
        return s, k
    if isinstance(obj, (int, float, bool)):
        return obj, []
    if isinstance(obj, list):
        out = []
        for it in obj:
            v, k = redact_obj(it)
            out.append(v)
            kinds.extend(k)
        return out, sorted(set(kinds))
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k0, v0 in obj.items():
            v, k = redact_obj(v0)
            out[k0] = v
            kinds.extend(k)
        return out, sorted(set(kinds))
    # Fallback: stringify unknowns
    s, k = redact_text(str(obj))
    return s, k


def redact_event(event: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Redact an event (returns a new dict)."""
    safe, kinds = redact_obj(event)
    assert isinstance(safe, dict)
    if kinds:
        safe.setdefault("payload", {})
        if isinstance(safe["payload"], dict):
            safe["payload"].setdefault("_redaction", {})
            safe["payload"]["_redaction"] = {
                "redacted": True,
                "kinds": kinds,
            }
    return safe, kinds


# -----------------------------
# Guardrails: detect secret introductions in diffs
# -----------------------------


def _iter_added_lines(unified_diff: str) -> Iterable[Tuple[int, str]]:
    """Yield (line_number_1_based, line_content) for added lines in a unified diff."""
    for i, ln in enumerate(unified_diff.splitlines(), start=1):
        if ln.startswith("+++") or ln.startswith("@@") or ln.startswith("diff "):
            continue
        if ln.startswith("+"):
            yield i, ln[1:]


def detect_secret_introductions_in_diff(unified_diff: str) -> List[SecretFinding]:
    """Return findings for secrets found in *added* lines only."""
    findings: List[SecretFinding] = []
    if not unified_diff:
        return findings

    for line_no, content in _iter_added_lines(unified_diff):
        # High-confidence patterns
        for kind, pat in _PATTERNS:
            if pat.search(content):
                findings.append(SecretFinding(kind=kind, line=line_no))

        # Bearer tokens
        m = _BEARER_RE.search(content)
        if m and _token_looks_secret(m.group(1)):
            findings.append(SecretFinding(kind="bearer_token", line=line_no))

        # Low-confidence assignments
        m2 = _ASSIGNMENT_RE.search(content)
        if m2 and _token_looks_secret(m2.group(2)):
            findings.append(SecretFinding(kind=f"assignment:{m2.group(1).lower()}", line=line_no))

    # Deduplicate
    uniq = {(f.kind, f.line): f for f in findings}
    return list(uniq.values())
