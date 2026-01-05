"""Minimal self-test for Checkpoint 8 secret redaction.

Run:
  python tools/test_redaction.py
"""

from __future__ import annotations

from codex_like_mvp.backend.redaction import redact_text


def main() -> None:
    samples = {
        "openai_key": "api_key=sk-1234567890abcdefghijklmnopqrstuv",
        "github_pat": "token ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
        "slack": "xoxb-123456789012-abcdefghijklmnopqrstuv",
        "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "bearer": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789.ABCD",
        "pem": "-----BEGIN RSA KEY-----\nMIIBOgIBAAJBAK\n-----END RSA KEY-----",
    }

    for name, s in samples.items():
        red, kinds = redact_text(s)
        assert "REDACTED" in red, f"expected redaction for {name}"
        assert kinds, f"expected kinds for {name}"
        # Ensure original secret-ish fragment isn't preserved verbatim.
        if name == "openai_key":
            assert "sk-" not in red
        if name == "github_pat":
            assert "ghp_" not in red
        if name == "slack":
            assert "xox" not in red

    print("OK: redaction patterns")


if __name__ == "__main__":
    main()
