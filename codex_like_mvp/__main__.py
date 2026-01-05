"""
Entry point: `python -m codex_like_mvp [demo]`
"""
from __future__ import annotations

import sys
from .client.mvp_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
