#!/usr/bin/env python3
"""Backward-compatible launcher for the original Phase 0 command.

New usage should prefer ``python -m csaf_analytics`` or the installed
``csaf-analytics`` command. This wrapper can be removed after downstream
automation has migrated to the package entry point.
"""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from csaf_analytics.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
