"""Audit every evaluation request and write output.csv at the repository root."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from code.audit import main

if __name__ == "__main__":
    main()
