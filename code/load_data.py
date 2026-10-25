"""Dataset paths and CSV loading. Paths are relative to the repository root."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUTPUT_PATH = ROOT / "output.csv"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_csv(name: str) -> list[dict[str, str]]:
    with (DATASET / name).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def case_number(case_id: str) -> int:
    return int(case_id.split("_")[1])
