"""Inspect participant-facing dataset files and evidence layout.

Reads only files under dataset/. Prints column names, sample rows, the full
deletion policy, evidence extension counts, and canonical sample_output rows.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
EVIDENCE = DATASET / "evidence"

SAMPLE_FILES = [
    "deletion_requests.csv",
    "sample_deletion_requests.csv",
    "sample_output.csv",
    "deletion_rules.csv",
    "user_identities.csv",
    "user_audit_log.csv",
    "system_activity.csv",
    "evidence_files.csv",
]


def load_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise SystemExit(f"{path} has no header")
        rows = list(reader)
        return list(reader.fieldnames), rows


def print_section(title: str) -> None:
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def preview_rows(name: str, limit: int = 3) -> None:
    path = DATASET / name
    columns, rows = load_rows(path)
    print_section(f"{name}  ({len(rows)} data rows)")
    print("columns:", ", ".join(columns))
    for index, row in enumerate(rows[:limit], start=1):
        print(f"--- sample row {index} ---")
        for column in columns:
            value = row[column]
            if column == "steps_json" and value not in ("", "[]"):
                print(f"{column}: <{len(value)} chars; full value printed in canonical section>")
            else:
                print(f"{column}: {value}")


def print_deletion_rules() -> None:
    path = DATASET / "deletion_rules.csv"
    columns, rows = load_rows(path)
    print_section(f"deletion_rules.csv FULL CONTENT ({len(rows)} rules)")
    print("columns:", ", ".join(columns))
    for index, row in enumerate(rows, start=1):
        print(f"--- rule {index} ---")
        for column in columns:
            print(f"{column}: {row[column]}")


def print_evidence_breakdown() -> None:
    print_section("dataset/evidence/ file types")
    if not EVIDENCE.is_dir():
        raise SystemExit(f"missing evidence directory: {EVIDENCE}")

    by_ext: Counter[str] = Counter()
    by_dir_ext: Counter[tuple[str, str]] = Counter()
    total = 0
    for path in EVIDENCE.rglob("*"):
        if not path.is_file():
            continue
        total += 1
        ext = path.suffix.lower() or "(no extension)"
        relative_parent = path.parent.relative_to(EVIDENCE).as_posix()
        by_ext[ext] += 1
        by_dir_ext[(relative_parent, ext)] += 1

    print(f"total files: {total}")
    print("by extension:")
    for ext, count in sorted(by_ext.items(), key=lambda item: (-item[1], item[0])):
        print(f"  {ext}: {count}")
    print("by subdirectory and extension:")
    for (folder, ext), count in sorted(by_dir_ext.items()):
        print(f"  {folder}/{ext}: {count}")


def print_canonical_sample_output(limit: int = 3) -> None:
    path = DATASET / "sample_output.csv"
    columns, rows = load_rows(path)
    print_section(f"sample_output.csv canonical rows ({limit} of {len(rows)})")
    print("columns:", ", ".join(columns))
    statuses = Counter(row["deletion_status"] for row in rows)
    print("status counts:", dict(sorted(statuses.items())))

    # Prefer one of each status when present, then fill to `limit`.
    chosen: list[dict[str, str]] = []
    seen_status: set[str] = set()
    for row in rows:
        status = row["deletion_status"]
        if status not in seen_status:
            chosen.append(row)
            seen_status.add(status)
        if len(chosen) >= limit:
            break
    if len(chosen) < limit:
        chosen_ids = {row["case_id"] for row in chosen}
        for row in rows:
            if row["case_id"] in chosen_ids:
                continue
            chosen.append(row)
            if len(chosen) >= limit:
                break

    for index, row in enumerate(chosen, start=1):
        print(f"--- complete row {index} case_id={row['case_id']} status={row['deletion_status']} ---")
        raw = row["steps_json"]
        print("steps_json raw:")
        print(raw)
        parsed = json.loads(raw)
        print(f"parsed step count: {len(parsed)}")
        if parsed:
            print("parsed steps (indent=2):")
            print(json.dumps(parsed, indent=2, ensure_ascii=False))


def main() -> None:
    missing = [name for name in SAMPLE_FILES if not (DATASET / name).is_file()]
    if missing:
        raise SystemExit("missing dataset files: " + ", ".join(missing))

    for name in SAMPLE_FILES:
        preview_rows(name, limit=3)
    print_deletion_rules()
    print_evidence_breakdown()
    print_canonical_sample_output(limit=3)


if __name__ == "__main__":
    main()
