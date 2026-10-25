"""Validate output.csv, step order, evidence citations, and the evaluation reports.

Run from the repository root:

    python scripts/final_check.py
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output.csv"
REQUESTS = ROOT / "dataset" / "deletion_requests.csv"
EVIDENCE_MANIFEST = ROOT / "dataset" / "evidence_files.csv"
REPORTS = [
    ROOT / "code" / "evaluation" / "evaluation_report.md",
    ROOT / "code" / "evaluation" / "usage_report.md",
    ROOT / "evaluation" / "evaluation_report.md",
    ROOT / "evaluation" / "usage_report.md",
]

STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]
OPERATIONS = {
    "FINDING": [
        "REPORT_REMAINING_RECORD",
        "REPORT_EXPOSED_PII",
        "REPORT_ACTIVE_DATA_FLOW",
        "REPORT_RESTORE_RISK",
    ],
    "REMEDIATION": [
        "DISABLE_DATA_FLOW",
        "BLOCK_RESTORE",
        "DELETE_RECORD",
        "REDACT_RECORD",
        "ANONYMIZE_RECORD",
    ],
    "VERIFICATION": [
        "VERIFY_RECORD_ABSENT",
        "VERIFY_RECORD_PRESENT",
        "VERIFY_RECORD_REDACTED",
        "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED",
        "VERIFY_RESTORE_BLOCKED",
    ],
}
STATES = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
STEP_FIELDS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def case_number(case_id: str) -> int:
    return int(case_id.split("_")[1])


class Checklist:
    def __init__(self) -> None:
        self.rows: list[tuple[bool, str]] = []

    def add(self, passed: bool, label: str) -> None:
        self.rows.append((passed, label))
        print(("PASS" if passed else "FAIL") + "  " + label)

    def ok(self) -> bool:
        return all(passed for passed, _label in self.rows)


def load_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        return fieldnames, list(reader)


def evidence_ids() -> set[str]:
    with EVIDENCE_MANIFEST.open(encoding="utf-8", newline="") as handle:
        return {row["file_id"] for row in csv.DictReader(handle)}


def check_output(checklist: Checklist) -> None:
    checklist.add(OUTPUT.is_file(), f"output.csv exists at {OUTPUT}")
    if not OUTPUT.is_file():
        return
    fieldnames, rows = load_rows(OUTPUT)
    checklist.add(fieldnames == ["case_id", "deletion_status", "steps_json"], "columns are case_id,deletion_status,steps_json")
    checklist.add(len(rows) == 518, f"exactly 518 data rows (found {len(rows)})")

    with REQUESTS.open(encoding="utf-8", newline="") as handle:
        expected_ids = [row["case_id"] for row in csv.DictReader(handle)]
    actual_ids = [row["case_id"] for row in rows]
    expected_order = sorted(expected_ids, key=case_number)
    checklist.add(actual_ids == expected_order, "rows contain every request case_id once, in ascending case_id order")
    checklist.add(len(actual_ids) == len(set(actual_ids)), "case_id values are unique")

    bad_status = [row["case_id"] for row in rows if row["deletion_status"] not in STATUSES]
    checklist.add(not bad_status, "deletion_status is COMPLETE, INCOMPLETE, or NOT_APPLICABLE" + (f" ({bad_status[:5]})" if bad_status else ""))

    bad_na = []
    for row in rows:
        if row["deletion_status"] != "NOT_APPLICABLE":
            continue
        try:
            parsed = json.loads(row["steps_json"])
        except json.JSONDecodeError:
            parsed = None
        if parsed != []:
            bad_na.append(row["case_id"])
    checklist.add(not bad_na, "NOT_APPLICABLE rows have an empty JSON array" + (f" ({bad_na[:5]})" if bad_na else ""))

    known_evidence = evidence_ids()
    problems: list[str] = []
    for row in rows:
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError:
            problems.append(f"{row['case_id']} invalid JSON")
            continue
        if not isinstance(steps, list):
            problems.append(f"{row['case_id']} steps_json is not an array")
            continue
        keys = []
        for index, step in enumerate(steps):
            if not isinstance(step, dict) or any(field not in step for field in STEP_FIELDS):
                problems.append(f"{row['case_id']} step {index + 1} missing fields")
                continue
            phase = step["phase"]
            operation = step["operation"]
            if phase not in OPERATIONS or operation not in OPERATIONS[phase]:
                problems.append(f"{row['case_id']} illegal {phase}/{operation}")
                continue
            if step["state"] != STATES[operation]:
                problems.append(f"{row['case_id']} {operation} state {step['state']}")
            keys.append((
                PHASES.index(phase),
                OPERATIONS[phase].index(operation),
                step["system_id"],
                step["resource_id"],
            ))
            evidence_id = step["evidence_id"]
            status = row["deletion_status"]
            if status == "COMPLETE" and (phase != "VERIFICATION" or evidence_id not in known_evidence):
                problems.append(f"{row['case_id']} complete step cites {evidence_id!r}")
            if phase == "FINDING" and evidence_id not in known_evidence:
                problems.append(f"{row['case_id']} finding cites {evidence_id!r}")
            if status == "INCOMPLETE" and phase in {"REMEDIATION", "VERIFICATION"} and evidence_id != "":
                problems.append(f"{row['case_id']} incomplete {phase} cites {evidence_id!r}")
        if [step.get("step_no") for step in steps] != list(range(1, len(steps) + 1)):
            problems.append(f"{row['case_id']} step_no is not 1..n")
        if keys != sorted(keys):
            problems.append(f"{row['case_id']} phase, operation, system_id, or resource_id order")
    checklist.add(not problems, "all 518 step arrays follow phase, operation, system, resource, step number, and evidence rules" + (f" ({problems[:3]})" if problems else ""))


def check_reports(checklist: Checklist) -> None:
    for path in REPORTS:
        checklist.add(path.is_file() and path.stat().st_size > 0, f"{path.relative_to(ROOT).as_posix()} exists and is non-empty")
    evaluation = (ROOT / "code" / "evaluation" / "evaluation_report.md").read_text(encoding="utf-8") if (ROOT / "code" / "evaluation" / "evaluation_report.md").is_file() else ""
    usage = (ROOT / "code" / "evaluation" / "usage_report.md").read_text(encoding="utf-8") if (ROOT / "code" / "evaluation" / "usage_report.md").is_file() else ""
    required_evaluation = ["deletion-status", "Step-level", "Field-level", "Sequence", "Custom cases", "Failures found"]
    missing = [phrase for phrase in required_evaluation if phrase not in evaluation]
    checklist.add(not missing, "evaluation report covers status, steps, fields, sequence, custom cases, and failures" + (f" missing {missing}" if missing else ""))
    required_usage = ["Model", "Input tokens", "Output tokens", "cost"]
    missing_usage = [phrase for phrase in required_usage if phrase.lower() not in usage.lower()]
    checklist.add(not missing_usage, "usage report covers model, tokens, and cost" + (f" missing {missing_usage}" if missing_usage else ""))


def check_evaluation_run(checklist: Checklist) -> None:
    completed = subprocess.run(
        [sys.executable, "code/evaluation/main.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    passed = completed.returncode == 0 and "status 32/32" in output
    detail = "python code/evaluation/main.py exits 0 and reports status 32/32"
    if not passed:
        tail = " ".join(output.split())[:240]
        detail += f" (exit {completed.returncode}; {tail})"
    checklist.add(passed, detail)


def main() -> None:
    checklist = Checklist()
    print("Final submission check")
    print("=" * 72)
    check_output(checklist)
    check_reports(checklist)
    check_evaluation_run(checklist)
    print("=" * 72)
    passed = sum(1 for ok, _label in checklist.rows if ok)
    print(f"{passed}/{len(checklist.rows)} checks passed")
    if not checklist.ok():
        print("RESULT: FAIL")
        sys.exit(1)
    print("RESULT: PASS")


if __name__ == "__main__":
    main()
