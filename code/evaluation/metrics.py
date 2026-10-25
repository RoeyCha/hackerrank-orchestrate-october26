"""Score predicted rows against a known step list."""

from __future__ import annotations

import json
from collections import Counter


def core(step: dict) -> tuple:
    return (
        step["phase"],
        step["operation"],
        step["system_id"],
        step["resource_id"],
        step["state"],
        step["evidence_id"],
    )


def score_cases(expected_rows: dict[str, dict[str, str]], predicted: list[dict[str, str]]) -> dict:
    status_hits = 0
    exact = 0
    sequence_hits = 0
    expected_steps = 0
    actual_steps = 0
    step_hits = 0
    field_hits = 0
    field_total = 0
    failures = []
    for row in predicted:
        case_id = row["case_id"]
        expected = json.loads(expected_rows[case_id]["steps_json"])
        actual = json.loads(row["steps_json"])
        expected_status = expected_rows[case_id]["deletion_status"]
        status_hits += row["deletion_status"] == expected_status
        expected_core = [core(step) for step in expected]
        actual_core = [core(step) for step in actual]
        sequence_hits += expected_core == actual_core
        if row["deletion_status"] == expected_status and expected_core == actual_core:
            exact += 1
        expected_steps += len(expected_core)
        actual_steps += len(actual_core)
        step_hits += sum((Counter(expected_core) & Counter(actual_core)).values())
        paired: set[int] = set()
        for step in expected:
            field_total += 6
            key = (step["phase"], step["operation"], step["system_id"], step["resource_id"])
            match = next(
                (
                    item for item in actual
                    if (item["phase"], item["operation"], item["system_id"], item["resource_id"]) == key
                    and id(item) not in paired
                ),
                None,
            )
            if match is None:
                continue
            paired.add(id(match))
            field_hits += 4
            field_hits += match["state"] == step["state"]
            field_hits += match["evidence_id"] == step["evidence_id"]
        if expected_core != actual_core or row["deletion_status"] != expected_status:
            expected_keys = {(step["system_id"], step["resource_id"]) for step in expected}
            actual_keys = {(step["system_id"], step["resource_id"]) for step in actual}
            failures.append(
                f"{case_id} status {expected_status}->{row['deletion_status']} "
                f"missing={sorted(expected_keys - actual_keys) or 'none'} "
                f"extra={sorted(actual_keys - expected_keys) or 'none'}"
            )
    total = len(predicted)
    return {
        "cases": total,
        "deletion_status": status_hits,
        "case_exact": exact,
        "sequence": sequence_hits,
        "step_hits": step_hits,
        "expected_steps": expected_steps,
        "actual_steps": actual_steps,
        "field_hits": field_hits,
        "field_total": field_total,
        "failures": failures,
    }
