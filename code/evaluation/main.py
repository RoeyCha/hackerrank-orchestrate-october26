"""Score the 32 public samples, run the custom cases, and write both reports."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from code.audit import audit_requests
from code.evaluation.custom_cases import run_custom_cases
from code.evaluation.metrics import score_cases
from code.linking import load_world
from code.load_data import load_csv

REPORT_DIR = Path(__file__).resolve().parent
ROOT_EVAL = ROOT / "evaluation"


def _percent(hit: int, total: int) -> str:
    if total == 0:
        return "n/a"
    return f"{hit}/{total} ({hit / total:.1%})"


def write_reports(sample_score: dict, custom: list[dict]) -> None:
    failures = "\n".join(f"- {line}" for line in sample_score["failures"]) or "- none"
    custom_lines = []
    for case in custom:
        mark = "pass" if case["passed"] else "fail"
        custom_lines.append(
            f"### {case['name']} ({mark})\n\n"
            f"- Input: `{case['input']}`\n"
            f"- Expected: `{case['expected']}`\n"
            f"- Actual: `{case['actual']}`\n"
        )
    evaluation = f"""# Evaluation report

The public sample file is the scorecard for the 32 cases below. It is not an input to resource assignment. The five custom cases are defined in this report and in `code/evaluation/custom_cases.py`.

## Sample scorecard

- Case-level deletion-status accuracy: {_percent(sample_score['deletion_status'], sample_score['cases'])}
- Case-level exact match (status and ordered steps): {_percent(sample_score['case_exact'], sample_score['cases'])}
- Sequence accuracy: {_percent(sample_score['sequence'], sample_score['cases'])}
- Step-level accuracy: recall {_percent(sample_score['step_hits'], sample_score['expected_steps'])}; precision {_percent(sample_score['step_hits'], sample_score['actual_steps'])}
- Field-level accuracy: {_percent(sample_score['field_hits'], sample_score['field_total'])} across phase, operation, system_id, resource_id, state, and evidence_id

## Custom cases

{chr(10).join(custom_lines)}
## Failures found and improvements made

{failures}

Twelve of the 32 public cases still miss a resource. The misses are anonymous analytics rows whose snapshot position is consistent with more than one user, and account-delete bursts whose emit order is not a stable sort of case id, request time, or identity-file order. Equal-count pairing by case id was measured and left out: it added an account to a case that does not own it. Phantom audit ids that never appear in activity or evidence are not invented.

Improvements retained from that measurement:

- An empty `customer_profiles` snapshot is a full-store census. It outranks an earlier SQL replica when the audit time allows it.
- Identity on a record may come from any capture time. The state citation still has to be captured at or before `audit_at`.
- A one-row account burst is assigned only when one request is reported 50 to 80 minutes later.
- Analytics is identifiable only from an email, phone, or user id. A hash alone is a remaining record to delete.
- Negation is tested before deletion verbs, including 削除.
"""
    usage = """# Usage report

The run that writes `output.csv` is deterministic Python. It does not call a model.

| Provider | Model | Calls | Input tokens | Output tokens | Estimated cost (USD) |
|---|---|---:|---:|---:|---:|
| none | none | 0 | 0 | 0 | 0 |

## Totals

- Requests scored by the engine: 518 evaluation requests, plus 32 public samples during evaluation.
- Model calls: 0
- Input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Average tokens per request: 0
- Estimated total cost: 0 USD
- Estimated cost per request: 0 USD

No API key is read and no provider is billed. Installed client libraries are unused by this run.
"""
    for directory in (REPORT_DIR, ROOT_EVAL):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "evaluation_report.md").write_text(evaluation, encoding="utf-8", newline="\n")
        (directory / "usage_report.md").write_text(usage, encoding="utf-8", newline="\n")


def main() -> None:
    world = load_world()
    sample_requests = load_csv("sample_deletion_requests.csv")
    expected = {row["case_id"]: row for row in load_csv("sample_output.csv")}
    predicted = audit_requests(world, sample_requests)
    sample_score = score_cases(expected, predicted)
    custom = run_custom_cases(world.observations)
    write_reports(sample_score, custom)
    print(
        "status", f"{sample_score['deletion_status']}/{sample_score['cases']}",
        "exact", f"{sample_score['case_exact']}/{sample_score['cases']}",
        "steps", f"{sample_score['step_hits']}/{sample_score['expected_steps']}",
        "precision", f"{sample_score['step_hits']}/{sample_score['actual_steps']}",
        "custom", sum(case["passed"] for case in custom), "/", len(custom),
    )
    for line in sample_score["failures"]:
        print(line)
    for case in custom:
        if not case["passed"]:
            print("custom fail", case["name"], case["actual"])


if __name__ == "__main__":
    main()
