"""Participant-written checks. Their inputs and expected results are printed in the report."""

from __future__ import annotations

from datetime import datetime

from code.absence import latest_absence
from code.evidence import Obs
from code.intent import authorizes_deletion
from code.policy import hash_only_analytics, plan_resource


def run_custom_cases(observations: list[Obs]) -> list[dict]:
    tombstone = Obs(
        file_id="custom_tombstone",
        captured_at="2026-09-01T00:00:00Z",
        observed_at="2026-09-01T00:00:00Z",
        system_id="identity_service",
        resource_id="tombstone_custom",
        category="ACCOUNT_TOMBSTONE",
        pattern="custom",
        emails={"person@example.com"},
        present=True,
        identifiable=True,
    )
    tombstone_plan = plan_resource(tombstone)
    analytics = Obs(
        file_id="custom_analytics",
        captured_at="2026-09-01T00:00:00Z",
        observed_at="2026-09-01T00:00:00Z",
        system_id="analytics_platform",
        resource_id="analytics_custom",
        category="ANALYTICS_PROFILE",
        pattern="custom",
        hashes={"a" * 64},
        present=True,
        identifiable=False,
    )
    early = datetime.fromisoformat("2026-09-02T23:00:00+00:00")
    later = datetime.fromisoformat("2026-09-15T12:00:00+00:00")
    absent_resource = "account_custom_absent"
    cases = [
        {
            "name": "negated erasure request",
            "input": "This is not a request to erase my account. It is an information request.",
            "expected": "NOT_APPLICABLE",
            "actual": "NOT_APPLICABLE" if not authorizes_deletion(
                "This is not a request to erase my account. It is an information request."
            ) else "DELETION",
        },
        {
            "name": "Japanese deletion verb",
            "input": "個人データを削除してください",
            "expected": "DELETION",
            "actual": "DELETION" if authorizes_deletion("個人データを削除してください") else "NOT_APPLICABLE",
        },
        {
            "name": "tombstone keeps the record and redacts identifiers",
            "input": "present ACCOUNT_TOMBSTONE with an email",
            "expected": "REPORT_EXPOSED_PII -> REDACT_RECORD -> VERIFY_RECORD_REDACTED",
            "actual": (
                f"{tombstone_plan['violation']} -> {tombstone_plan['remedy']} -> {tombstone_plan['verify_op']}"
                if tombstone_plan else "none"
            ),
        },
        {
            "name": "hash-only analytics is deleted rather than anonymized",
            "input": "present ANALYTICS_PROFILE with an email hash and no email, phone, or user id",
            "expected": "DELETE",
            "actual": "DELETE" if hash_only_analytics(analytics) else "ANONYMIZE",
        },
        {
            "name": "later empty account census outranks the earlier replica",
            "input": f"{absent_resource} at 2026-09-02T23:00:00Z and at 2026-09-15T12:00:00Z",
            "expected": "evidence_54 then evidence_51",
            "actual": (
                f"{(latest_absence(observations, early, absent_resource) or ('', ''))[0]} then "
                f"{(latest_absence(observations, later, absent_resource) or ('', ''))[0]}"
            ),
        },
    ]
    for case in cases:
        case["passed"] = case["actual"] == case["expected"]
    return cases
