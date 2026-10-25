"""Apply deletion_rules.csv through the category of each observation.

Findings keep their evidence id. Remediation steps, and every verification
step on an incomplete case, use an empty evidence id.
"""

from __future__ import annotations

from code.evidence import (
    ANONYMIZE_CATEGORIES,
    DELETE_CATEGORIES,
    REDACT_CATEGORIES,
    RETAIN_CATEGORIES,
    Obs,
)

OP_ORDER = {
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


def _verify(operation: str, state: str, obs: Obs) -> dict[str, str]:
    return {
        "violation": "",
        "remedy": "",
        "verify_op": operation,
        "verify_state": state,
        "system_id": obs.system_id,
        "resource_id": obs.resource_id,
        "evidence_id": obs.file_id,
    }


def violate(
    finding: str,
    finding_state: str,
    remedy: str,
    remedy_state: str,
    verify_op: str,
    verify_state: str,
    obs: Obs,
) -> dict[str, str]:
    return {
        "violation": finding,
        "violation_state": finding_state,
        "remedy": remedy,
        "remedy_state": remedy_state,
        "verify_op": verify_op,
        "verify_state": verify_state,
        "system_id": obs.system_id,
        "resource_id": obs.resource_id,
        "evidence_id": obs.file_id,
    }


def plan_resource(obs: Obs) -> dict[str, str] | None:
    category = obs.category
    if category in DELETE_CATEGORIES:
        if not obs.present:
            return _verify("VERIFY_RECORD_ABSENT", "ABSENT", obs)
        return violate(
            "REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT", obs,
        )
    if category in ANONYMIZE_CATEGORIES:
        if not obs.present:
            return _verify("VERIFY_RECORD_ABSENT", "ABSENT", obs)
        if obs.identifiable:
            return violate(
                "REPORT_EXPOSED_PII", "PRESENT", "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", obs,
            )
        return _verify("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", obs)
    if category in REDACT_CATEGORIES:
        if not obs.present:
            return _verify("VERIFY_RECORD_ABSENT", "ABSENT", obs)
        if obs.identifiable:
            return violate(
                "REPORT_EXPOSED_PII", "PRESENT", "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REDACTED", obs,
            )
        return _verify("VERIFY_RECORD_REDACTED", "REDACTED", obs)
    if category in RETAIN_CATEGORIES:
        if obs.present:
            return _verify("VERIFY_RECORD_PRESENT", "PRESENT", obs)
        return None
    if category == "BACKUP_ARCHIVE":
        if obs.restore_allowed is False:
            return _verify("VERIFY_RESTORE_BLOCKED", "BLOCKED", obs)
        if obs.present:
            return violate(
                "REPORT_RESTORE_RISK", "ACTIVE", "BLOCK_RESTORE", "BLOCKED", "VERIFY_RESTORE_BLOCKED", "BLOCKED", obs,
            )
        return None
    if category == "DATA_FLOW":
        if obs.enabled is False:
            return _verify("VERIFY_DATA_FLOW_DISABLED", "DISABLED", obs)
        if obs.present or obs.enabled is True:
            return violate(
                "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED", "DISABLED", obs,
            )
        return None
    return None


def hash_only_analytics(obs: Obs) -> bool:
    return bool(
        obs.category == "ANALYTICS_PROFILE"
        and obs.present
        and obs.hashes
        and not (obs.emails or obs.phones or obs.user_ids)
    )


def steps_from_plans(plans: list[dict[str, str]]) -> tuple[str, list[dict]]:
    findings = []
    remedies = []
    checks = []
    for plan in plans:
        if plan["violation"]:
            findings.append({
                "phase": "FINDING",
                "operation": plan["violation"],
                "state": plan["violation_state"],
                "system_id": plan["system_id"],
                "resource_id": plan["resource_id"],
                "evidence_id": plan["evidence_id"],
            })
            remedies.append({
                "phase": "REMEDIATION",
                "operation": plan["remedy"],
                "state": plan["remedy_state"],
                "system_id": plan["system_id"],
                "resource_id": plan["resource_id"],
                "evidence_id": "",
            })
        checks.append({
            "phase": "VERIFICATION",
            "operation": plan["verify_op"],
            "state": plan["verify_state"],
            "system_id": plan["system_id"],
            "resource_id": plan["resource_id"],
            "evidence_id": plan["evidence_id"],
        })
    status = "INCOMPLETE" if findings else "COMPLETE"
    if status == "INCOMPLETE":
        for check in checks:
            check["evidence_id"] = ""
    ordered = findings + remedies + checks
    ordered.sort(key=lambda step: (
        list(OP_ORDER).index(step["phase"]),
        OP_ORDER[step["phase"]].index(step["operation"]),
        step["system_id"],
        step["resource_id"],
    ))
    steps = []
    for number, step in enumerate(ordered, start=1):
        steps.append({
            "step_no": number,
            "phase": step["phase"],
            "system_id": step["system_id"],
            "resource_id": step["resource_id"],
            "operation": step["operation"],
            "state": step["state"],
            "evidence_id": step["evidence_id"],
        })
    return status, steps
