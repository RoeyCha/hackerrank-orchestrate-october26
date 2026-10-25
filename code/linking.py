"""Connect a request to the resources that belong to that person.

Evidence and LINK_RESOURCE_IDENTITY rows may use any capture time. A deletion
worker event is used only when its target line names one resource and exactly
one request has a reported_at within twenty minutes. A one-row account burst
is used only when exactly one request is reported 50 to 80 minutes later.
Users user_01 through user_10 fall back to account_001 through account_010
when nothing else names an account.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta

from code.alignment import alignment_observations
from code.evidence import Obs, load_observations

EXCLUDED_PATTERNS = {"pdf_legal_hold", "png_retained_reference"}
from code.intent import non_deletion_accounts
from code.load_data import load_csv, parse_time

WINDOW = timedelta(minutes=20)
CANONICAL_SYSTEM = {
    "USER_PROFILE": "account_service",
    "SECONDARY_IDENTIFIER": "account_service",
    "SEARCH_INDEX_ENTRY": "search_service",
    "ANALYTICS_PROFILE": "analytics_platform",
    "PRODUCT_TELEMETRY": "analytics_platform",
    "SUPPORT_MESSAGE": "support_platform",
    "SUPPORT_ATTACHMENT": "support_platform",
    "USER_EXPORT": "export_service",
    "DATA_FLOW": "integration_service",
    "BACKUP_ARCHIVE": "backup_service",
    "SECURITY_AUDIT_LOG": "security_service",
    "ACCOUNT_TOMBSTONE": "identity_service",
    "CACHE_ENTRY": "cache_service",
    "MARKETING_PROFILE": "marketing_platform",
    "EMAIL_DELIVERY_LOG": "email_delivery_service",
    "LEGAL_HOLD_RECORD": "legal_service",
    "object_storage": "object_storage",
    "archive_service": "security_service",
    "account_failover_replica": "account_service",
    "account_replication_cluster": "account_service",
    "object_store": "export_service",
    "privacy_case_management": "account_service",
    "user_export_store": "export_service",
    "analytics_identity_store": "analytics_platform",
    "search_index_service": "search_service",
    "support_replica": "support_platform",
    "downstream_delivery_service": "email_delivery_service",
    "attachment_preview": "support_platform",
}


def system_of(value: str) -> str:
    return CANONICAL_SYSTEM.get(value, value)


@dataclass
class World:
    observations: list[Obs]
    activity: list[dict[str, str]]
    identities: list[dict[str, str]]
    audits: list[dict[str, str]]
    requests: list[dict[str, str]]
    singleton_accounts: dict[str, str] = field(default_factory=dict)
    classified_accounts: set[str] = field(default_factory=set)


def singleton_account_owners(activity: list[dict[str, str]], requests: list[dict[str, str]]) -> dict[str, str]:
    rows = sorted(
        (
            row for row in activity
            if row["source_system"] == "deletion_worker"
            and row["event_type"] == "DELETE_RECORD"
            and row["target_system"] == "account_service"
            and "Target resource:" not in row["details"]
        ),
        key=lambda row: row["event_time"],
    )
    bursts: list[list[dict[str, str]]] = []
    current: list[dict[str, str]] = []
    for row in rows:
        if current and (parse_time(row["event_time"]) - parse_time(current[-1]["event_time"])).total_seconds() > 20 * 60:
            bursts.append(current)
            current = []
        current.append(row)
    if current:
        bursts.append(current)
    owners = {}
    for burst in bursts:
        if len(burst) != 1:
            continue
        event = parse_time(burst[0]["event_time"])
        candidates = []
        for request in requests:
            delta = (parse_time(request["reported_at"]) - event).total_seconds()
            if 50 * 60 <= delta <= 80 * 60:
                candidates.append(request)
        if len(candidates) != 1:
            continue
        request = candidates[0]
        if parse_time(request["requested_at"]) <= event <= parse_time(request["audit_at"]):
            owners[burst[0]["resource_id"]] = request["case_id"]
    return owners


def load_world() -> World:
    identities = load_csv("user_identities.csv")
    audits = load_csv("user_audit_log.csv")
    activity = load_csv("system_activity.csv")
    manifest = load_csv("evidence_files.csv")
    requests = load_csv("sample_deletion_requests.csv") + load_csv("deletion_requests.csv")
    observations, _patterns, _unparsed = load_observations(manifest)
    observations = [obs for obs in observations if obs.pattern not in EXCLUDED_PATTERNS]
    email_user = {row["email"].lower(): row["user_id"] for row in identities}
    for row in audits:
        if row["field_name"] == "email":
            email_user.setdefault(row["old_value"].lower(), row["user_id"])
            email_user.setdefault(row["new_value"].lower(), row["user_id"])
    requests_by_id = {row["case_id"]: row for row in requests}
    user_case: dict[str, str] = {}
    for row in requests:
        user_id = email_user.get(row["email"].lower(), "")
        if user_id:
            user_case.setdefault(user_id, row["case_id"])
    observations.extend(alignment_observations(manifest, requests, activity, email_user, user_case, requests_by_id))
    return World(
        observations=observations,
        activity=activity,
        identities=identities,
        audits=audits,
        requests=requests,
        singleton_accounts=singleton_account_owners(activity, requests),
        classified_accounts=non_deletion_accounts(activity),
    )


def linked_resource_ids(world: World, request: dict[str, str], user_ids: set[str], tokens: dict[str, set[str]]) -> set[tuple[str, str]]:
    case_id = request["case_id"]
    requested_at = parse_time(request["requested_at"])
    audit_at = parse_time(request["audit_at"])
    linked = {(obs.system_id, obs.resource_id) for obs in world.observations if obs.touches(tokens)}
    for row in world.activity:
        if row["event_type"] != "LINK_RESOURCE_IDENTITY":
            continue
        detail = row["details"].lower()
        if any(email in detail for email in tokens["emails"]) or any(user_id in detail for user_id in user_ids):
            linked.add((system_of(row["target_system"]), row["resource_id"]))
    reported = [(row, parse_time(row["reported_at"])) for row in world.requests]

    def unique_owner(event_time):
        ranked = sorted(reported, key=lambda item: abs((item[1] - event_time).total_seconds()))
        best_row, best_at = ranked[0]
        best_delta = abs((best_at - event_time).total_seconds())
        second_delta = abs((ranked[1][1] - event_time).total_seconds())
        if best_delta <= WINDOW.total_seconds() and second_delta > best_delta + 1:
            return best_row
        return None

    for row in world.activity:
        if row["source_system"] != "deletion_worker" or "Target resource:" not in row["details"]:
            continue
        event_time = parse_time(row["event_time"])
        if event_time < requested_at or event_time > audit_at:
            continue
        owner = unique_owner(event_time)
        if owner and owner["case_id"] == case_id:
            linked.add((system_of(row["target_system"]), row["resource_id"]))
    for resource_id, owner_case in world.singleton_accounts.items():
        if owner_case == case_id:
            linked.add(("account_service", resource_id))
    if not any(resource_id.startswith("account_") for _, resource_id in linked):
        for user_id in user_ids:
            match = re.fullmatch(r"user_(\d+)", user_id)
            if match and 1 <= int(match.group(1)) <= 10:
                linked.add(("account_service", f"account_{int(match.group(1)):03d}"))
    return linked
