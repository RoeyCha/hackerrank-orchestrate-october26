"""Print the cohorts that still hold the 13 unmatched sample resources.

Non-deletion requests are detected from the request text and from
CLASSIFY_REQUEST rows. Sample answers are printed only as a check against
the burst order. They are not used to decide which resource a case owns.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import solve_burst_assignment as burst  # noqa: E402
import solve_resource_linking as link  # noqa: E402

verify = link.verify

FOCUS = [
    "2026-08-30T12:00:00Z",
    "2026-09-01T10:00:00Z",
    "2026-09-02T12:00:00Z",
    "2026-09-05T12:00:00Z",
    "2026-09-06T12:00:00Z",
    "2026-09-09T11:00:00Z",
    "2026-09-15T11:00:00Z",
]

NON_DELETION = re.compile(
    r"not a request to erase|do not close|leave the account active|keep the account|"
    r"without removing|marketing lists only|leave my profile|continue using the service|"
    r"information request|leave my profile and purchase",
    re.IGNORECASE,
)
DELETION = re.compile(
    r"delet|eras|exclu|supprim|삭제|削除|suppression|remov|close the account|closed|"
    r"forget|profile is gone|permanen",
    re.IGNORECASE,
)


def section(title: str) -> None:
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def authorizes_deletion(text: str) -> bool:
    if NON_DELETION.search(text):
        return False
    return bool(DELETION.search(text))


def case_number(case_id: str) -> int:
    return int(case_id.split("_")[1])


def user_number(user_id: str) -> int:
    return int(user_id.split("_")[1]) if user_id.startswith("user_") else 0


def owner_names(resource_id: str, identified: dict[str, str], sample_owner: dict[str, str]) -> str:
    evidence = identified.get(resource_id, "")
    sample = sample_owner.get(resource_id, "")
    parts = []
    if evidence:
        parts.append(f"evidence={evidence}")
    if sample and sample != evidence:
        parts.append(f"sample_check={sample}")
    return ", ".join(parts) or "unidentified"


def main() -> None:
    identities = link.load_csv("user_identities.csv")
    audits = link.load_csv("user_audit_log.csv")
    activity = link.load_csv("system_activity.csv")
    manifest = link.load_csv("evidence_files.csv")
    sample_requests = link.load_csv("sample_deletion_requests.csv")
    eval_requests = link.load_csv("deletion_requests.csv")
    requests = sample_requests + eval_requests
    requests_by_id = {row["case_id"]: row for row in requests}
    file_order = {row["case_id"]: index for index, row in enumerate(requests)}
    identity_by_user = {row["user_id"]: row for row in identities}
    identity_order = {row["user_id"]: index for index, row in enumerate(identities)}
    email_user = {row["email"].lower(): row["user_id"] for row in identities}
    for row in audits:
        if row["field_name"] == "email":
            email_user.setdefault(row["old_value"].lower(), row["user_id"])
            email_user.setdefault(row["new_value"].lower(), row["user_id"])

    sample_owner: dict[str, str] = {}
    sample_resources: dict[str, set[str]] = defaultdict(set)
    for row in link.load_csv("sample_output.csv"):
        for step in json.loads(row["steps_json"]):
            sample_owner[step["resource_id"]] = row["case_id"]
            sample_resources[row["case_id"]].add(step["resource_id"])

    observations, _patterns, _unparsed = verify.load_observations(manifest)
    observations = [obs for obs in observations if obs.pattern not in link.EXCLUDED_PATTERNS]
    identified = burst.evidence_owners(observations, requests, identities, audits)
    for resource_id, case_id in burst.link_owners(activity, requests, identities, audits).items():
        identified.setdefault(resource_id, case_id)
    resources_for: dict[str, list[str]] = defaultdict(list)
    for resource_id, case_id in identified.items():
        resources_for[case_id].append(resource_id)

    classified_accounts = {
        row["resource_id"]
        for row in activity
        if row["event_type"] == "CLASSIFY_REQUEST" and "non-deletion" in row["details"]
    }
    tokens = {
        row["case_id"]: verify.identity_tokens(row["email"], identities, audits)
        for row in requests
    }

    by_reported: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in requests:
        by_reported[row["reported_at"]].append(row)
    worker = [
        row for row in activity
        if row["source_system"] == "deletion_worker" and "Target resource:" not in row["details"]
    ]
    account_bursts = burst.align_bursts(
        burst.bursts_of([
            row for row in worker
            if row["event_type"] == "DELETE_RECORD" and row["target_system"] == "account_service"
        ]),
        by_reported,
        burst.ACCOUNT_WINDOW,
        70 * 60,
    )
    analytics_bursts = burst.align_bursts(
        burst.bursts_of([
            row for row in worker
            if row["event_type"] == "ANONYMIZE_RECORD"
            and row["target_system"] == "analytics_platform"
            and row["reported_result"] == "SUCCESS"
        ]),
        by_reported,
        burst.ANALYTICS_WINDOW,
        29 * 60,
    )

    def user_of(row: dict[str, str]) -> str:
        return email_user.get(row["email"].lower(), "?")

    def deletion_case(row: dict[str, str]) -> bool:
        return authorizes_deletion(row["request_text"])

    def linked(case_id: str, prefix: str) -> list[str]:
        return sorted(resource_id for resource_id in resources_for.get(case_id, []) if resource_id.startswith(prefix))

    def print_cases(cohort: list[dict[str, str]]) -> None:
        ordered = sorted(cohort, key=lambda row: case_number(row["case_id"]))
        for row in ordered:
            user = user_of(row)
            identity = identity_by_user.get(user, {})
            accounts = linked(row["case_id"], "account_")
            analytics = linked(row["case_id"], "analytics_")
            classified = [resource_id for resource_id in accounts if resource_id in classified_accounts]
            kind = "DELETION" if deletion_case(row) else "NOT_DELETION"
            print(
                f"  {row['case_id']} {user} {kind} status={row['reported_status']} "
                f"requested={row['requested_at']} email={row['email']}"
            )
            print(
                f"    identity_row={identity_order.get(user, -1)} updated_at={identity.get('updated_at', '')} "
                f"name={identity.get('name', '')} phone={identity.get('phone', '')} "
                f"hash={identity.get('email_hash', '')[:16]}"
            )
            print(f"    accounts={accounts or 'none'} analytics={analytics or 'none'} classify_non_deletion={classified or 'no'}")
            others = sorted(
                resource_id for resource_id in resources_for.get(row["case_id"], [])
                if not resource_id.startswith(("account_", "analytics_"))
            )
            print(f"    other_linked={others or 'none'}")
            if row["case_id"] in sample_resources:
                print(f"    sample_answer_resources={sorted(sample_resources[row['case_id']])}")
            print(f"    request: {row['request_text'][:240]}")

    def print_burst(title: str, rows: list[dict[str, str]] | None) -> None:
        print(f"  {title}:")
        if not rows:
            print("    no aligned burst")
            return
        for index, row in enumerate(rows):
            print(
                f"    [{index}] {row['activity_id']} {row['event_time']} {row['event_type']} "
                f"{row['resource_id']} {row['reported_result']} "
                f"{owner_names(row['resource_id'], identified, sample_owner)}"
            )
            print(f"         {row['details']}")

    def print_window(moment: str, cohort_ids: set[str]) -> None:
        start = link.parse_time(moment) - timedelta(minutes=90)
        end = link.parse_time(moment) + timedelta(hours=3)
        print(f"  deletion_worker rows from {start.strftime('%H:%M:%SZ')} to {end.strftime('%H:%M:%SZ')}:")
        count = 0
        for row in worker:
            event = link.parse_time(row["event_time"])
            if not start <= event <= end:
                continue
            owner = identified.get(row["resource_id"], "")
            if owner and owner not in cohort_ids:
                continue
            count += 1
            print(
                f"    {row['activity_id']} {row['event_time']} {row['event_type']} "
                f"{row['target_system']} {row['resource_id']} {row['reported_result']} "
                f"{owner_names(row['resource_id'], identified, sample_owner)}"
            )
        print(f"    rows shown: {count}")

    keys = {
        "requested_at": lambda row: row["requested_at"],
        "requested_desc": lambda row: tuple(-ord(char) for char in row["requested_at"]),
        "user_id": lambda row: user_number(user_of(row)),
        "user_desc": lambda row: -user_number(user_of(row)),
        "case_id": lambda row: case_number(row["case_id"]),
        "case_desc": lambda row: -case_number(row["case_id"]),
        "email": lambda row: row["email"].lower(),
        "name": lambda row: identity_by_user.get(user_of(row), {}).get("name", "").lower(),
        "hash": lambda row: identity_by_user.get(user_of(row), {}).get("email_hash", ""),
        "updated_at": lambda row: identity_by_user.get(user_of(row), {}).get("updated_at", ""),
        "updated_desc": lambda row: tuple(-ord(char) for char in identity_by_user.get(user_of(row), {}).get("updated_at", "")),
        "phone": lambda row: re.sub(r"\D", "", identity_by_user.get(user_of(row), {}).get("phone", "")),
        "identity_row": lambda row: identity_order.get(user_of(row), 10**9),
        "file_order": lambda row: file_order.get(row["case_id"], 10**9),
        "sha_user": lambda row: hashlib.sha256(user_of(row).encode()).hexdigest(),
        "sha_email": lambda row: hashlib.sha256(row["email"].lower().encode()).hexdigest(),
        "status_then_requested": lambda row: (row["reported_status"], row["requested_at"]),
    }

    def labeled_sequence(rows: list[dict[str, str]], allowed: set[str]) -> list[str] | None:
        labels = []
        for row in rows:
            label = identified.get(row["resource_id"]) or sample_owner.get(row["resource_id"])
            if label not in allowed:
                return None
            labels.append(label)
        if len(set(labels)) != len(labels):
            return None
        return labels

    def score_keys(title: str, cohort: list[dict[str, str]], rows: list[dict[str, str]] | None) -> None:
        print(f"  sort keys for {title}:")
        if not rows:
            print("    no burst")
            return
        deletion_rows = [row for row in cohort if deletion_case(row)]
        groups = {
            "all_cases": cohort,
            "deletion_only": deletion_rows,
        }
        for group_name, group in groups.items():
            if len(group) != len(rows):
                print(f"    {group_name}: length {len(group)} does not equal burst {len(rows)}")
                continue
            allowed = {row["case_id"] for row in group}
            labels = labeled_sequence(rows, allowed)
            if labels is None:
                print(f"    {group_name}: burst is not fully labeled by evidence or the sample check")
                known = []
                for index, row in enumerate(rows):
                    label = identified.get(row["resource_id"]) or sample_owner.get(row["resource_id"])
                    if label in allowed:
                        known.append((index, label))
                print(f"      known positions: {known}")
                for name, fn in keys.items():
                    ordered = [row["case_id"] for row in sorted(group, key=fn)]
                    hits = sum(1 for index, label in known if index < len(ordered) and ordered[index] == label)
                    if hits == len(known) and known:
                        print(f"      {name} places every known label at its burst index: {ordered}")
                continue
            print(f"    {group_name} labeled order: {labels}")
            for name, fn in keys.items():
                ordered = [row["case_id"] for row in sorted(group, key=fn)]
                if ordered == labels:
                    print(f"      MATCH {name}: {ordered}")

    section("Focus cohorts")
    for moment in FOCUS:
        cohort = by_reported[moment]
        cohort_ids = {row["case_id"] for row in cohort}
        deletion_count = sum(1 for row in cohort if deletion_case(row))
        section(f"{moment}  cases={len(cohort)} deletion={deletion_count}")
        print_cases(cohort)
        print_burst("account DELETE burst", account_bursts.get(moment))
        print_burst("analytics ANONYMIZE success burst", analytics_bursts.get(moment))
        print_window(moment, cohort_ids)
        score_keys("account burst", cohort, account_bursts.get(moment))
        score_keys("analytics burst", cohort, analytics_bursts.get(moment))

    section("2026-09-01 10:00: case_22 versus case_54")
    moment = "2026-09-01T10:00:00Z"
    for case_id in ("case_16", "case_22", "case_54"):
        row = requests_by_id[case_id]
        user = user_of(row)
        identity = identity_by_user.get(user, {})
        print(
            f"  {case_id} {user} deletion={deletion_case(row)} requested={row['requested_at']} "
            f"status={row['reported_status']} identity_row={identity_order.get(user)} "
            f"updated={identity.get('updated_at')} email={row['email']} name={identity.get('name')}"
        )
        print(f"    hash={identity.get('email_hash')} phone={identity.get('phone')}")
        print(f"    accounts={linked(case_id, 'account_')} analytics={linked(case_id, 'analytics_')}")
    print("  account burst order with labels:")
    for index, row in enumerate(account_bursts.get(moment, [])):
        print(f"    [{index}] {row['resource_id']} {row['event_time']} {owner_names(row['resource_id'], identified, sample_owner)}")
    print("  evidence/activity hits for account_6829 and account_4990:")
    for resource_id in ("account_6829", "account_4990"):
        hits = [row for row in activity if row["resource_id"] == resource_id]
        print(f"    {resource_id} activity={len(hits)} evidence_owner={identified.get(resource_id, 'none')} sample_check={sample_owner.get(resource_id, 'none')}")
        for row in hits:
            print(f"      {row['activity_id']} {row['event_time']} {row['event_type']} {row['details']}")
        needle = resource_id.encode()
        files = []
        for path in (link.DATASET).rglob("*"):
            if path.is_file() and needle in path.read_bytes():
                files.append(str(path.relative_to(link.DATASET)))
        print(f"      files containing {resource_id}: {files or 'none'}")
    print("  case_id order would assign the middle row to case_22 and the last row to case_54.")
    print("  requested_at order (and user_id descending) assigns the middle row to case_54 and the last row to case_22.")
    print(f"  sample_output for case_22 contains account_4990: {'account_4990' in sample_resources.get('case_22', set())}")

    section("2026-09-05 12:00: six accounts and one analytics row")
    moment = "2026-09-05T12:00:00Z"
    cohort = by_reported[moment]
    print("  cases in reported_at order of requested_at, then case_id:")
    for row in sorted(cohort, key=lambda item: (item["requested_at"], case_number(item["case_id"]))):
        user = user_of(row)
        print(
            f"    {row['case_id']} {user} deletion={deletion_case(row)} requested={row['requested_at']} "
            f"status={row['reported_status']} accounts={linked(row['case_id'], 'account_') or 'none'} "
            f"analytics={linked(row['case_id'], 'analytics_') or 'none'}"
        )
    account_rows = account_bursts.get(moment, [])
    print("  where sample_output places case_21 and case_23 inside the account burst:")
    for index, row in enumerate(account_rows):
        if sample_owner.get(row["resource_id"]) in {"case_21", "case_23"}:
            print(f"    index {index} {row['resource_id']} is the sample resource for {sample_owner[row['resource_id']]}")
    print("  analytics activity for each cohort case, any time:")
    analytics_activity = [
        row for row in activity
        if row["target_system"] == "analytics_platform" or row["resource_id"].startswith("analytics_")
    ]
    for row in sorted(cohort, key=lambda item: case_number(item["case_id"])):
        owned = set(resources_for.get(row["case_id"], []))
        mine = [item for item in analytics_activity if item["resource_id"] in owned]
        print(f"    {row['case_id']} linked_analytics_events={len(mine)}")
        for item in mine:
            print(f"      {item['activity_id']} {item['event_time']} {item['event_type']} {item['resource_id']} {item['reported_result']}")
    print("  the success anonymize burst has one row, analytics_5335.")
    print(f"  sample_output gives analytics_5335 to {sample_owner.get('analytics_5335', 'no sample case')}.")
    print("  case_23 sample resources:", sorted(sample_resources.get("case_23", [])))
    print("  case_21 sample resources:", sorted(sample_resources.get("case_21", [])))

    section("2026-09-02 12:00 analytics: who has an analytics profile")
    moment = "2026-09-02T12:00:00Z"
    cohort = by_reported[moment]
    for row in sorted(cohort, key=lambda item: case_number(item["case_id"])):
        owned = set(resources_for.get(row["case_id"], []))
        events = [
            item for item in activity
            if item["resource_id"] in owned and (
                item["target_system"] == "analytics_platform" or item["resource_id"].startswith("analytics_")
            )
        ]
        mentions_analytics = "analytics" in row["request_text"].lower()
        print(
            f"  {row['case_id']} deletion={deletion_case(row)} requested={row['requested_at']} "
            f"linked_analytics={linked(row['case_id'], 'analytics_') or 'none'} "
            f"analytics_events={len(events)} request_mentions_analytics={mentions_analytics}"
        )
    print("  anonymize burst:")
    for index, row in enumerate(analytics_bursts.get(moment, [])):
        print(
            f"    [{index}] {row['resource_id']} {row['event_time']} "
            f"{owner_names(row['resource_id'], identified, sample_owner)} {row['details']}"
        )
    print("  account burst labels, for comparison with the analytics pair:")
    for index, row in enumerate(account_bursts.get(moment, [])):
        print(f"    [{index}] {row['resource_id']} {owner_names(row['resource_id'], identified, sample_owner)}")


if __name__ == "__main__":
    main()
