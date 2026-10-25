"""Look for the generator's row order in evidence tables and cohort activity.

Sample answers are printed as a check beside a resource. They are not used to
decide which activity row belongs to a case.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import solve_burst_assignment as burst  # noqa: E402
import solve_resource_linking as link  # noqa: E402

verify = link.verify
DATASET = link.DATASET

TARGETS = [
    "analytics_1895",
    "analytics_4566",
    "analytics_5335",
    "analytics_9406",
    "analytics_4574",
    "analytics_6077",
]
COHORTS = {
    "2026-09-05T12:00:00Z": [
        "case_21",
        "case_23",
        "case_536",
        "case_546",
        "case_547",
        "case_548",
    ],
    "2026-09-02T12:00:00Z": [
        "case_24",
        "case_25",
        "case_26",
        "case_549",
        "case_550",
    ],
    "2026-09-01T10:00:00Z": [
        "case_16",
        "case_22",
        "case_54",
    ],
}
RESOURCE_WORD = re.compile(r"\b(?:account|analytics|search|export|support|data_flow|backup|audit_record|tombstone)_\d+\b")


def section(title: str) -> None:
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def case_number(case_id: str) -> int:
    return int(case_id.split("_")[1])


def activity_number(activity_id: str) -> int:
    return int(activity_id.split("_")[1])


def identity_hint(record: dict) -> str:
    fields = []
    for key in (
        "user_id",
        "email",
        "phone",
        "email_hash",
        "subject_reference",
        "customer_reference",
        "owner_email",
        "requester_email",
        "customer_email",
        "status_code",
        "account_status",
    ):
        value = record.get(key)
        if value not in (None, "", [], {}):
            fields.append(f"{key}={value}")
    profile = record.get("profile")
    if isinstance(profile, dict):
        for key in ("user_id", "email", "status"):
            value = profile.get(key)
            if value not in (None, ""):
                fields.append(f"profile.{key}={value}")
    return ", ".join(fields)


def iter_collections(path: Path):
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("snapshots"), list):
            for snap in payload["snapshots"]:
                records = snap.get("records") or []
                label = f"{snap.get('captured_at')} {snap.get('data_store')} {snap.get('collection')}"
                yield label, records
        if isinstance(payload, dict) and isinstance(payload.get("service_exports"), dict):
            for service, block in payload["service_exports"].items():
                if not isinstance(block, dict):
                    continue
                for name, records in block.items():
                    if isinstance(records, list):
                        yield f"{service} {name}", records
        return
    if path.suffix.lower() == ".sql":
        text = path.read_text(encoding="utf-8", errors="ignore")
        current = None
        buckets: dict[str, list[dict]] = defaultdict(list)
        for line in text.splitlines():
            table = re.search(r"INSERT INTO\s+([A-Za-z0-9_]+)", line, flags=re.I)
            if table:
                current = table.group(1)
            if current is None:
                continue
            for resource_id in RESOURCE_WORD.findall(line):
                buckets[current].append({"resource_id": resource_id, "line": line.strip()[:180]})
        for name, records in buckets.items():
            yield name, records
        return
    if path.suffix.lower() in {".log", ".txt"}:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        records = []
        for index, line in enumerate(lines):
            found = RESOURCE_WORD.findall(line)
            if found:
                records.append({"resource_id": found[0], "line_no": index + 1, "line": line.strip()[:180]})
        yield path.name, records


def load_context():
    identities = link.load_csv("user_identities.csv")
    audits = link.load_csv("user_audit_log.csv")
    activity = link.load_csv("system_activity.csv")
    manifest = link.load_csv("evidence_files.csv")
    requests = link.load_csv("sample_deletion_requests.csv") + link.load_csv("deletion_requests.csv")
    requests_by_id = {row["case_id"]: row for row in requests}
    email_user = {row["email"].lower(): row["user_id"] for row in identities}
    for row in audits:
        if row["field_name"] == "email":
            email_user.setdefault(row["old_value"].lower(), row["user_id"])
            email_user.setdefault(row["new_value"].lower(), row["user_id"])
    sample_owner = {}
    for row in link.load_csv("sample_output.csv"):
        for step in json.loads(row["steps_json"]):
            sample_owner.setdefault(step["resource_id"], row["case_id"])
    observations, _patterns, _unparsed = verify.load_observations(manifest)
    observations = [obs for obs in observations if obs.pattern not in link.EXCLUDED_PATTERNS]
    owners = burst.evidence_owners(observations, requests, identities, audits)
    for resource_id, case_id in burst.link_owners(activity, requests, identities, audits).items():
        owners.setdefault(resource_id, case_id)
    for row in activity:
        if row["event_type"] != "CLASSIFY_REQUEST":
            continue
        detail = row["details"].lower()
        matched = [
            request["case_id"]
            for request in requests
            if request["email"].lower() in detail or email_user.get(request["email"].lower(), "") in detail
        ]
        if len(matched) == 1:
            owners.setdefault(row["resource_id"], matched[0])
    known: dict[str, set[str]] = defaultdict(set)
    for resource_id, case_id in owners.items():
        known[case_id].add(resource_id)
    for resource_id, case_id in sample_owner.items():
        known[case_id].add(resource_id)
    return {
        "activity": activity,
        "manifest": manifest,
        "requests_by_id": requests_by_id,
        "email_user": email_user,
        "sample_owner": sample_owner,
        "owners": owners,
        "known": known,
    }


def label_resource(resource_id: str, ctx) -> str:
    sample = ctx["sample_owner"].get(resource_id, "")
    owner = ctx["owners"].get(resource_id, "")
    parts = []
    if sample:
        parts.append(f"sample={sample}")
    if owner and owner != sample:
        parts.append(f"owner={owner}")
    if not parts and owner:
        parts.append(f"owner={owner}")
    return " ".join(parts)


def print_evidence(ctx) -> None:
    section("1. Where the six analytics ids sit, and the collections around them")
    manifest = {row["file_id"]: row for row in ctx["manifest"]}
    locations = []
    for row in ctx["manifest"]:
        path = DATASET / row["file_path"]
        if path.suffix.lower() not in {".json", ".sql", ".log", ".txt"}:
            continue
        try:
            collections = list(iter_collections(path))
        except (OSError, json.JSONDecodeError):
            continue
        for collection, records in collections:
            for index, record in enumerate(records):
                resource_id = str(record.get("resource_id", ""))
                if resource_id in TARGETS:
                    locations.append((row, collection, records, index))
    print(f"occurrences: {len(locations)}")
    seen_files = []
    for row, collection, records, index in locations:
        resource_id = records[index]["resource_id"]
        previous_id = records[index - 1]["resource_id"] if index else ""
        next_id = records[index + 1]["resource_id"] if index + 1 < len(records) else ""
        print(
            f"{resource_id} in {row['file_id']} captured={row['captured_at']} "
            f"collection={collection} index={index}/{len(records) - 1}"
        )
        print(f"  self: {identity_hint(records[index])} {label_resource(resource_id, ctx)}")
        if previous_id:
            print(f"  prev: {previous_id} {identity_hint(records[index - 1])} {label_resource(previous_id, ctx)}")
        if next_id:
            print(f"  next: {next_id} {identity_hint(records[index + 1])} {label_resource(next_id, ctx)}")
        if row["file_id"] not in seen_files:
            seen_files.append(row["file_id"])

    for file_id in seen_files:
        row = manifest[file_id]
        path = DATASET / row["file_path"]
        print()
        print(f"FULL COLLECTION ORDER {file_id} {row['file_path']} captured={row['captured_at']}")
        for collection, records in iter_collections(path):
            print(f"  [{collection}] n={len(records)}")
            for index, record in enumerate(records):
                resource_id = str(record.get("resource_id", ""))
                print(f"    {index:02d} {resource_id} {identity_hint(record)} {label_resource(resource_id, ctx)}")

    capture_times = sorted({row["captured_at"] for row, _collection, _records, _index in locations})
    section("1b. Other evidence files captured at the same timestamp")
    for stamp in capture_times:
        companions = [
            row for row in ctx["manifest"]
            if row["captured_at"] == stamp and row["file_id"] not in seen_files
        ]
        print(f"\n{stamp} companions={len(companions)}")
        for row in companions:
            path = DATASET / row["file_path"]
            print(f"  {row['file_id']} {row['file_path']} origin={row['origin']}")
            if path.suffix.lower() not in {".json", ".sql", ".log", ".txt"}:
                continue
            try:
                collections = list(iter_collections(path))
            except (OSError, json.JSONDecodeError):
                print("    unreadable")
                continue
            for collection, records in collections:
                sequence = [
                    f"{record.get('resource_id')}({label_resource(str(record.get('resource_id')), ctx) or '-'})"
                    for record in records
                ]
                print(f"    {collection}: {sequence}")


def rows_for_cases(activity, case_ids, known) -> list[dict[str, str]]:
    resources = set()
    for case_id in case_ids:
        resources |= known[case_id]
    selected = []
    for row in activity:
        mentioned = set(RESOURCE_WORD.findall(row["details"]))
        if row["resource_id"] in resources or mentioned & resources:
            selected.append(row)
    return sorted(selected, key=lambda row: (row["event_time"], activity_number(row["activity_id"])))


def print_cohorts(ctx) -> None:
    section("2. Activity already tied to the focus cases, plus cohort status")
    activity_by_id = {row["activity_id"]: row for row in ctx["activity"]}
    for moment, case_ids in COHORTS.items():
        print(f"\n{moment}")
        for case_id in case_ids:
            request = ctx["requests_by_id"][case_id]
            resources = sorted(ctx["known"][case_id])
            anonymize = [
                row["activity_id"]
                for row in ctx["activity"]
                if row["event_type"] == "ANONYMIZE_RECORD" and row["resource_id"] in ctx["known"][case_id]
            ]
            print(
                f"  {case_id} user={ctx['email_user'].get(request['email'].lower(), '?')} "
                f"reported_status={request['reported_status']} requested_at={request['requested_at']} "
                f"known={resources or 'none'} anonymize={anonymize or 'none'}"
            )
        print("  timeline of activity rows that name one of those known resources:")
        timeline = rows_for_cases(ctx["activity"], case_ids, ctx["known"])
        if not timeline:
            print("    none")
        for row in timeline:
            owners = sorted(
                case_id for case_id in case_ids if row["resource_id"] in ctx["known"][case_id]
                or any(resource_id in ctx["known"][case_id] for resource_id in RESOURCE_WORD.findall(row["details"]))
            )
            print(
                f"    {row['activity_id']} {row['event_time']} {row['event_type']} "
                f"{row['resource_id']} result={row['reported_result']} cases={owners or '?'}"
            )
            print(f"      {row['details']}")
        burst_rows = account_burst(ctx, moment)
        if not burst_rows:
            continue
        numbers = [activity_number(row["activity_id"]) for row in burst_rows]
        print(f"  account-delete burst activity_id span {min(numbers)}..{max(numbers)}")
        for number in range(min(numbers), max(numbers) + 1):
            activity_id = f"activity_{number}"
            row = activity_by_id.get(activity_id)
            if row is None:
                print(f"    {activity_id} MISSING")
                continue
            marker = "BURST" if row in burst_rows or row["activity_id"] in {item["activity_id"] for item in burst_rows} else "BETWEEN"
            print(
                f"    {marker} {row['activity_id']} {row['event_time']} {row['event_type']} "
                f"{row['resource_id']} target={row['target_system']} result={row['reported_result']}"
            )
            if marker == "BETWEEN":
                print(f"      {row['details']}")


def account_burst(ctx, moment: str) -> list[dict[str, str]]:
    by_reported = defaultdict(list)
    for row in ctx["requests_by_id"].values():
        by_reported[row["reported_at"]].append(row)
    worker = [
        row for row in ctx["activity"]
        if row["source_system"] == "deletion_worker" and "Target resource:" not in row["details"]
    ]
    grouped = burst.align_bursts(
        burst.bursts_of([
            row for row in worker
            if row["event_type"] == "DELETE_RECORD" and row["target_system"] == "account_service"
        ]),
        by_reported,
        burst.ACCOUNT_WINDOW,
        70 * 60,
    )
    return grouped.get(moment, [])


def analytics_burst(ctx, moment: str) -> list[dict[str, str]]:
    by_reported = defaultdict(list)
    for row in ctx["requests_by_id"].values():
        by_reported[row["reported_at"]].append(row)
    worker = [
        row for row in ctx["activity"]
        if row["source_system"] == "deletion_worker" and "Target resource:" not in row["details"]
    ]
    grouped = burst.align_bursts(
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
    return grouped.get(moment, [])


def print_ids(ctx) -> None:
    section("3. activity_id and event_time for the three account bursts and analytics bursts")
    activity_by_id = {row["activity_id"]: row for row in ctx["activity"]}
    for moment in COHORTS:
        for family, rows in (
            ("account DELETE", account_burst(ctx, moment)),
            ("analytics ANONYMIZE success", analytics_burst(ctx, moment)),
        ):
            print(f"\n{moment} {family} n={len(rows)}")
            if not rows:
                continue
            numbers = []
            for row in rows:
                numbers.append(activity_number(row["activity_id"]))
                print(
                    f"  {row['activity_id']} {row['event_time']} {row['resource_id']} "
                    f"result={row['reported_result']} {label_resource(row['resource_id'], ctx)}"
                )
            missing = [number for number in range(min(numbers), max(numbers) + 1) if number not in set(numbers)]
            print(f"  consecutive={missing == []} gaps={missing or 'none'}")
            for number in missing:
                row = activity_by_id.get(f"activity_{number}")
                if row is None:
                    print(f"  gap activity_{number} has no row")
                    continue
                same_case = [
                    case_id for case_id, resources in ctx["known"].items()
                    if row["resource_id"] in resources
                    or any(resource_id in resources for resource_id in RESOURCE_WORD.findall(row["details"]))
                ]
                focus_hit = [case_id for case_id in same_case if case_id in COHORTS[moment]]
                print(
                    f"  gap {row['activity_id']} {row['event_time']} {row['event_type']} "
                    f"{row['resource_id']} target={row['target_system']} result={row['reported_result']} "
                    f"focus_cases={focus_hit or 'none'} any_case={same_case[:6] or 'none'}"
                )
                print(f"    {row['details']}")


def main() -> None:
    ctx = load_context()
    print_evidence(ctx)
    print_cohorts(ctx)
    print_ids(ctx)


if __name__ == "__main__":
    main()
