"""Test user_id snapshot order and the order of evidence-labeled account bursts.

Sample answers are a check beside an assignment. They do not decide it.
"""

from __future__ import annotations

import itertools
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
    "analytics_5335",
    "analytics_1895",
    "analytics_4566",
    "analytics_4574",
    "analytics_6077",
    "analytics_9406",
]
SEP5 = [
    "case_21",
    "case_23",
    "case_536",
    "case_546",
    "case_547",
    "case_548",
]
USER_RE = re.compile(r"user_(\d+)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RESOURCE_RE = re.compile(
    r"\b(?:account|analytics|search|export|support|data_flow|backup|audit_record|tombstone)_\d+\b"
)


def section(title: str) -> None:
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def case_number(case_id: str) -> int:
    return int(case_id.split("_")[1])


def activity_number(activity_id: str) -> int:
    return int(activity_id.split("_")[1])


def resource_number(resource_id: str) -> int:
    match = re.search(r"_(\d+)$", resource_id)
    return int(match.group(1)) if match else 10**9


def iter_collections(path: Path):
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("snapshots"), list):
            for snap in payload["snapshots"]:
                yield f"{snap.get('captured_at')} {snap.get('data_store')} {snap.get('collection')}", list(snap.get("records") or [])
        if isinstance(payload, dict) and isinstance(payload.get("service_exports"), dict):
            for service, block in payload["service_exports"].items():
                if not isinstance(block, dict):
                    continue
                for name, records in block.items():
                    if isinstance(records, list):
                        yield f"{service} {name}", list(records)
        return
    if path.suffix.lower() == ".sql":
        buckets: dict[str, list[dict]] = defaultdict(list)
        current = None
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            table = re.search(r"INSERT INTO\s+([A-Za-z0-9_]+)", line, flags=re.I)
            if table:
                current = table.group(1)
            if current is None:
                continue
            found = RESOURCE_RE.findall(line)
            if found:
                buckets[current].append({"resource_id": found[0], "line": line.strip()})
        for name, records in buckets.items():
            yield name, records
        return
    if path.suffix.lower() in {".log", ".txt"}:
        records = []
        for index, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            found = RESOURCE_RE.findall(line)
            if found:
                records.append({"resource_id": found[0], "line_no": index, "line": line.strip()})
        if records:
            yield path.name, records


def blob(record: dict) -> str:
    if "line" in record:
        return record["line"]
    return json.dumps(record, default=str)


def on_record_users(record: dict) -> list[int]:
    return [int(value) for value in USER_RE.findall(blob(record))]


def anonymous(record: dict) -> bool:
    text = blob(record)
    return not USER_RE.search(text) and not EMAIL_RE.search(text)


def collapse(records: list[dict]) -> list[dict]:
    collapsed = []
    for record in records:
        if collapsed and collapsed[-1].get("resource_id") == record.get("resource_id"):
            continue
        collapsed.append(record)
    return collapsed


def is_sorted(values: list[int]) -> bool:
    return values == sorted(values)


def load_context():
    identities = link.load_csv("user_identities.csv")
    audits = link.load_csv("user_audit_log.csv")
    activity = link.load_csv("system_activity.csv")
    manifest = link.load_csv("evidence_files.csv")
    sample_requests = link.load_csv("sample_deletion_requests.csv")
    eval_requests = link.load_csv("deletion_requests.csv")
    requests = sample_requests + eval_requests
    identity_by_user = {row["user_id"]: row for row in identities}
    identity_index = {row["user_id"]: index for index, row in enumerate(identities)}
    request_index = {row["case_id"]: index for index, row in enumerate(requests)}
    email_user = {row["email"].lower(): row["user_id"] for row in identities}
    for row in audits:
        if row["field_name"] == "email":
            email_user.setdefault(row["old_value"].lower(), row["user_id"])
            email_user.setdefault(row["new_value"].lower(), row["user_id"])
    requests_by_id = {row["case_id"]: row for row in requests}
    user_case = {}
    for row in requests:
        user_id = email_user.get(row["email"].lower(), "")
        if user_id:
            user_case.setdefault(user_id, row["case_id"])
    sample_owner = {}
    for row in link.load_csv("sample_output.csv"):
        for step in json.loads(row["steps_json"]):
            sample_owner.setdefault(step["resource_id"], row["case_id"])
    observations, _patterns, _unparsed = verify.load_observations(manifest)
    observations = [obs for obs in observations if obs.pattern not in link.EXCLUDED_PATTERNS]
    owners = burst.evidence_owners(observations, requests, identities, audits)
    for resource_id, case_id in burst.link_owners(activity, requests, identities, audits).items():
        owners.setdefault(resource_id, case_id)
    return {
        "identities": identities,
        "identity_by_user": identity_by_user,
        "identity_index": identity_index,
        "request_index": request_index,
        "email_user": email_user,
        "requests": requests,
        "requests_by_id": requests_by_id,
        "user_case": user_case,
        "activity": activity,
        "manifest": manifest,
        "sample_owner": sample_owner,
        "owners": owners,
    }


def case_user(ctx, case_id: str) -> tuple[str, int]:
    request = ctx["requests_by_id"][case_id]
    user_id = ctx["email_user"].get(request["email"].lower(), "")
    number = int(user_id.split("_")[1]) if user_id.startswith("user_") else 10**9
    return user_id, number


def known_resources(ctx) -> dict[str, set[str]]:
    owned: dict[str, set[str]] = defaultdict(set)
    for resource_id, case_id in ctx["owners"].items():
        owned[case_id].add(resource_id)
    for row in ctx["activity"]:
        if row["event_type"] != "CLASSIFY_REQUEST":
            continue
        detail = row["details"].lower()
        matched = [
            request["case_id"]
            for request in ctx["requests"]
            if request["email"].lower() in detail or ctx["email_user"].get(request["email"].lower(), "") in detail
        ]
        if len(matched) == 1:
            owned[matched[0]].add(row["resource_id"])
    return owned


def print_collections(ctx) -> dict[str, list[tuple[str, str, list[dict]]]]:
    section("1. Collection order across snapshot bundles, JSON, SQL, and logs")
    grouped: dict[str, list[tuple[str, str, list[dict]]]] = defaultdict(list)
    multi = 0
    user_sorted = 0
    user_checked = 0
    number_sorted = 0
    null_collections = 0
    mixed_anchor = []
    for row in ctx["manifest"]:
        path = DATASET / row["file_path"]
        if path.suffix.lower() not in {".json", ".sql", ".log", ".txt"}:
            continue
        try:
            collections = list(iter_collections(path))
        except (OSError, json.JSONDecodeError):
            continue
        for label, records in collections:
            records = collapse(records)
            grouped[row["file_id"]].append((row["captured_at"], label, records))
            if len(records) < 2:
                continue
            multi += 1
            users = [on_record_users(record) for record in records]
            known = [found[0] for found in users if found]
            numbers = [resource_number(str(record.get("resource_id", ""))) for record in records]
            if len(known) >= 2:
                user_checked += 1
                if is_sorted(known):
                    user_sorted += 1
            if is_sorted(numbers):
                number_sorted += 1
            nulls = sum(anonymous(record) for record in records)
            if nulls:
                null_collections += 1
            if nulls and known:
                sequence = []
                for record, found in zip(records, users):
                    sequence.append(f"user_{found[0]}" if found else str(record.get("resource_id")))
                mixed_anchor.append((row["file_id"], label, nulls, len(records), sequence))
    print(f"multi-row collections: {multi}")
    print(f"with 2+ on-record user ids: {user_checked}, already in user_id order: {user_sorted}")
    print(f"already in resource-number order: {number_sorted}")
    print(f"collections containing an anonymous record: {null_collections}")
    print()
    print("anonymous records sitting in a collection that also names a user:")
    for file_id, label, nulls, size, sequence in mixed_anchor:
        print(f"  {file_id} {label} anonymous={nulls}/{size}")
        print(f"    {sequence}")
    return grouped


def fills(population: list[int], known: list[int | None]) -> list[list[int]]:
    """Every subsequence of population whose anchored positions match."""
    size = len(known)
    if size == 0 or size > len(population) or len(population) > 16:
        return []
    found = []
    for choice in itertools.combinations(population, size):
        if all(user is None or user == choice[index] for index, user in enumerate(known)):
            found.append(list(choice))
    return found


def print_targets(ctx, grouped) -> None:
    section("2. Does user_id order name the six analytics resources?")
    population_by_file: dict[str, list[int]] = {}
    for file_id, collections in grouped.items():
        users = []
        for _stamp, _label, records in collections:
            for record in records:
                users.extend(on_record_users(record))
        population_by_file[file_id] = sorted(set(users))
    sample = ctx["sample_owner"]
    for file_id, collections in grouped.items():
        hits = []
        for stamp, label, records in collections:
            if any(str(record.get("resource_id")) in TARGETS for record in records):
                hits.append((stamp, label, records))
        if not hits:
            continue
        population = population_by_file[file_id]
        print(f"\n{file_id} sibling users={['user_' + str(user) for user in population]}")
        for _stamp, label, records in hits:
            known = []
            print(f"  {label} n={len(records)}")
            for index, record in enumerate(records):
                resource_id = str(record.get("resource_id"))
                users = on_record_users(record)
                known.append(users[0] if users else None)
                print(
                    f"    {index:02d} {resource_id} on_record={users or 'anonymous'} "
                    f"sample={sample.get(resource_id, '-')}"
                )
            matched = fills(population, known)
            consistent = []
            for choice in matched:
                pairs = []
                ok = True
                for user, record in zip(choice, records):
                    resource_id = str(record.get("resource_id"))
                    case_id = ctx["user_case"].get(f"user_{user}", "?")
                    expected = sample.get(resource_id)
                    if expected and expected != case_id:
                        ok = False
                    if resource_id in TARGETS:
                        pairs.append(f"{resource_id}->user_{user}/{case_id}")
                if ok:
                    consistent.append(pairs)
            print(f"    anchor-respecting subsequences: {len(matched)}; sample-consistent: {len(consistent)}")
            for pairs in consistent[:4]:
                print("      " + ", ".join(pairs))


def cohort_bursts(ctx):
    by_reported = defaultdict(list)
    for row in ctx["requests"]:
        by_reported[row["reported_at"]].append(row)
    worker = [
        row for row in ctx["activity"]
        if row["source_system"] == "deletion_worker" and "Target resource:" not in row["details"]
    ]
    accounts = burst.align_bursts(
        burst.bursts_of([
            row for row in worker
            if row["event_type"] == "DELETE_RECORD" and row["target_system"] == "account_service"
        ]),
        by_reported,
        burst.ACCOUNT_WINDOW,
        70 * 60,
    )
    analytics = burst.align_bursts(
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
    return by_reported, accounts, analytics


def sort_value(name: str, row: dict, ctx, owned: dict[str, set[str]]):
    user_id, number = case_user(ctx, row["case_id"])
    identity = ctx["identity_by_user"].get(user_id, {})
    resources = owned.get(row["case_id"], set())
    tombstones = sorted(resource_number(resource_id) for resource_id in resources if resource_id.startswith("tombstone_"))
    tombstone = tombstones[0] if tombstones else 10**9
    if name == "user_id":
        return (number, case_number(row["case_id"]))
    if name == "requested_at":
        return (row["requested_at"], case_number(row["case_id"]))
    if name == "case_id":
        return (case_number(row["case_id"]),)
    if name == "identity_row":
        return (ctx["identity_index"].get(user_id, 10**9), case_number(row["case_id"]))
    if name == "request_row":
        return (ctx["request_index"].get(row["case_id"], 10**9),)
    if name == "updated_at":
        return (identity.get("updated_at", ""), case_number(row["case_id"]))
    if name == "status_requested":
        return (row["reported_status"], row["requested_at"], case_number(row["case_id"]))
    if name == "tombstone_then_user":
        return (0 if tombstones else 1, tombstone, number)
    return (case_number(row["case_id"]),)


def print_analytics_bursts(ctx, owned) -> None:
    section("3. Analytics bursts zipped with cohort order")
    by_reported, _accounts, analytics = cohort_bursts(ctx)
    keys = (
        "user_id",
        "requested_at",
        "case_id",
        "identity_row",
        "request_row",
        "updated_at",
        "status_requested",
        "tombstone_then_user",
    )
    print("A zip is attempted only when the ordered case list has the same length as the burst.")
    for moment, rows in sorted(analytics.items()):
        cohort = by_reported[moment]
        interesting = any(row["resource_id"] in TARGETS for row in rows)
        if not interesting and len(rows) < 2:
            continue
        if not interesting and not any(ctx["sample_owner"].get(row["resource_id"]) for row in rows):
            continue
        print(f"\n{moment} burst={[row['resource_id'] for row in rows]}")
        subsets = {
            "all": cohort,
            "no_tombstone": [
                row for row in cohort
                if not any(resource_id.startswith("tombstone_") for resource_id in owned[row["case_id"]])
            ],
            "has_tombstone": [
                row for row in cohort
                if any(resource_id.startswith("tombstone_") for resource_id in owned[row["case_id"]])
            ],
            "status_COMPLETE": [row for row in cohort if row["reported_status"] == "COMPLETE"],
            "status_NOT_STARTED": [row for row in cohort if row["reported_status"] == "NOT_STARTED"],
            "status_PARTIALLY_COMPLETE": [row for row in cohort if row["reported_status"] == "PARTIALLY_COMPLETE"],
        }
        print("  subset sizes: " + ", ".join(f"{name}={len(members)}" for name, members in subsets.items()))
        for subset_name, members in subsets.items():
            for name in keys:
                ordered = sorted(members, key=lambda row: sort_value(name, row, ctx, owned))
                if len(ordered) != len(rows):
                    continue
                pairs = []
                mismatches = 0
                for case, row in zip(ordered, rows):
                    expected = ctx["sample_owner"].get(row["resource_id"])
                    mark = ""
                    if expected:
                        mark = " ok" if expected == case["case_id"] else " DIFFERS"
                        mismatches += expected != case["case_id"]
                    pairs.append(f"{row['resource_id']}->{case['case_id']}{mark}")
                print(f"  {subset_name} by {name}: {', '.join(pairs)} mismatches={mismatches}")


def print_sep5(ctx, owned) -> None:
    section("4. The six 2026-09-05 cases and the delete slots")
    by_reported, accounts, _analytics = cohort_bursts(ctx)
    moment = "2026-09-05T12:00:00Z"
    for case_id in SEP5:
        request = ctx["requests_by_id"][case_id]
        user_id, _number = case_user(ctx, case_id)
        identity = ctx["identity_by_user"].get(user_id, {})
        resources = sorted(owned[case_id])
        print(
            f"{case_id} user={user_id} identity_row={ctx['identity_index'].get(user_id)} "
            f"request_row={ctx['request_index'].get(case_id)}"
        )
        print(
            f"  name={identity.get('name', '')} email={identity.get('email', request['email'])} "
            f"phone={identity.get('phone', '')}"
        )
        print(
            f"  email_hash={identity.get('email_hash', '')} updated_at={identity.get('updated_at', '')}"
        )
        print(
            f"  requested_at={request['requested_at']} reported_status={request['reported_status']} "
            f"audit_at={request['audit_at']}"
        )
        print(f"  linked={resources or 'none'}")
        related = [
            row for row in ctx["activity"]
            if row["resource_id"] in owned[case_id]
            or any(resource_id in owned[case_id] for resource_id in RESOURCE_RE.findall(row["details"]))
        ]
        if not related:
            print("  activity=none")
        for row in sorted(related, key=lambda item: activity_number(item["activity_id"])):
            print(
                f"  activity {row['activity_id']} {row['event_time']} {row['event_type']} "
                f"{row['resource_id']} result={row['reported_result']}"
            )
    print()
    burst_rows = accounts.get(moment, [])
    print("delete slots:")
    for index, row in enumerate(burst_rows):
        print(
            f"  [{index}] {row['activity_id']} {row['event_time']} {row['resource_id']} "
            f"result={row['reported_result']} sample={ctx['sample_owner'].get(row['resource_id'], '-')}"
        )
    print()
    print("order of the six cases under each key:")
    cohort = [ctx["requests_by_id"][case_id] for case_id in SEP5]
    for name in (
        "user_id",
        "requested_at",
        "case_id",
        "identity_row",
        "request_row",
        "updated_at",
        "status_requested",
        "tombstone_then_user",
    ):
        ordered = sorted(cohort, key=lambda row: sort_value(name, row, ctx, owned))
        rendered = []
        for row in ordered:
            user_id, _number = case_user(ctx, row["case_id"])
            tombstones = sorted(
                resource_id for resource_id in owned[row["case_id"]] if resource_id.startswith("tombstone_")
            )
            rendered.append(f"{row['case_id']}({user_id},{row['reported_status']},tomb={tombstones or '-'})")
        positions = {row["case_id"]: index for index, row in enumerate(ordered)}
        print(f"  {name}: case_21 at {positions['case_21']}, case_23 at {positions['case_23']}")
        print("    " + ", ".join(rendered))


def print_labeled_bursts(ctx) -> None:
    section("5. Account bursts whose every account is known from evidence or LINK")
    by_reported, accounts, _analytics = cohort_bursts(ctx)
    evidence_only = {
        resource_id: case_id
        for resource_id, case_id in ctx["owners"].items()
    }
    keys = (
        "user_id",
        "requested_at",
        "case_id",
        "identity_row",
        "request_row",
        "updated_at",
        "status_requested",
        "tombstone_then_user",
    )
    labeled = []
    for moment, rows in accounts.items():
        owners = [evidence_only.get(row["resource_id"]) for row in rows]
        if not owners or any(owner is None for owner in owners):
            continue
        if len(set(owners)) != len(owners):
            continue
        labeled.append((moment, rows, owners))
    multi = [item for item in labeled if len(item[2]) >= 2]
    print(f"fully labeled account bursts: {len(labeled)}")
    print(f"of those, multi-case: {len(multi)}")
    owned = known_resources(ctx)
    match_counts = {name: 0 for name in keys}
    for _moment, rows, owners in multi:
        cohort = [ctx["requests_by_id"][case_id] for case_id in owners]
        for name in keys:
            ordered = [row["case_id"] for row in sorted(cohort, key=lambda row: sort_value(name, row, ctx, owned))]
            if ordered == owners:
                match_counts[name] += 1
    print("multi-case bursts whose sort equals the delete order:")
    for name, count in match_counts.items():
        print(f"  {name}: {count}/{len(multi)}")
    print()
    print("10 multi-case examples:")
    for moment, rows, owners in multi[:10]:
        print(f"  {moment}")
        for row, case_id in zip(rows, owners):
            request = ctx["requests_by_id"][case_id]
            user_id, _number = case_user(ctx, case_id)
            identity = ctx["identity_by_user"].get(user_id, {})
            print(
                f"    {row['event_time']} {row['resource_id']} -> {case_id} {user_id} "
                f"requested_at={request['requested_at']} status={request['reported_status']} "
                f"updated_at={identity.get('updated_at', '')} "
                f"identity_row={ctx['identity_index'].get(user_id)} request_row={ctx['request_index'].get(case_id)}"
            )


def main() -> None:
    ctx = load_context()
    grouped = print_collections(ctx)
    print_targets(ctx, grouped)
    owned = known_resources(ctx)
    print_analytics_bursts(ctx, owned)
    print_sep5(ctx, owned)
    print_labeled_bursts(ctx)


if __name__ == "__main__":
    main()
