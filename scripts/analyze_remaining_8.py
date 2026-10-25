"""Compare the last eight sample misses and correct absence citations.

Sample answers are a check after a rule is applied. They are not the rule.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import crack_remaining_16 as crack  # noqa: E402
import deep_check_unlinked as deep  # noqa: E402
import solve_burst_assignment as burst  # noqa: E402
import solve_resource_linking as link  # noqa: E402

verify = link.verify
DATASET = link.DATASET

LISTED = [
    "case_01",
    "case_02",
    "case_04",
    "case_10",
    "case_19",
    "case_22",
    "case_24",
    "case_26",
    "case_30",
    "case_31",
]
REMAINING = [
    "case_18",
    "case_20",
    "case_21",
    "case_22",
    "case_23",
    "case_25",
    "case_26",
    "case_31",
]
NEEDLES = [
    "account_6829",
    "account_4990",
    "account_6440",
    "account_410",
    "account_294",
    "account_8832",
    "account_7015",
    "account_9155",
    "analytics_1895",
    "analytics_4566",
    "analytics_5335",
]
FOCUS = (
    "2026-09-01T10:00:00Z",
    "2026-09-02T12:00:00Z",
    "2026-09-05T12:00:00Z",
)


def section(title: str) -> None:
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def case_number(case_id: str) -> int:
    return int(case_id.split("_")[1])


def sql_tables(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    names = re.findall(r"CREATE TABLE(?: IF NOT EXISTS)?\s+([A-Za-z0-9_]+)", text, flags=re.I)
    if names:
        return names
    return sorted(set(re.findall(r"INSERT INTO\s+([A-Za-z0-9_]+)", text, flags=re.I)))


def snapshot_shape(path: Path) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    lines = []
    for snap in payload.get("snapshots") or []:
        records = snap.get("records") or []
        prefixes = Counter(str(rec.get("resource_id", "")).split("_")[0] or "?" for rec in records)
        lines.append(
            f"{snap.get('captured_at')} {snap.get('data_store')} {snap.get('collection')} "
            f"n={len(records)} {dict(prefixes) or 'empty'}"
        )
    return lines


def account_absence(steps: list[dict]) -> list[tuple[str, str, str]]:
    return [
        (step["operation"], step["resource_id"], step["evidence_id"])
        for step in steps
        if step["system_id"] == "account_service" and "ABSENT" in step["state"]
    ]


def load_context():
    identities = link.load_csv("user_identities.csv")
    audits = link.load_csv("user_audit_log.csv")
    activity = link.load_csv("system_activity.csv")
    manifest = link.load_csv("evidence_files.csv")
    sample_requests = link.load_csv("sample_deletion_requests.csv")
    eval_requests = link.load_csv("deletion_requests.csv")
    requests = sample_requests + eval_requests
    requests_by_id = {row["case_id"]: row for row in requests}
    identity_by_user = {row["user_id"]: row for row in identities}
    identity_index = {row["user_id"]: index for index, row in enumerate(identities)}
    email_user = {row["email"].lower(): row["user_id"] for row in identities}
    for row in audits:
        if row["field_name"] == "email":
            email_user.setdefault(row["old_value"].lower(), row["user_id"])
            email_user.setdefault(row["new_value"].lower(), row["user_id"])
    sample_outputs = {row["case_id"]: row for row in link.load_csv("sample_output.csv")}
    observations, _patterns, _unparsed = verify.load_observations(manifest)
    observations = [obs for obs in observations if obs.pattern not in link.EXCLUDED_PATTERNS]
    return {
        "identities": identities,
        "audits": audits,
        "activity": activity,
        "manifest": manifest,
        "sample_requests": sample_requests,
        "requests": requests,
        "requests_by_id": requests_by_id,
        "identity_by_user": identity_by_user,
        "identity_index": identity_index,
        "email_user": email_user,
        "sample_outputs": sample_outputs,
        "observations": observations,
    }


def print_absence(ctx) -> None:
    section("1. evidence_51 versus evidence_54, and every listed account absence")
    manifest = {row["file_id"]: row for row in ctx["manifest"]}
    for file_id in ("evidence_51", "evidence_54", "evidence_02", "evidence_92"):
        row = manifest[file_id]
        path = DATASET / row["file_path"]
        print(f"{row['file_id']} path={row['file_path']}")
        print(f"  origin={row['origin']} captured_at={row['captured_at']}")
        if path.suffix.lower() == ".json" and "snapshot" in path.name:
            for line in snapshot_shape(path):
                print(f"  snapshot {line}")
        elif path.suffix.lower() == ".sql":
            print(f"  sql tables={sql_tables(path)}")
        else:
            print(f"  kind={path.suffix}")
    print()
    print("empty customer_profiles censuses (the new absence candidates):")
    for file_id, stamp in crack.empty_account_censuses():
        print(f"  {file_id} snapshot_captured_at={stamp}")
    print()
    print("listed cases. Sample status is printed from sample_output, not assumed.")
    print("rule_file is the fallback census. A direct in-time observation still wins over it.")
    for case_id in LISTED:
        request = ctx["requests_by_id"][case_id]
        output = ctx["sample_outputs"][case_id]
        steps = json.loads(output["steps_json"])
        cited = account_absence(steps)
        resource_id = next((item[1] for item in cited if item[1].startswith("account_")), "")
        proof = None
        if resource_id:
            proof = crack.latest_absence(
                ctx["observations"],
                link.parse_time(request["audit_at"]),
                resource_id,
            )
        print(
            f"  {case_id} status={output['deletion_status']} audit_at={request['audit_at']} "
            f"account_steps={cited or 'none'} rule_file={proof[0] if proof else 'none'}"
        )


def analytics_table(ctx) -> None:
    section("2. Which of the 32 samples have an analytics step")
    rows = []
    for request in ctx["sample_requests"]:
        output = ctx["sample_outputs"][request["case_id"]]
        steps = json.loads(output["steps_json"])
        systems = sorted({step["system_id"] for step in steps})
        analytics = sorted({step["resource_id"] for step in steps if step["resource_id"].startswith("analytics_")})
        user_id = ctx["email_user"].get(request["email"].lower(), "")
        identity = ctx["identity_by_user"].get(user_id, {})
        text = request["request_text"].lower()
        rows.append(
            {
                "case_id": request["case_id"],
                "has": bool(analytics),
                "analytics": analytics,
                "status": output["deletion_status"],
                "reported": request["reported_status"],
                "user_id": user_id,
                "user_no": int(user_id.split("_")[1]) if user_id.startswith("user_") else -1,
                "identity_row": ctx["identity_index"].get(user_id, -1),
                "updated_at": identity.get("updated_at", ""),
                "requested_at": request["requested_at"],
                "reported_at": request["reported_at"],
                "audit_at": request["audit_at"],
                "systems": systems,
                "mentions_analytics": "analytic" in text,
                "mentions_search": "search" in text,
                "mentions_export": "export" in text,
                "mentions_account": "account" in text or "compte" in text or "cuenta" in text,
                "text": request["request_text"],
            }
        )
    print("HAS analytics:")
    for row in rows:
        if row["has"]:
            print(
                f"  {row['case_id']} {row['analytics']} reported={row['reported']} "
                f"status={row['status']} user={row['user_id']} audit={row['audit_at']} "
                f"systems={row['systems']}"
            )
            print(f"    text: {row['text']}")
    print("NO analytics:")
    for row in rows:
        if not row["has"]:
            print(
                f"  {row['case_id']} reported={row['reported']} status={row['status']} "
                f"user={row['user_id']} audit={row['audit_at']} systems={row['systems']}"
            )
    print()
    print("feature contrast (analytics cases vs the other sample cases):")
    yes = [row for row in rows if row["has"]]
    no = [row for row in rows if not row["has"]]
    for name in (
        "mentions_analytics",
        "mentions_search",
        "mentions_export",
        "mentions_account",
    ):
        print(f"  {name}: yes-group {sum(row[name] for row in yes)}/{len(yes)}  no-group {sum(row[name] for row in no)}/{len(no)}")
    for system in ("search_service", "export_service", "integration_service", "account_service", "security_service"):
        print(
            f"  step {system}: yes-group {sum(system in row['systems'] for row in yes)}/{len(yes)}  "
            f"no-group {sum(system in row['systems'] for row in no)}/{len(no)}"
        )
    print("  reported_status among analytics:", Counter(row["reported"] for row in yes))
    print("  reported_status among others:   ", Counter(row["reported"] for row in no))
    print("  deletion_status among analytics:", Counter(row["status"] for row in yes))
    print("  deletion_status among others:   ", Counter(row["status"] for row in no))
    print("  user numbers with analytics:", sorted(row["user_no"] for row in yes))
    print("  audit dates with analytics:", sorted({row["audit_at"][:10] for row in yes}))
    print("  audit dates without analytics:", sorted({row["audit_at"][:10] for row in no}))


def activity_hits(activity: list[dict[str, str]], needle: str) -> list[dict[str, str]]:
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(needle)}(?![A-Za-z0-9_])")
    return [
        row
        for row in activity
        if row["resource_id"] == needle or pattern.search(row["details"]) or pattern.search(row.get("target_system", ""))
    ]


def print_sep5_and_needles(ctx) -> None:
    section("3. 2026-09-05 account deletes, nearby reported_at, and every activity hit")
    activity = ctx["activity"]
    moment = datetime.fromisoformat("2026-09-05T12:00:00+00:00")
    account_deletes = [
        row
        for row in activity
        if row["event_type"] == "DELETE_RECORD"
        and row["target_system"] == "account_service"
        and row["event_time"].startswith("2026-09-05")
    ]
    print(f"account DELETE_RECORD rows on 2026-09-05: {len(account_deletes)}")
    for row in account_deletes:
        print(
            f"  {row['activity_id']} event_time={row['event_time']} resource={row['resource_id']} "
            f"result={row['reported_result']} source={row['source_system']}"
        )
    print()
    print("requests whose reported_at is within 2 hours of 2026-09-05T12:00:00Z:")
    near = []
    for row in ctx["requests"]:
        reported = link.parse_time(row["reported_at"])
        delta = abs((reported - moment).total_seconds())
        if delta <= 2 * 3600:
            near.append((delta, row))
    if not near:
        print("  none")
    for delta, row in sorted(near, key=lambda item: (item[0], case_number(item[1]["case_id"]))):
        print(
            f"  {row['case_id']} reported_at={row['reported_at']} delta={delta:.0f}s "
            f"status={row['reported_status']} requested_at={row['requested_at']}"
        )
    print()
    print(f"searched all {len(activity)} activity rows, resource_id and details, word boundary:")
    for needle in NEEDLES:
        hits = activity_hits(activity, needle)
        if not hits:
            print(f"  {needle}: no activity row")
            continue
        print(f"  {needle}: {len(hits)} row(s)")
        for row in hits:
            print(
                f"    {row['activity_id']} {row['event_time']} {row['event_type']} "
                f"resource={row['resource_id']} target={row['target_system']} result={row['reported_result']}"
            )
            print(f"      {row['details']}")


def sort_keys(row, identity_index, email_user):
    user_id = email_user.get(row["email"].lower(), "")
    return {
        "status_requested": (row["reported_status"], row["requested_at"], case_number(row["case_id"])),
        "status_case": (row["reported_status"], case_number(row["case_id"])),
        "identity_file": (identity_index.get(user_id, 10**9), case_number(row["case_id"])),
        "case_id": (case_number(row["case_id"]),),
        "requested_at": (row["requested_at"], case_number(row["case_id"])),
    }


def print_order(ctx) -> None:
    section("4. Burst order against status, case_id, and identity-file order")
    activity = ctx["activity"]
    requests = ctx["requests"]
    by_reported: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in requests:
        by_reported[row["reported_at"]].append(row)
    worker = [
        row
        for row in activity
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
    sample_owner = {}
    for row in ctx["sample_outputs"].values():
        for step in json.loads(row["steps_json"]):
            sample_owner[step["resource_id"]] = row["case_id"]

    def render(moment: str, family: str, bursts: dict[str, list[dict[str, str]]]) -> None:
        rows = bursts.get(moment, [])
        cohort = by_reported.get(moment, [])
        print(f"\n{moment} {family} burst n={len(rows)} cohort n={len(cohort)}")
        for index, row in enumerate(rows):
            owner = sample_owner.get(row["resource_id"], "")
            print(f"  [{index}] {row['event_time']} {row['resource_id']} sample={owner or 'not in the 32'}")
        for name in ("status_requested", "status_case", "identity_file", "case_id", "requested_at"):
            ordered = sorted(cohort, key=lambda item: sort_keys(item, ctx["identity_index"], ctx["email_user"])[name])
            rendered = ", ".join(
                f"{row['case_id']}:{row['reported_status']}" for row in ordered
            )
            print(f"  sort {name}: {rendered}")

    for moment in FOCUS:
        render(moment, "account", account_bursts)
        render(moment, "analytics", analytics_bursts)

    print()
    print("multi-row account bursts whose every resource is a distinct sample case in that reported_at:")
    labeled = 0
    for moment, rows in sorted(account_bursts.items()):
        owners = [sample_owner.get(row["resource_id"]) for row in rows]
        if len(rows) < 2 or any(owner is None for owner in owners) or len(set(owners)) != len(owners):
            continue
        cohort = [row for row in by_reported[moment] if row["case_id"] in set(owners)]
        if len(cohort) != len(owners):
            continue
        labeled += 1
        print(f"  {moment} burst={owners}")
        for name in ("status_requested", "status_case", "identity_file", "case_id", "requested_at"):
            ordered = [
                row["case_id"]
                for row in sorted(cohort, key=lambda item: sort_keys(item, ctx["identity_index"], ctx["email_user"])[name])
            ]
            print(f"    {name} {'MATCH' if ordered == owners else 'differs'}: {ordered}")
    if labeled == 0:
        print("  none")


def rescore_case_id(ctx) -> None:
    section("5. Rescore the 32 samples with the case_id leftover zip and the new absence rule")
    print("This is the same unfinalized pairing as the 24/32 run. It is a check, not a shipped rule.")
    requests = ctx["requests"]
    activity = ctx["activity"]
    observations = ctx["observations"]
    email_user = ctx["email_user"]
    identified = burst.evidence_owners(observations, requests, ctx["identities"], ctx["audits"])
    for resource_id, case_id in burst.link_owners(activity, requests, ctx["identities"], ctx["audits"]).items():
        identified.setdefault(resource_id, case_id)
    classified = {
        row["resource_id"]
        for row in activity
        if row["event_type"] == "CLASSIFY_REQUEST" and "non-deletion" in row["details"]
    }
    worker = [row for row in activity if row["source_system"] == "deletion_worker"]
    singleton = crack.singleton_account_owners(
        [row for row in worker if "Target resource:" not in row["details"]],
        requests,
    )
    reported_rows = [(row, link.parse_time(row["reported_at"])) for row in requests]

    def unique_owner(event_time: datetime):
        ranked = sorted(reported_rows, key=lambda item: abs((item[1] - event_time).total_seconds()))
        best_row, best_at = ranked[0]
        best_delta = abs((best_at - event_time).total_seconds())
        second = abs((ranked[1][1] - event_time).total_seconds())
        if best_delta <= link.WINDOW.total_seconds() and second > best_delta + 1:
            return best_row
        return None

    satisfied: dict[str, set[str]] = defaultdict(set)
    for resource_id, case_id in identified.items():
        satisfied[case_id].add(resource_id)
    for resource_id, case_id in singleton.items():
        satisfied[case_id].add(resource_id)
    for row in worker:
        if "Target resource:" not in row["details"]:
            continue
        event = link.parse_time(row["event_time"])
        owner = unique_owner(event)
        if owner is None:
            continue
        if link.parse_time(owner["requested_at"]) <= event <= link.parse_time(owner["audit_at"]):
            satisfied[owner["case_id"]].add(row["resource_id"])
    for row in requests:
        user = email_user.get(row["email"].lower(), "")
        match = re.fullmatch(r"user_(\d+)", user)
        if not match or not 1 <= int(match.group(1)) <= 10:
            continue
        if any(resource_id.startswith("account_") for resource_id in satisfied[row["case_id"]]):
            continue
        satisfied[row["case_id"]].add(f"account_{int(match.group(1)):03d}")
    taken = {resource_id for resources in satisfied.values() for resource_id in resources}

    def is_deletion(row: dict[str, str]) -> bool:
        if any(resource_id in classified for resource_id in satisfied[row["case_id"]]):
            return False
        return deep.authorizes_deletion(row["request_text"])

    by_reported: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in requests:
        by_reported[row["reported_at"]].append(row)
    plain_worker = [row for row in worker if "Target resource:" not in row["details"]]
    families = {
        "account": burst.align_bursts(
            burst.bursts_of([
                row for row in plain_worker
                if row["event_type"] == "DELETE_RECORD" and row["target_system"] == "account_service"
            ]),
            by_reported,
            burst.ACCOUNT_WINDOW,
            70 * 60,
        ),
        "analytics": burst.align_bursts(
            burst.bursts_of([
                row for row in plain_worker
                if row["event_type"] == "ANONYMIZE_RECORD"
                and row["target_system"] == "analytics_platform"
                and row["reported_result"] == "SUCCESS"
            ]),
            by_reported,
            burst.ANALYTICS_WINDOW,
            29 * 60,
        ),
    }
    extras = []
    for moment, cohort in by_reported.items():
        for family, prefix in (("account", "account_"), ("analytics", "analytics_")):
            rows = families[family].get(moment, [])
            waiting = [
                row for row in cohort
                if is_deletion(row)
                and not any(resource_id.startswith(prefix) for resource_id in satisfied[row["case_id"]])
            ]
            unknown = [row for row in rows if row["resource_id"] not in taken]
            if len(waiting) != len(unknown) or not waiting:
                continue
            ordered = sorted(waiting, key=lambda row: case_number(row["case_id"]))
            for case, row in zip(ordered, unknown):
                system_id = "account_service" if family == "account" else "analytics_platform"
                category = "USER_PROFILE" if family == "account" else "ANALYTICS_PROFILE"
                extras.append(verify.Obs(
                    file_id="",
                    captured_at="2099-01-01T00:00:00Z",
                    observed_at="2099-01-01T00:00:00Z",
                    system_id=system_id,
                    resource_id=row["resource_id"],
                    category=category,
                    pattern="leftover_pairing",
                    emails={ctx["requests_by_id"][case["case_id"]]["email"].lower()},
                    present=False,
                ))
    crack.score_linker(
        ctx["sample_requests"],
        ctx["sample_outputs"],
        observations + extras,
        activity,
        ctx["identities"],
        ctx["audits"],
        requests,
    )
    print("remaining-eight case ids were:", ", ".join(REMAINING))


def main() -> None:
    ctx = load_context()
    print_absence(ctx)
    analytics_table(ctx)
    print_sep5_and_needles(ctx)
    print_order(ctx)
    rescore_case_id(ctx)


if __name__ == "__main__":
    main()
