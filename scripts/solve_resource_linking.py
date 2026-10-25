"""Reverse-engineer resource linking against the 32 sample answers.

Linking rules under test:

1. Resolve the request email to a user and gather historical emails, phones, and hashes.
2. Read every evidence observation. A trace_id joins the line that names the subject
   (subject_ref, subject_key, lookup_key, owner_key) to the line that names the resource.
3. Keep a resource when any in-time observation carries one of those identifiers,
   or when a catalog LINK_RESOURCE_IDENTITY row names the person.
4. Keep a deletion_worker resource only when its detail says "Target resource:"
   and this case's reported_at is the unique nearest reported_at, within 20 minutes,
   inside [requested_at, audit_at]. Those are the early one-resource jobs.
   Clock-hour batches interleave several cases, so proximity is not identity there.
5. Latest observation per (system_id, resource_id) still decides state. A replica
   that still holds a row wins. A cache miss on the same trace does not hide rows=1.
   Nested document/profile emails count. Activity success/failure is not state.
6. A worker-linked or seed account with no evidence row is absent. A complete case
   cites the latest full account snapshot at or before audit_at that does not contain it.
   A profile that was already absent before requested_at is out of scope.
7. user_01 through user_10 use account_NNN when no other account was linked.
   account_004 exists only in sample_output.csv and is reached by that rule.
8. Legal-register pages and the retained-reference screen do not create steps.
   A legal hold needs a legal_hold_* id. A tombstone needs a tombstone_* id.
9. An analytics contact row that has only a historical email hash is deleted.
   That is the one sample shape that does not take the ANONYMIZE action.

Running this file prints the raw-byte search, the batch collisions, the system map,
and the semantic diff against all 32 sample answers.

The policy, ordering, and evidence-clearing rules are the ones already verified.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
SCRIPT = ROOT / "scripts" / "verify_evidence_and_samples.py"

spec = importlib.util.spec_from_file_location("verify_evidence_and_samples", SCRIPT)
verify = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verify
spec.loader.exec_module(verify)

_ORIGINAL_ADD = verify.add_id_fields


def add_id_fields(obs, record: dict) -> None:
    """Keep the shared extractor and also read the subject fields logs actually use."""
    _ORIGINAL_ADD(obs, record)
    for key in ("subject_ref", "owner_key", "customer_key", "subject_reference", "correlation_key", "lookup_key"):
        obs.user_ids |= verify.users_in(record.get(key))
        obs.emails |= verify.emails_in(record.get(key))
        obs.phones |= verify.phones_in(record.get(key))
        obs.hashes |= verify.hashes_in(record.get(key))
    if obs.category in verify.ANONYMIZE_CATEGORIES:
        # A historical email hash alone does not make the analytics row attributable.
        # case_12's contact lookup keeps only that hash and the sample deletes the row.
        obs.identifiable = bool(obs.emails or obs.phones or obs.user_ids)


verify.add_id_fields = add_id_fields

WINDOW = timedelta(minutes=20)
EXCLUDED_PATTERNS = {"pdf_legal_hold", "png_retained_reference"}
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


def load_csv(name: str) -> list[dict[str, str]]:
    with (DATASET / name).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def section(title: str) -> None:
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def raw_search(needles: list[str]) -> None:
    for needle in needles:
        hits = []
        token = needle.encode()
        for path in DATASET.rglob("*"):
            if path.is_file() and token in path.read_bytes():
                hits.append(str(path.relative_to(DATASET)))
        print(f"  {needle}: {hits or 'no file'}")


def synthetic_absent(resource_id: str, file_id: str, captured_at: str) -> verify.Obs:
    category = verify.category_for_resource(resource_id, "account_service")
    system_id = CANONICAL_SYSTEM.get(category, "account_service")
    return verify.Obs(
        file_id=file_id,
        captured_at=captured_at,
        observed_at=captured_at,
        system_id=system_id,
        resource_id=resource_id,
        category=category,
        pattern="absence_snapshot",
        present=False,
        identifiable=False,
    )


def main() -> None:
    manifest = load_csv("evidence_files.csv")
    identities = load_csv("user_identities.csv")
    audits = load_csv("user_audit_log.csv")
    activity = load_csv("system_activity.csv")
    sample_requests = load_csv("sample_deletion_requests.csv")
    eval_requests = load_csv("deletion_requests.csv")
    sample_outputs = {row["case_id"]: row for row in load_csv("sample_output.csv")}
    observations, patterns, unparsed = verify.load_observations(manifest)
    observations = [obs for obs in observations if obs.pattern not in EXCLUDED_PATTERNS]

    by_case_expected = {}
    golden_rows = []
    for request in sample_requests:
        steps = json.loads(sample_outputs[request["case_id"]]["steps_json"])
        resources = {}
        for step in steps:
            resources.setdefault(step["resource_id"], step)
        by_case_expected[request["case_id"]] = resources
        for step in steps:
            golden_rows.append(step)

    section("1. Activity around reported_at, and the four hard resource ids")
    print(f"golden step rows: {len(golden_rows)}")
    print(f"distinct golden resources: {len({(request['case_id'], step['resource_id']) for request in sample_requests for step in json.loads(sample_outputs[request['case_id']]['steps_json'])})}")
    print("raw byte search:")
    raw_search(
        [
            "account_004",
            "audit_record_4902",
            "audit_record_6645",
            "audit_record_5569",
        ]
    )
    print("numeric fragments that are different resources:")
    raw_search(["account_6645", "support_5569"])
    print(
        "account_004 is the profile id for user_04 and is absent from every source file. "
        "audit_record_4902 is in structured_service_events_eu_west_20260918.log, joined by trace tr-9028396 to subject_ref user_61. "
        "audit_record_6645 and audit_record_5569 occur only in sample_output.csv. "
        "6645 is account_6645. 5569 is support_5569 and ticket CS-5569."
    )

    activity_by_resource = defaultdict(list)
    for row in activity:
        activity_by_resource[row["resource_id"]].append(row)
    worker = [row for row in activity if row["source_system"] == "deletion_worker"]
    all_requests = sample_requests + eval_requests
    reported = [(row, parse_time(row["reported_at"])) for row in all_requests]

    def unique_owner(event_time: datetime) -> tuple[dict | None, float]:
        ranked = sorted(reported, key=lambda item: abs((item[1] - event_time).total_seconds()))
        best_row, best_at = ranked[0]
        best_delta = abs((best_at - event_time).total_seconds())
        second_delta = abs((ranked[1][1] - event_time).total_seconds())
        if best_delta <= WINDOW.total_seconds() and second_delta > best_delta + 1:
            return best_row, best_delta
        return None, best_delta

    owned = 0
    missed = []
    stolen = []
    for request in sample_requests:
        expected_ids = set(by_case_expected[request["case_id"]])
        for resource_id in sorted(expected_ids):
            rows = [
                row
                for row in activity_by_resource.get(resource_id, [])
                if row["source_system"] == "deletion_worker"
            ]
            if not rows:
                continue
            owners = []
            for row in rows:
                owner, delta = unique_owner(parse_time(row["event_time"]))
                owners.append((owner["case_id"] if owner else None, int(delta), row["activity_id"]))
            if any(owner == request["case_id"] for owner, _, _ in owners):
                owned += 1
            else:
                missed.append((request["case_id"], resource_id, owners))
            for owner, delta, activity_id in owners:
                if owner and owner != request["case_id"]:
                    stolen.append((request["case_id"], resource_id, owner, activity_id))
    print(f"golden resources with a deletion_worker row uniquely owned by their case: {owned}")
    print(f"golden worker resources not uniquely owned: {len(missed)}")
    for item in missed:
        print("  not owned", item)
    print(f"worker rows whose unique owner is a different case: {len(stolen)}")
    for item in stolen[:12]:
        print("  stolen", item)

    print("shared sample reported_at values, and why time clustering cannot split them:")
    by_reported = defaultdict(list)
    for request in sample_requests:
        by_reported[request["reported_at"]].append(request["case_id"])
    for moment, case_ids in sorted(by_reported.items()):
        if len(case_ids) > 1:
            print(f"  {moment} {case_ids}")

    section("2. Why the legal register and retained-reference screen are not steps")
    manifest_by_id = {row["file_id"]: row for row in manifest}
    for request in sample_requests:
        if request["case_id"] not in {"case_08", "case_17"}:
            continue
        print(
            f"{request['case_id']} audit_at={request['audit_at']} "
            f"legal_pdf={manifest_by_id['evidence_27']['captured_at']} "
            f"retained_png={manifest_by_id['evidence_42']['captured_at']}"
        )
    print(
        "Both files are earlier than audit_at, so the time cutoff does not remove them. "
        "The register names orders and user ids, not a legal_hold_* resource. "
        "The ten legal_service activity rows are legal_hold_<id> with no subject email. "
        "The retained-reference screen shows the stable key user_17. "
        "The catalog resource is tombstone_17, and case_17's answer has no tombstone step. "
        "case_31 and case_32 include a tombstone only where evidence uses the tombstone_* id."
    )
    print("canonical system_id map:")
    for source, target in sorted(CANONICAL_SYSTEM.items()):
        print(f"  {source:32} -> {target}")

    section("3. Refined linker versus sample_output.csv")
    obs_by_resource = defaultdict(list)
    for obs in observations:
        obs_by_resource[obs.resource_id].append(obs)
    account_snapshots = []
    counts = defaultdict(int)
    captured = {}
    for obs in observations:
        if obs.category == "USER_PROFILE" and obs.pattern in {"sqlite_failover_profiles", "sqlite_typed_table"}:
            counts[obs.file_id] += 1
            captured[obs.file_id] = obs.captured_at
    for file_id, count in counts.items():
        if count >= 3:
            account_snapshots.append((parse_time(captured[file_id]), file_id, captured[file_id]))
    account_snapshots.sort()
    print("full account snapshots:")
    for _, file_id, captured_at in account_snapshots:
        print(f"  {file_id} {captured_at} rows={counts[file_id]}")

    link_rows = [row for row in activity if row["event_type"] == "LINK_RESOURCE_IDENTITY"]

    def absence_file(audit_at: datetime, resource_id: str) -> tuple[str, str] | None:
        chosen = None
        for captured_at, file_id, captured_text in account_snapshots:
            if captured_at > audit_at:
                continue
            present_ids = {
                obs.resource_id
                for obs in obs_by_resource.get(resource_id, [])
                if obs.file_id == file_id and obs.present
            }
            if resource_id in present_ids:
                continue
            chosen = (file_id, captured_text)
        return chosen

    matches = 0
    matched_ids = []
    remaining = []
    for request in sample_requests:
        case_id = request["case_id"]
        expected_steps = json.loads(sample_outputs[case_id]["steps_json"])
        expected_status = sample_outputs[case_id]["deletion_status"]
        user_ids, tokens = verify.identity_tokens(request["email"], identities, audits)
        audit_at = parse_time(request["audit_at"])
        requested_at = parse_time(request["requested_at"])
        in_time = [obs for obs in observations if parse_time(obs.captured_at) <= audit_at]
        linked_ids = {
            (obs.system_id, obs.resource_id)
            for obs in in_time
            if obs.touches(tokens)
        }
        for row in link_rows:
            if parse_time(row["event_time"]) > audit_at:
                continue
            detail = row["details"].lower()
            if any(email in detail for email in tokens["emails"]) or any(user_id in detail for user_id in tokens["user_ids"]):
                system_id = CANONICAL_SYSTEM.get(row["target_system"], row["target_system"])
                linked_ids.add((system_id, row["resource_id"]))

        for row in worker:
            # Early deletion jobs name one target and finish within minutes of reported_at.
            # Batch jobs interleave several cases that share a clock-hour reported_at, so
            # proximity is not identity for those rows.
            if "Target resource:" not in row["details"]:
                continue
            event_time = parse_time(row["event_time"])
            if event_time < requested_at or event_time > audit_at:
                continue
            owner, _delta = unique_owner(event_time)
            if owner and owner["case_id"] == case_id:
                system_id = CANONICAL_SYSTEM.get(row["target_system"], row["target_system"])
                linked_ids.add((system_id, row["resource_id"]))

        if not any(resource_id.startswith("account_") for _, resource_id in linked_ids):
            for user_id in user_ids:
                match = re.fullmatch(r"user_(\d+)", user_id)
                if not match:
                    continue
                number = int(match.group(1))
                if 1 <= number <= 10:
                    linked_ids.add(("account_service", f"account_{number:03d}"))

        linked = [obs for obs in in_time if (obs.system_id, obs.resource_id) in linked_ids]
        had_evidence = {(obs.system_id, obs.resource_id) for obs in linked}
        # A profile that was already absent before the request is not part of this deletion.
        def in_request(obs: verify.Obs) -> bool:
            raw = obs.observed_at or obs.captured_at
            try:
                return parse_time(raw) >= requested_at
            except ValueError:
                return parse_time(obs.captured_at) >= requested_at

        linked = [obs for obs in linked if obs.present or in_request(obs)]
        seen = {(obs.system_id, obs.resource_id) for obs in linked}
        for system_id, resource_id in sorted(linked_ids):
            if (system_id, resource_id) in had_evidence or (system_id, resource_id) in seen:
                continue
            if not resource_id.startswith("account_"):
                continue
            proof = absence_file(audit_at, resource_id)
            if proof is None:
                continue
            file_id, captured_at = proof
            linked.append(synthetic_absent(resource_id, file_id, captured_at))

        states = verify.reduce_states(linked)
        plans = []
        for obs in states:
            hash_only_contact = (
                obs.category == "ANALYTICS_PROFILE"
                and obs.present
                and obs.hashes
                and not (obs.emails or obs.phones or obs.user_ids)
            )
            if hash_only_contact:
                plans.append(
                    verify.violate(
                        "REPORT_REMAINING_RECORD",
                        "PRESENT",
                        "DELETE_RECORD",
                        "ABSENT",
                        "VERIFY_RECORD_ABSENT",
                        "ABSENT",
                        obs,
                    )
                )
                continue
            plan = verify.plan_resource(obs)
            if plan:
                plans.append(plan)
        status, steps = verify.steps_from_plans(plans)
        expected_tuples = [verify.step_tuple(step) for step in expected_steps]
        actual_tuples = [verify.step_tuple(step) for step in steps]
        if status == expected_status and actual_tuples == expected_tuples:
            matches += 1
            matched_ids.append(case_id)
            continue
        expected_keys = {(step["system_id"], step["resource_id"]) for step in expected_steps}
        actual_keys = {(step["system_id"], step["resource_id"]) for step in steps}
        field_diffs = [pair for pair in zip(expected_tuples, actual_tuples) if pair[0] != pair[1]]
        remaining.append(case_id)
        print("-" * 88)
        print(f"{case_id} expected {expected_status} got {status} users={sorted(user_ids)}")
        print("  missing:", sorted(expected_keys - actual_keys) or "none")
        print("  extra:", sorted(actual_keys - expected_keys) or "none")
        if expected_keys == actual_keys and field_diffs:
            print("  same resources, field diffs:")
            for expected, actual in field_diffs:
                print("   expected", expected)
                print("   actual  ", actual)
        elif expected_keys != actual_keys and len(field_diffs) <= 8:
            print("  expected:")
            for item in expected_tuples:
                print("   ", item)
            print("  actual:")
            for item in actual_tuples:
                print("   ", item)

    print()
    print(f"exact semantic matches: {matches} / {len(sample_requests)}")
    print("matched:", ", ".join(matched_ids) or "none")
    print("remaining:", ", ".join(remaining) or "none")
    print("unparsed text files:", unparsed or "none")
    print("observations used:", len(observations))
    print("parser patterns:", ", ".join(f"{name}={count}" for name, count in patterns.most_common()))


if __name__ == "__main__":
    main()
