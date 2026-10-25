"""Score snapshot user-order plus anonymize-cohort constraints on the 32 samples.

A resource is assigned only when every legal solution gives it the same user.
Sample answers are the scorecard, not an input to that assignment.
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

import check_snapshots_and_sep5 as snap  # noqa: E402
import crack_remaining_16 as crack  # noqa: E402
import deep_check_unlinked as deep  # noqa: E402
import solve_burst_assignment as burst  # noqa: E402
import solve_resource_linking as link  # noqa: E402

verify = link.verify


def section(title: str) -> None:
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def monotonic_analytics(ctx) -> list[tuple[str, list[dict]]]:
    found = []
    for row in ctx["manifest"]:
        path = snap.DATASET / row["file_path"]
        if path.suffix.lower() not in {".json", ".sql", ".log", ".txt"}:
            continue
        try:
            collections = list(snap.iter_collections(path))
        except (OSError, json.JSONDecodeError):
            continue
        for label, records in collections:
            records = snap.collapse(records)
            if not any(str(record.get("resource_id", "")).startswith("analytics_") for record in records):
                continue
            known = [snap.on_record_users(record) for record in records]
            anchors = [users[0] for users in known if users]
            if len(anchors) < 2 or anchors != sorted(anchors):
                continue
            if len(set(anchors)) != len(anchors):
                continue
            found.append((f"{row['file_id']} {label}", records))
    return found


def cohort_users(ctx) -> dict[str, set[int]]:
    _by_reported, _accounts, analytics = snap.cohort_bursts(ctx)
    by_reported = defaultdict(list)
    for row in ctx["requests"]:
        by_reported[row["reported_at"]].append(row)
    allowed: dict[str, set[int]] = {}
    for moment, rows in analytics.items():
        users = set()
        for case in by_reported[moment]:
            _user_id, number = snap.case_user(ctx, case["case_id"])
            if number < 10**9:
                users.add(number)
        for row in rows:
            allowed[row["resource_id"]] = users
    return allowed


def solve_alignment(records: list[dict], allowed: dict[str, set[int]]) -> list[dict[str, int]]:
    sequence = [str(record.get("resource_id")) for record in records]
    anchors = {}
    for record in records:
        users = snap.on_record_users(record)
        if users:
            anchors[str(record.get("resource_id"))] = users[0]
    solutions: list[dict[str, int]] = []

    def walk(index: int, previous: int, used: set[int], assignment: dict[str, int]) -> None:
        if len(solutions) > 500:
            return
        if index == len(sequence):
            solutions.append(dict(assignment))
            return
        resource_id = sequence[index]
        later = [anchors[item] for item in sequence[index + 1 :] if item in anchors]
        ceiling = min(later) if later else 10**9
        if resource_id in anchors:
            user = anchors[resource_id]
            if previous < user < ceiling and user not in used:
                assignment[resource_id] = user
                used.add(user)
                walk(index + 1, user, used, assignment)
                used.remove(user)
                del assignment[resource_id]
            return
        domain = allowed.get(resource_id)
        if not domain:
            return
        for user in sorted(domain):
            if user <= previous or user >= ceiling or user in used:
                continue
            assignment[resource_id] = user
            used.add(user)
            walk(index + 1, user, used, assignment)
            used.remove(user)
            del assignment[resource_id]

    walk(0, -1, set(), {})
    return solutions


def unique_assignments(solutions: list[dict[str, int]]) -> dict[str, int]:
    if not solutions:
        return {}
    agreed = {}
    keys = set.intersection(*(set(solution) for solution in solutions))
    for resource_id in keys:
        values = {solution[resource_id] for solution in solutions}
        if len(values) == 1:
            agreed[resource_id] = next(iter(values))
    return agreed


def case_for_user(ctx, user_number: int) -> str:
    return ctx["user_case"].get(f"user_{user_number}", "")


def analytics_obs(ctx, assignments: dict[str, int]) -> list:
    extras = []
    for resource_id, user_number in assignments.items():
        case_id = case_for_user(ctx, user_number)
        if not case_id:
            continue
        email = ctx["requests_by_id"][case_id]["email"].lower()
        extras.append(verify.Obs(
            file_id="",
            captured_at="2099-01-01T00:00:00Z",
            observed_at="2099-01-01T00:00:00Z",
            system_id="analytics_platform",
            resource_id=resource_id,
            category="ANALYTICS_PROFILE",
            pattern="snapshot_user_alignment",
            emails={email},
            present=False,
        ))
    return extras


def account_pairing_obs(ctx) -> list:
    """Equal-count leftover zip ordered by case_id. This is the measured check, not a final key."""
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
        if owner and link.parse_time(owner["requested_at"]) <= event <= link.parse_time(owner["audit_at"]):
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
    plain = [row for row in worker if "Target resource:" not in row["details"]]
    families = {
        "account": burst.align_bursts(
            burst.bursts_of([
                row for row in plain
                if row["event_type"] == "DELETE_RECORD" and row["target_system"] == "account_service"
            ]),
            by_reported,
            burst.ACCOUNT_WINDOW,
            70 * 60,
        ),
        "analytics": burst.align_bursts(
            burst.bursts_of([
                row for row in plain
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
                if is_deletion(row) and not any(resource_id.startswith(prefix) for resource_id in satisfied[row["case_id"]])
            ]
            unknown = [row for row in rows if row["resource_id"] not in taken]
            if len(waiting) != len(unknown) or not waiting:
                continue
            ordered = sorted(waiting, key=lambda row: int(row["case_id"].split("_")[1]))
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
                    pattern="equal_count_pairing",
                    emails={case["email"].lower()},
                    present=False,
                ))
    return extras


def core(step: dict) -> tuple:
    return (
        step["phase"],
        step["operation"],
        step["system_id"],
        step["resource_id"],
        step["state"],
        step["evidence_id"],
    )


def predict(ctx, observations):
    activity = ctx["activity"]
    identities = ctx["identities"]
    audits = ctx["audits"]
    requests = ctx["requests"]
    worker = [row for row in activity if row["source_system"] == "deletion_worker"]
    singleton_accounts = crack.singleton_account_owners(worker, requests)
    link_rows = [row for row in activity if row["event_type"] == "LINK_RESOURCE_IDENTITY"]
    reported_rows = [(row, link.parse_time(row["reported_at"])) for row in requests]

    def unique_owner(event_time: datetime):
        ranked = sorted(reported_rows, key=lambda item: abs((item[1] - event_time).total_seconds()))
        best_row, best_at = ranked[0]
        best_delta = abs((best_at - event_time).total_seconds())
        second_delta = abs((ranked[1][1] - event_time).total_seconds())
        if best_delta <= link.WINDOW.total_seconds() and second_delta > best_delta + 1:
            return best_row
        return None

    predictions = []
    for request in ctx["sample_requests"]:
        case_id = request["case_id"]
        user_ids, tokens = verify.identity_tokens(request["email"], identities, audits)
        audit_at = link.parse_time(request["audit_at"])
        requested_at = link.parse_time(request["requested_at"])
        in_time = [obs for obs in observations if link.parse_time(obs.captured_at) <= audit_at]
        linked_ids = {(obs.system_id, obs.resource_id) for obs in observations if obs.touches(tokens)}
        for row in link_rows:
            detail = row["details"].lower()
            if any(email in detail for email in tokens["emails"]) or any(user_id in detail for user_id in user_ids):
                linked_ids.add((link.CANONICAL_SYSTEM.get(row["target_system"], row["target_system"]), row["resource_id"]))
        for row in worker:
            if "Target resource:" not in row["details"]:
                continue
            event_time = link.parse_time(row["event_time"])
            if event_time < requested_at or event_time > audit_at:
                continue
            owner = unique_owner(event_time)
            if owner and owner["case_id"] == case_id:
                linked_ids.add((link.CANONICAL_SYSTEM.get(row["target_system"], row["target_system"]), row["resource_id"]))
        for resource_id, owner_case in singleton_accounts.items():
            if owner_case == case_id:
                linked_ids.add(("account_service", resource_id))
        if not any(resource_id.startswith("account_") for _, resource_id in linked_ids):
            for user_id in user_ids:
                match = re.fullmatch(r"user_(\d+)", user_id)
                if match and 1 <= int(match.group(1)) <= 10:
                    linked_ids.add(("account_service", f"account_{int(match.group(1)):03d}"))
        linked = [obs for obs in in_time if (obs.system_id, obs.resource_id) in linked_ids]
        had_evidence = {(obs.system_id, obs.resource_id) for obs in linked}

        def during_request(obs) -> bool:
            raw = obs.observed_at or obs.captured_at
            try:
                return link.parse_time(raw) >= requested_at
            except ValueError:
                return link.parse_time(obs.captured_at) >= requested_at

        linked = [obs for obs in linked if obs.present or during_request(obs)]
        seen = {(obs.system_id, obs.resource_id) for obs in linked}
        for system_id, resource_id in sorted(linked_ids):
            if (system_id, resource_id) in had_evidence or (system_id, resource_id) in seen:
                continue
            if resource_id.startswith("account_"):
                proof = crack.latest_absence(observations, audit_at, resource_id)
                if proof:
                    linked.append(link.synthetic_absent(resource_id, proof[0], proof[1]))
                continue
            if resource_id.startswith("audit_record_"):
                linked.append(crack.synthetic_present_audit(resource_id, audit_at))
        states = verify.reduce_states(linked)
        plans = []
        for obs in states:
            hash_only = (
                obs.category == "ANALYTICS_PROFILE"
                and obs.present
                and obs.hashes
                and not (obs.emails or obs.phones or obs.user_ids)
            )
            if hash_only:
                plans.append(verify.violate(
                    "REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT", obs,
                ))
                continue
            plan = verify.plan_resource(obs)
            if plan:
                plans.append(plan)
        status, steps = verify.steps_from_plans(plans)
        predictions.append((case_id, status, steps))
    return predictions


def score(ctx, predictions) -> None:
    status_hits = 0
    exact = 0
    sequence_hits = 0
    expected_steps = 0
    actual_steps = 0
    step_hits = 0
    field_hits = 0
    field_total = 0
    matched_ids = []
    for case_id, status, steps in predictions:
        expected = json.loads(ctx["sample_outputs"][case_id]["steps_json"])
        expected_status = ctx["sample_outputs"][case_id]["deletion_status"]
        status_hits += status == expected_status
        expected_core = [core(step) for step in expected]
        actual_core = [core(step) for step in steps]
        sequence_hits += expected_core == actual_core
        if status == expected_status and expected_core == actual_core:
            exact += 1
            matched_ids.append(case_id)
        expected_steps += len(expected_core)
        actual_steps += len(actual_core)
        overlap = Counter(expected_core) & Counter(actual_core)
        step_hits += sum(overlap.values())
        paired: set[tuple] = set()
        for step in expected:
            field_total += 6
            key = (step["phase"], step["operation"], step["system_id"], step["resource_id"])
            match = next((item for item in steps if (item["phase"], item["operation"], item["system_id"], item["resource_id"]) == key and id(item) not in paired), None)
            if match is None:
                continue
            paired.add(id(match))
            field_hits += 4
            field_hits += match["state"] == step["state"]
            field_hits += match["evidence_id"] == step["evidence_id"]
            if core(step) != core(match):
                print(
                    f"  field {case_id} {step['resource_id']} {step['operation']} "
                    f"state {step['state']}->{match['state']} evidence {step['evidence_id']!r}->{match['evidence_id']!r}"
                )
        if expected_core != actual_core or status != expected_status:
            expected_keys = {(step["system_id"], step["resource_id"]) for step in expected}
            actual_keys = {(step["system_id"], step["resource_id"]) for step in steps}
            print(f"{case_id} status {expected_status}->{status} missing={sorted(expected_keys - actual_keys) or 'none'} extra={sorted(actual_keys - expected_keys) or 'none'}")
    total = len(predictions)
    print(f"deletion_status {status_hits}/{total}")
    print(f"case_exact {exact}/{total}")
    print(f"sequence {sequence_hits}/{total}")
    print(f"step_recall {step_hits}/{expected_steps}")
    print(f"step_precision {step_hits}/{actual_steps}")
    print(f"field {field_hits}/{field_total}")
    print("exact:", ", ".join(matched_ids))


def main() -> None:
    ctx = snap.load_context()
    ctx["identities"] = link.load_csv("user_identities.csv")
    ctx["audits"] = link.load_csv("user_audit_log.csv")
    ctx["sample_requests"] = link.load_csv("sample_deletion_requests.csv")
    ctx["sample_outputs"] = {row["case_id"]: row for row in link.load_csv("sample_output.csv")}
    ctx["observations"] = [
        obs for obs in verify.load_observations(ctx["manifest"])[0]
        if obs.pattern not in link.EXCLUDED_PATTERNS
    ]
    section("1. Monotonic analytics collections and cohort-constrained solutions")
    collections = monotonic_analytics(ctx)
    allowed = cohort_users(ctx)
    print(f"monotonic analytics collections: {len(collections)}")
    agreed: dict[str, int] = {}
    for label, records in collections:
        solutions = solve_alignment(records, allowed)
        unique = unique_assignments(solutions)
        print(f"{label} rows={len(records)} solutions={len(solutions)} unique={len(unique)}")
        if not solutions:
            continue
        varying = []
        for resource_id in solutions[0]:
            values = sorted({solution[resource_id] for solution in solutions})
            if len(values) == 1:
                case_id = case_for_user(ctx, values[0])
                sample = ctx["sample_outputs"] and ctx["sample_owner"].get(resource_id, "")
                mark = ""
                if sample:
                    mark = " sample-match" if sample == case_id else " sample-differs"
                print(f"  fixed {resource_id} -> user_{values[0]} {case_id}{mark}")
            else:
                varying.append(f"{resource_id}: {['user_' + str(value) for value in values]}")
        if varying:
            print("  ambiguous " + "; ".join(varying))
        for resource_id, user_number in unique.items():
            if resource_id not in agreed:
                agreed[resource_id] = user_number
    section("2. Linker plus only the assignments shared by every solution")
    base = ctx["observations"]
    score(ctx, predict(ctx, base + analytics_obs(ctx, agreed)))
    section("3. That linker plus equal-count case_id pairing")
    print("Pairing is included only as the previously measured check. Account-burst order is still not a settled key.")
    score(ctx, predict(ctx, base + analytics_obs(ctx, agreed) + account_pairing_obs(ctx)))


if __name__ == "__main__":
    main()
