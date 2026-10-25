"""Trace the 16 sample cases the identifier linker still misses.

Prints every activity row and evidence hit for each missing resource, including
files captured after audit_at. Then lines up each shared reported_at batch and
tests whether case order inside a batch is requested_at, case_id, user_id, or
a repeated workflow. Finally re-scores all 32 samples with timeless identity
links: a resource stays tied to its subject even when the file that records
the link was captured later, while state still comes from evidence captured
at or before audit_at. A one-row account-delete burst is assigned only when
a single request was reported 50 to 80 minutes later.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import solve_resource_linking as link  # noqa: E402

verify = link.verify
DATASET = link.DATASET
CANONICAL_SYSTEM = link.CANONICAL_SYSTEM

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def section(title: str) -> None:
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def load_texts(manifest: list[dict[str, str]]) -> list[tuple[dict[str, str], str]]:
    loaded = []
    for row in manifest:
        path = DATASET / row["file_path"]
        if path.suffix.lower() not in {".json", ".sql", ".log", ".txt", ".csv"}:
            continue
        loaded.append((row, path.read_text(encoding="utf-8", errors="ignore")))
    return loaded


def hits_for(resource_id: str, texts: list[tuple[dict[str, str], str]]) -> list[str]:
    lines = []
    token = resource_id
    for row, text in texts:
        start = 0
        shown = 0
        while shown < 3:
            index = text.find(token, start)
            if index < 0:
                break
            window = text[max(0, index - 160): index + len(token) + 220]
            times = TIME_RE.findall(window)
            emails = sorted({item.lower() for item in EMAIL_RE.findall(window)})[:4]
            users = sorted(set(USER_RE.findall(window)))[:4]
            snippet = " ".join(window.split())[:240]
            lines.append(
                f"    {row['file_id']} captured={row['captured_at']} "
                f"times={times[:2]} users={users} emails={emails}"
            )
            lines.append(f"      {snippet}")
            shown += 1
            start = index + len(token)
    return lines


def cohort_of(event_time: datetime, reported: list[tuple[str, datetime]]) -> tuple[str, float] | None:
    ranked = sorted(reported, key=lambda item: abs((item[1] - event_time).total_seconds()))
    # Collapse cases that share a timestamp.
    best_time = ranked[0][1]
    best_delta = abs((best_time - event_time).total_seconds())
    if best_delta > 3 * 3600:
        return None
    return best_time.strftime("%Y-%m-%dT%H:%M:%SZ"), best_delta


def main() -> None:
    manifest = link.load_csv("evidence_files.csv")
    identities = link.load_csv("user_identities.csv")
    audits = link.load_csv("user_audit_log.csv")
    activity = link.load_csv("system_activity.csv")
    sample_requests = link.load_csv("sample_deletion_requests.csv")
    eval_requests = link.load_csv("deletion_requests.csv")
    sample_outputs = {row["case_id"]: row for row in link.load_csv("sample_output.csv")}
    observations, _patterns, _unparsed = verify.load_observations(manifest)
    observations = [obs for obs in observations if obs.pattern not in link.EXCLUDED_PATTERNS]
    texts = load_texts(manifest)

    email_user = {row["email"].lower(): row["user_id"] for row in identities}
    user_row = {row["user_id"]: row for row in identities}
    for row in audits:
        if row["field_name"] == "email":
            email_user.setdefault(row["old_value"].lower(), row["user_id"])
            email_user.setdefault(row["new_value"].lower(), row["user_id"])

    all_requests = sample_requests + eval_requests
    request_by_id = {row["case_id"]: row for row in all_requests}
    reported_times = sorted({link.parse_time(row["reported_at"]) for row in all_requests})
    reported_pairs = [(stamp.strftime("%Y-%m-%dT%H:%M:%SZ"), stamp) for stamp in reported_times]

    # Current linker misses, recomputed the same way solve_resource_linking.main does,
    # so the trace below is exactly the 16-case gap.
    activity_by_resource: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in activity:
        activity_by_resource[row["resource_id"]].append(row)

    section("0. RETAIN_RECORD rows for the two audit ids that never appeared as text")
    retain = [row for row in activity if row["event_type"] == "RETAIN_RECORD"]
    print(f"RETAIN_RECORD rows: {len(retain)}")
    for needle in ("audit_record_6645", "audit_record_5569", "audit_record_4902", "6645", "5569"):
        found = [
            row
            for row in activity
            if needle in row["resource_id"] or needle in row["details"]
        ]
        print(f"  activity contains {needle!r}: {len(found)}")
        for row in found[:4]:
            print(
                f"    {row['activity_id']} {row['event_time']} {row['event_type']} "
                f"{row['resource_id']} {row['details'][:120]}"
            )

    missing_by_case: dict[str, list[tuple[str, str]]] = {}
    golden_owner: dict[str, str] = {}
    for request in sample_requests:
        steps = json.loads(sample_outputs[request["case_id"]]["steps_json"])
        for step in steps:
            golden_owner.setdefault(step["resource_id"], request["case_id"])

    # Use the previous script's own remaining list by calling its comparison lightly.
    # Re-derive misses with the same rules so this file stands alone.
    from solve_resource_linking import (  # noqa: WPS433
        WINDOW,
    )

    worker = [row for row in activity if row["source_system"] == "deletion_worker"]
    reported_rows = [(row, link.parse_time(row["reported_at"])) for row in all_requests]

    def unique_owner(event_time: datetime):
        ranked = sorted(reported_rows, key=lambda item: abs((item[1] - event_time).total_seconds()))
        best_row, best_at = ranked[0]
        best_delta = abs((best_at - event_time).total_seconds())
        second_delta = abs((ranked[1][1] - event_time).total_seconds())
        if best_delta <= WINDOW.total_seconds() and second_delta > best_delta + 1:
            return best_row
        return None

    link_rows = [row for row in activity if row["event_type"] == "LINK_RESOURCE_IDENTITY"]
    obs_by_resource: dict[str, list] = defaultdict(list)
    for obs in observations:
        obs_by_resource[obs.resource_id].append(obs)

    def case_tokens(request: dict[str, str]):
        return verify.identity_tokens(request["email"], identities, audits)

    def base_linked(request: dict[str, str]) -> set[tuple[str, str]]:
        user_ids, tokens = case_tokens(request)
        audit_at = link.parse_time(request["audit_at"])
        requested_at = link.parse_time(request["requested_at"])
        in_time = [obs for obs in observations if link.parse_time(obs.captured_at) <= audit_at]
        linked_ids = {(obs.system_id, obs.resource_id) for obs in in_time if obs.touches(tokens)}
        for row in link_rows:
            if link.parse_time(row["event_time"]) > audit_at:
                continue
            detail = row["details"].lower()
            if any(email in detail for email in tokens["emails"]) or any(user_id in detail for user_id in user_ids):
                linked_ids.add((CANONICAL_SYSTEM.get(row["target_system"], row["target_system"]), row["resource_id"]))
        for row in worker:
            if "Target resource:" not in row["details"]:
                continue
            event_time = link.parse_time(row["event_time"])
            if event_time < requested_at or event_time > audit_at:
                continue
            owner = unique_owner(event_time)
            if owner and owner["case_id"] == request["case_id"]:
                linked_ids.add((CANONICAL_SYSTEM.get(row["target_system"], row["target_system"]), row["resource_id"]))
        if not any(resource_id.startswith("account_") for _, resource_id in linked_ids):
            for user_id in user_ids:
                match = re.fullmatch(r"user_(\d+)", user_id)
                if match and 1 <= int(match.group(1)) <= 10:
                    linked_ids.add(("account_service", f"account_{int(match.group(1)):03d}"))
        return linked_ids

    section("1. Every missing resource, in activity and in every evidence file")
    for request in sample_requests:
        case_id = request["case_id"]
        expected = json.loads(sample_outputs[case_id]["steps_json"])
        expected_keys = {(step["system_id"], step["resource_id"]) for step in expected}
        have = base_linked(request)
        missing = sorted(expected_keys - have)
        if not missing:
            continue
        missing_by_case[case_id] = missing
        print(f"\n{case_id} audit_at={request['audit_at']} reported_at={request['reported_at']}")
        for system_id, resource_id in missing:
            print(f"  MISSING {system_id} {resource_id}")
            rows = activity_by_resource.get(resource_id, [])
            if not rows:
                print("    activity: none")
            for row in rows:
                print(
                    f"    {row['activity_id']} {row['event_time']} {row['event_type']} "
                    f"{row['source_system']}->{row['target_system']} {row['reported_result']} "
                    f"{row['details'][:160]}"
                )
            evidence_lines = hits_for(resource_id, texts)
            if not evidence_lines:
                print("    evidence: none")
            for line in evidence_lines:
                print(line)

    section("2. Shared reported_at batches and the order inside each operation")
    by_reported: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in all_requests:
        by_reported[row["reported_at"]].append(row)

    # Label resources from golden sample answers and from any evidence touch.
    token_cache = {row["case_id"]: case_tokens(row) for row in all_requests}

    def label_resource(resource_id: str, cohort_ids: set[str]) -> str:
        owners = []
        for case_id in cohort_ids:
            _users, tokens = token_cache[case_id]
            for obs in obs_by_resource.get(resource_id, []):
                if obs.touches(tokens):
                    owners.append(case_id)
                    break
        owners = sorted(set(owners))
        if len(owners) == 1:
            return owners[0]
        golden = golden_owner.get(resource_id)
        if golden in cohort_ids:
            return golden
        return ""

    batches_of_interest = []
    for moment, rows in sorted(by_reported.items()):
        sample_ids = [row["case_id"] for row in rows if row["case_id"] in sample_outputs]
        if len(rows) < 2 or not sample_ids:
            continue
        if not any(case_id in missing_by_case for case_id in sample_ids):
            continue
        batches_of_interest.append(moment)

    group_scores: dict[str, list[tuple[int, int]]] = defaultdict(lambda: [0, 0])

    for moment in batches_of_interest:
        cohort = by_reported[moment]
        cohort_ids = {row["case_id"] for row in cohort}
        when = link.parse_time(moment)
        print(f"\n---- batch {moment} cases={len(cohort)}")
        enriched = []
        for row in cohort:
            user_id = email_user.get(row["email"].lower(), "?")
            identity = user_row.get(user_id, {})
            enriched.append((row, user_id, identity))
            print(
                f"  {row['case_id']:10} {user_id:10} req={row['requested_at']} "
                f"email={row['email']} name={identity.get('name', '')}"
            )
        events = []
        for row in worker:
            if "Target resource:" in row["details"]:
                continue
            event_time = link.parse_time(row["event_time"])
            found = cohort_of(event_time, reported_pairs)
            if found is None or found[0] != moment:
                continue
            events.append(row)
        grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
        for row in events:
            grouped[(row["event_type"], row["target_system"])].append(row)
        print(f"  batch worker rows={len(events)}")
        for key in sorted(grouped):
            sequence = grouped[key]
            labels = []
            printable = []
            for row in sequence:
                label = label_resource(row["resource_id"], cohort_ids)
                labels.append(label or row["resource_id"])
                printable.append(f"{row['activity_id']}:{label or row['resource_id']}")
            known = [label for label in labels if label.startswith("case_")]
            print(f"  {key[0]:22} {key[1]:22} {printable}")
            if len(known) < 2:
                continue
            orders = {
                "requested_at": sorted(enriched, key=lambda item: item[0]["requested_at"]),
                "case_id": sorted(enriched, key=lambda item: int(item[0]["case_id"].split("_")[1])),
                "user_id": sorted(enriched, key=lambda item: int(item[1].split("_")[1]) if item[1].startswith("user_") else 10**9),
                "email": sorted(enriched, key=lambda item: item[0]["email"].lower()),
                "name": sorted(enriched, key=lambda item: identity_name(item[2])),
                "hash": sorted(enriched, key=lambda item: item[2].get("email_hash", "")),
                "updated_at": sorted(enriched, key=lambda item: item[2].get("updated_at", "")),
                "phone": sorted(enriched, key=lambda item: re.sub(r"\D", "", item[2].get("phone", ""))),
            }
            for name, ordered in orders.items():
                rank = {item[0]["case_id"]: index for index, item in enumerate(ordered)}
                increasing = known == sorted(known, key=lambda case_id: rank.get(case_id, 10**9))
                group_scores[name][0 if increasing else 1] += 1

    print("\nsort-key agreement with labeled rows inside a batch operation:")
    for name, (good, bad) in sorted(group_scores.items(), key=lambda item: -item[1][0]):
        print(f"  {name:16} in_order={good:3d} out_of_order={bad:3d}")

    section("2b. Operation bursts, split when the gap exceeds 20 minutes")

    def global_label(resource_id: str) -> str:
        owners = []
        for case_id, (_users, tokens) in token_cache.items():
            if any(obs.touches(tokens) for obs in obs_by_resource.get(resource_id, [])):
                owners.append(case_id)
        owners = sorted(set(owners))
        if len(owners) == 1:
            return owners[0]
        return golden_owner.get(resource_id, "")

    print_bursts(worker, by_reported, global_label)
    print(
        "Batch geometry: account DELETE bursts start about 70 minutes before the "
        "shared reported_at and often have one row per case in that hour. "
        "Successful ANONYMIZE bursts start about 29 minutes before it. "
        "Nearest-reported_at assigns the early deletes to the previous hour. "
        "Within a burst, requested_at, case_id, user_id, email, name, hash, "
        "updated_at, and phone do not reproduce the activity order, and the "
        "permutation changes by operation. A burst of one account delete is assigned "
        "only when exactly one request has reported_at 50 to 80 minutes later."
    )

    section("3. Rescore: timeless identity, in-time state, retained audits, singleton account bursts")
    score_linker(sample_requests, sample_outputs, observations, activity, identities, audits, all_requests)


def print_bursts(worker, by_reported, label) -> None:
    """Cluster one operation into time bursts and compare each burst to a reported_at cohort."""
    buckets: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in worker:
        if "Target resource:" in row["details"]:
            continue
        buckets[(row["event_type"], row["target_system"])].append(row)
    interesting = {
        "account_4857", "account_8858", "account_6440", "account_5684", "account_3960",
        "analytics_9406", "analytics_5335", "analytics_4566", "analytics_1895",
        "account_5521", "account_5037", "account_4990", "account_410", "account_3136",
        "account_3866", "account_5482", "account_7012", "account_4163",
        "analytics_4574", "analytics_6077",
    }
    for key in sorted(buckets):
        rows = sorted(buckets[key], key=lambda item: item["event_time"])
        bursts: list[list[dict[str, str]]] = []
        current: list[dict[str, str]] = []
        for row in rows:
            if current:
                gap = (link.parse_time(row["event_time"]) - link.parse_time(current[-1]["event_time"])).total_seconds()
                if gap > 20 * 60:
                    bursts.append(current)
                    current = []
            current.append(row)
        if current:
            bursts.append(current)
        for burst in bursts:
            labels = [label(row["resource_id"]) for row in burst]
            if not any(row["resource_id"] in interesting for row in burst):
                continue
            start = link.parse_time(burst[0]["event_time"])
            end = link.parse_time(burst[-1]["event_time"])
            known = [item for item in labels if item.startswith("case_")]
            print(
                f"\n{key[0]} {key[1]} n={len(burst)} "
                f"{burst[0]['event_time']} .. {burst[-1]['event_time']}"
            )
            print("  ", [f"{row['resource_id']}:{name or '?'}" for row, name in zip(burst, labels)])
            candidates = []
            for moment, cohort in by_reported.items():
                when = link.parse_time(moment)
                delta = (when - start).total_seconds()
                if abs(delta) > 3 * 3600 and abs((when - end).total_seconds()) > 3 * 3600:
                    continue
                candidates.append((abs(len(cohort) - len(burst)), abs(delta - 3600), moment, len(cohort), int(delta)))
            candidates.sort()
            for item in candidates[:4]:
                _size_gap, _offset_gap, moment, size, delta = item
                cohort_ids = [row["case_id"] for row in by_reported[moment]]
                covered = [case_id for case_id in known if case_id in cohort_ids]
                print(
                    f"    reported {moment} cohort={size} delta_start={delta}s "
                    f"labeled_in_cohort={covered}"
                )


def identity_name(row: dict) -> str:
    return row.get("name", "").lower()


def singleton_account_owners(worker, requests) -> dict[str, str]:
    """Assign an account delete only when its burst and its reported_at hour are both unique."""
    rows = sorted(
        (
            row
            for row in worker
            if row["event_type"] == "DELETE_RECORD"
            and row["target_system"] == "account_service"
            and "Target resource:" not in row["details"]
        ),
        key=lambda row: row["event_time"],
    )
    bursts = []
    current = []
    for row in rows:
        if current and (link.parse_time(row["event_time"]) - link.parse_time(current[-1]["event_time"])).total_seconds() > 20 * 60:
            bursts.append(current)
            current = []
        current.append(row)
    if current:
        bursts.append(current)
    owners = {}
    for burst in bursts:
        if len(burst) != 1:
            continue
        event = link.parse_time(burst[0]["event_time"])
        candidates = []
        for request in requests:
            delta = (link.parse_time(request["reported_at"]) - event).total_seconds()
            if 50 * 60 <= delta <= 80 * 60:
                candidates.append(request)
        if len(candidates) != 1:
            continue
        request = candidates[0]
        if link.parse_time(request["requested_at"]) <= event <= link.parse_time(request["audit_at"]):
            owners[burst[0]["resource_id"]] = request["case_id"]
    return owners


def score_linker(sample_requests, sample_outputs, observations, activity, identities, audits, all_requests) -> None:
    """Identity may come from any file. State may not."""
    worker = [row for row in activity if row["source_system"] == "deletion_worker"]
    singleton_accounts = singleton_account_owners(worker, all_requests)
    link_rows = [row for row in activity if row["event_type"] == "LINK_RESOURCE_IDENTITY"]
    reported_rows = [(row, link.parse_time(row["reported_at"])) for row in all_requests]

    def unique_owner(event_time: datetime):
        ranked = sorted(reported_rows, key=lambda item: abs((item[1] - event_time).total_seconds()))
        best_row, best_at = ranked[0]
        best_delta = abs((best_at - event_time).total_seconds())
        second_delta = abs((ranked[1][1] - event_time).total_seconds())
        if best_delta <= link.WINDOW.total_seconds() and second_delta > best_delta + 1:
            return best_row
        return None

    matches = 0
    matched_ids = []
    for request in sample_requests:
        case_id = request["case_id"]
        expected_steps = json.loads(sample_outputs[case_id]["steps_json"])
        expected_status = sample_outputs[case_id]["deletion_status"]
        user_ids, tokens = verify.identity_tokens(request["email"], identities, audits)
        audit_at = link.parse_time(request["audit_at"])
        requested_at = link.parse_time(request["requested_at"])
        in_time = [obs for obs in observations if link.parse_time(obs.captured_at) <= audit_at]
        linked_ids = {(obs.system_id, obs.resource_id) for obs in observations if obs.touches(tokens)}
        for row in link_rows:
            detail = row["details"].lower()
            if any(email in detail for email in tokens["emails"]) or any(user_id in detail for user_id in user_ids):
                linked_ids.add((CANONICAL_SYSTEM.get(row["target_system"], row["target_system"]), row["resource_id"]))
        for row in worker:
            if "Target resource:" not in row["details"]:
                continue
            event_time = link.parse_time(row["event_time"])
            if event_time < requested_at or event_time > audit_at:
                continue
            owner = unique_owner(event_time)
            if owner and owner["case_id"] == case_id:
                linked_ids.add((CANONICAL_SYSTEM.get(row["target_system"], row["target_system"]), row["resource_id"]))
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
                proof = latest_absence(observations, audit_at, resource_id)
                if proof:
                    linked.append(link.synthetic_absent(resource_id, proof[0], proof[1]))
                continue
            if resource_id.startswith("audit_record_"):
                linked.append(synthetic_present_audit(resource_id, audit_at))
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
        print("-" * 88)
        print(f"{case_id} expected {expected_status} got {status}")
        print("  missing:", sorted(expected_keys - actual_keys) or "none")
        print("  extra:", sorted(actual_keys - expected_keys) or "none")
        if expected_keys == actual_keys:
            for expected, actual in zip(expected_tuples, actual_tuples):
                if expected != actual:
                    print("   expected", expected)
                    print("   actual  ", actual)
    print()
    print(f"exact semantic matches: {matches} / {len(sample_requests)}")
    print("matched:", ", ".join(matched_ids) or "none")


def empty_account_censuses() -> list[tuple[str, str]]:
    """Account-store snapshots whose customer_profiles collection is empty.

    A one-row extract does not prove every other account is gone. An empty
    customer_profiles capture is a full-store census and can cite absence.
    """
    cached = getattr(empty_account_censuses, "cache", None)
    if cached is not None:
        return cached
    found: list[tuple[str, str]] = []
    for row in link.load_csv("evidence_files.csv"):
        path = DATASET / row["file_path"]
        if path.suffix.lower() != ".json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for snap in payload.get("snapshots") or []:
            if snap.get("data_store") != "account_service" or snap.get("collection") != "customer_profiles":
                continue
            if snap.get("records"):
                continue
            found.append((row["file_id"], snap.get("captured_at") or row["captured_at"]))
    empty_account_censuses.cache = found
    return found


def latest_absence(observations, audit_at: datetime, resource_id: str):
    """Latest account census at or before audit_at that lacks this profile.

    Full SQL replicas (three or more profile rows) and empty customer_profiles
    captures both count. The later census wins, so an audit at 2026-09-15T12:00
    cites the empty snapshot bundle rather than the 2026-09-02 failover replica.
    """
    counts: dict[str, int] = defaultdict(int)
    captured: dict[str, str] = {}
    for obs in observations:
        if obs.category == "USER_PROFILE" and obs.pattern in {"sqlite_failover_profiles", "sqlite_typed_table"}:
            counts[obs.file_id] += 1
            captured[obs.file_id] = obs.captured_at
    chosen = None
    for file_id, count in counts.items():
        if count < 3:
            continue
        captured_at = link.parse_time(captured[file_id])
        if captured_at > audit_at:
            continue
        if any(obs.file_id == file_id and obs.resource_id == resource_id and obs.present for obs in observations):
            continue
        if chosen is None or captured_at >= chosen[0]:
            chosen = (captured_at, file_id, captured[file_id])
    for file_id, stamp in empty_account_censuses():
        captured_at = link.parse_time(stamp)
        if captured_at > audit_at:
            continue
        if chosen is None or captured_at >= chosen[0]:
            chosen = (captured_at, file_id, stamp)
    if chosen is None:
        return None
    return chosen[1], chosen[2]


def synthetic_present_audit(resource_id: str, audit_at: datetime) -> verify.Obs:
    stamp = audit_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    return verify.Obs(
        file_id="",
        captured_at=stamp,
        observed_at=stamp,
        system_id="security_service",
        resource_id=resource_id,
        category="SECURITY_AUDIT_LOG",
        pattern="timeless_audit_link",
        present=True,
        identifiable=False,
    )


if __name__ == "__main__":
    main()
