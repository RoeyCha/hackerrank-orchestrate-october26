"""Test cohort elimination, intra-cohort rank, and the raw leftover rows.

Identity used for elimination comes from evidence observations and from
LINK_RESOURCE_IDENTITY details that name the person. Sample answers are used
only afterwards, to check an assignment. A leftover burst row is assigned only
when exactly one cohort member and exactly one burst row remain.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import crack_remaining_16 as crack  # noqa: E402
import solve_resource_linking as link  # noqa: E402

verify = link.verify
DATASET = link.DATASET

SAMPLE_FOCUS = {
    "account_5521": "case_18",
    "account_5037": "case_20",
    "account_6440": "case_21",
    "account_4990": "case_22",
    "account_410": "case_23",
    "account_3136": "case_25",
    "account_5482": "case_28",
    "account_7012": "case_29",
    "account_4857": "case_31",
    "account_8858": "case_32",
    "analytics_9406": "case_03",
    "analytics_5335": "case_21",
    "analytics_1895": "case_25",
    "analytics_4566": "case_26",
    "analytics_4574": "case_27",
    "analytics_6077": "case_28",
    "audit_record_6645": "case_18",
    "audit_record_5569": "case_20",
}

ACCOUNT_WINDOW = (50 * 60, 90 * 60)
ANALYTICS_WINDOW = (20 * 60, 40 * 60)
BURST_GAP = 20 * 60


def section(title: str) -> None:
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def canonical(system_id: str) -> str:
    return link.CANONICAL_SYSTEM.get(system_id, system_id)


def bursts_of(rows: list[dict[str, str]]) -> list[list[dict[str, str]]]:
    rows = sorted(rows, key=lambda row: row["event_time"])
    grouped: list[list[dict[str, str]]] = []
    current: list[dict[str, str]] = []
    for row in rows:
        if current and (link.parse_time(row["event_time"]) - link.parse_time(current[-1]["event_time"])).total_seconds() > BURST_GAP:
            grouped.append(current)
            current = []
        current.append(row)
    if current:
        grouped.append(current)
    return grouped


def align_bursts(
    grouped: list[list[dict[str, str]]],
    by_reported: dict[str, list[dict[str, str]]],
    window: tuple[int, int],
    prefer: int,
) -> dict[str, list[dict[str, str]]]:
    """One burst per reported_at. Prefer equal length, then the usual offset."""
    candidates = []
    for grouped_rows in grouped:
        start = link.parse_time(grouped_rows[0]["event_time"])
        for moment, cohort in by_reported.items():
            delta = (link.parse_time(moment) - start).total_seconds()
            if not window[0] <= delta <= window[1]:
                continue
            candidates.append((abs(len(cohort) - len(grouped_rows)), abs(delta - prefer), moment, grouped_rows))
    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    assigned: dict[str, list[dict[str, str]]] = {}
    used = set()
    for _gap, _delta, moment, grouped_rows in candidates:
        identity = id(grouped_rows)
        if moment in assigned or identity in used:
            continue
        assigned[moment] = grouped_rows
        used.add(identity)
    return assigned


def unique_map(pairs: dict[str, set[str]]) -> dict[str, str]:
    return {resource_id: next(iter(owners)) for resource_id, owners in pairs.items() if len(owners) == 1}


def evidence_owners(observations, requests, identities, audits) -> dict[str, str]:
    tokens = {
        row["case_id"]: verify.identity_tokens(row["email"], identities, audits)
        for row in requests
    }
    buckets: dict[str, dict[str, set[str]]] = {
        "emails": defaultdict(set),
        "phones": defaultdict(set),
        "hashes": defaultdict(set),
        "user_ids": defaultdict(set),
    }
    for obs in observations:
        if not obs.resource_id or obs.pattern in link.EXCLUDED_PATTERNS:
            continue
        for kind, values in (
            ("emails", obs.emails),
            ("phones", obs.phones),
            ("hashes", obs.hashes),
            ("user_ids", obs.user_ids),
        ):
            for value in values:
                buckets[kind][value].add(obs.resource_id)
    owners: dict[str, set[str]] = defaultdict(set)
    for case_id, (_users, token_sets) in tokens.items():
        found = set()
        for kind, values in token_sets.items():
            for value in values:
                found |= buckets[kind].get(value, set())
        for resource_id in found:
            owners[resource_id].add(case_id)
    return unique_map(owners)


def link_owners(activity, requests, identities, audits) -> dict[str, str]:
    tokens = {
        row["case_id"]: verify.identity_tokens(row["email"], identities, audits)
        for row in requests
    }
    owners: dict[str, set[str]] = defaultdict(set)
    for row in activity:
        if row["event_type"] != "LINK_RESOURCE_IDENTITY":
            continue
        detail = row["details"].lower()
        for case_id, (user_ids, token_sets) in tokens.items():
            if any(email in detail for email in token_sets["emails"]) or any(user_id in detail for user_id in user_ids):
                owners[row["resource_id"]].add(case_id)
    return unique_map(owners)


def elimination(cohort, burst, identified: dict[str, str]) -> tuple[list[dict], list[dict], list[dict]]:
    cohort_ids = {row["case_id"] for row in cohort}
    known_rows = []
    leftover_rows = []
    for row in burst:
        owner = identified.get(row["resource_id"])
        if owner in cohort_ids:
            known_rows.append(row)
        elif owner:
            continue
        else:
            leftover_rows.append(row)
    prefix = "account_" if burst[0]["resource_id"].startswith("account_") else "analytics_"
    waiting = []
    for row in cohort:
        owned = [resource_id for resource_id, owner in identified.items() if owner == row["case_id"] and resource_id.startswith(prefix)]
        if not owned:
            waiting.append(row)
    return known_rows, waiting, leftover_rows


def describe_case(row: dict[str, str], email_user: dict[str, str]) -> str:
    user = email_user.get(row["email"].lower(), "?")
    return f"{row['case_id']} {user} req={row['requested_at']} email={row['email']}"


def print_side(rows: list[dict[str, str]], identified: dict[str, str], email_user: dict[str, str], requests_by_id: dict[str, dict]) -> None:
    for row in rows:
        owner = identified.get(row["resource_id"], "")
        owner_text = describe_case(requests_by_id[owner], email_user) if owner in requests_by_id else (owner or "unidentified")
        print(
            f"    {row['activity_id']} {row['event_time']} {row['event_type']} "
            f"{row['resource_id']} result={row['reported_result']} -> {owner_text}"
        )


def enclosing_record(text: str, index: int) -> str:
    region = max(0, index - 12000)
    stack = []
    for position in range(region, index + 1):
        char = text[position]
        if char == "{":
            stack.append(position)
        elif char == "}" and stack:
            stack.pop()
    if stack:
        start = stack[-1]
        depth = 0
        for position in range(start, min(len(text), start + 12000)):
            if text[position] == "{":
                depth += 1
            elif text[position] == "}":
                depth -= 1
                if depth == 0:
                    blob = text[start:position + 1]
                    if len(blob) <= 4000:
                        return blob
                    return blob[:2000] + f"\n... truncated from {len(blob)} chars"
    line_start = text.rfind("\n", 0, index) + 1
    line_end = text.find("\n", index)
    if line_end < 0:
        line_end = min(len(text), index + 1500)
    return text[line_start:line_end]


def raw_records(resource_id: str, texts: list[tuple[dict[str, str], str]]) -> list[str]:
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(resource_id)}(?![A-Za-z0-9_])")
    found = []
    seen = set()
    for row, text in texts:
        for match in pattern.finditer(text):
            blob = " ".join(enclosing_record(text, match.start()).split())
            key = (row["file_id"], blob[:240])
            if key in seen:
                continue
            seen.add(key)
            found.append(f"    {row['file_id']} captured={row['captured_at']}\n      {blob[:2000]}")
            if len(found) >= 4:
                return found
    return found


def main() -> None:
    identities = link.load_csv("user_identities.csv")
    audits = link.load_csv("user_audit_log.csv")
    activity = link.load_csv("system_activity.csv")
    manifest = link.load_csv("evidence_files.csv")
    sample_requests = link.load_csv("sample_deletion_requests.csv")
    eval_requests = link.load_csv("deletion_requests.csv")
    sample_outputs = {row["case_id"]: row for row in link.load_csv("sample_output.csv")}
    requests = sample_requests + eval_requests
    requests_by_id = {row["case_id"]: row for row in requests}
    identity_by_user = {row["user_id"]: row for row in identities}
    identity_order = {row["user_id"]: index for index, row in enumerate(identities)}
    email_user = {row["email"].lower(): row["user_id"] for row in identities}
    for row in audits:
        if row["field_name"] == "email":
            email_user.setdefault(row["old_value"].lower(), row["user_id"])
            email_user.setdefault(row["new_value"].lower(), row["user_id"])

    observations, _patterns, _unparsed = verify.load_observations(manifest)
    observations = [obs for obs in observations if obs.pattern not in link.EXCLUDED_PATTERNS]
    identified = evidence_owners(observations, requests, identities, audits)
    identified.update(link_owners(activity, requests, identities, audits))

    by_reported: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in requests:
        by_reported[row["reported_at"]].append(row)

    worker = [row for row in activity if row["source_system"] == "deletion_worker" and "Target resource:" not in row["details"]]
    account_bursts = align_bursts(
        bursts_of([row for row in worker if row["event_type"] == "DELETE_RECORD" and row["target_system"] == "account_service"]),
        by_reported,
        ACCOUNT_WINDOW,
        70 * 60,
    )
    analytics_bursts = align_bursts(
        bursts_of([
            row for row in worker
            if row["event_type"] == "ANONYMIZE_RECORD"
            and row["target_system"] == "analytics_platform"
            and row["reported_result"] == "SUCCESS"
        ]),
        by_reported,
        ANALYTICS_WINDOW,
        29 * 60,
    )

    section("1. Full-cohort elimination from evidence-identified resources")
    print(f"cases={len(requests)} reported_at cohorts={len(by_reported)} evidence-unique resources={len(identified)}")
    print(f"aligned account bursts={len(account_bursts)} aligned analytics bursts={len(analytics_bursts)}")

    assignments: dict[str, list[tuple[str, str]]] = defaultdict(list)
    shrink = {"account": [0, 0, 0], "analytics": [0, 0, 0]}
    focus_moments = set()
    for row in sample_requests:
        if row["case_id"] in set(SAMPLE_FOCUS.values()):
            focus_moments.add(row["reported_at"])

    def run_family(name: str, aligned: dict[str, list[dict[str, str]]], focus_only: bool) -> None:
        for moment in sorted(aligned):
            cohort = by_reported[moment]
            burst = aligned[moment]
            known_rows, waiting, leftover = elimination(cohort, burst, identified)
            if len(waiting) == 1 and len(leftover) == 1:
                shrink[name][0] += 1
                resource_id = leftover[0]["resource_id"]
                case_id = waiting[0]["case_id"]
                if identified.get(resource_id) in (None, case_id):
                    assignments[case_id].append((resource_id, name))
            elif len(waiting) == 0 and len(leftover) == 0:
                shrink[name][1] += 1
            else:
                shrink[name][2] += 1
            if focus_only and moment not in focus_moments:
                continue
            if not focus_only:
                continue
            print(
                f"\n{name} reported_at={moment} cohort={len(cohort)} burst={len(burst)} "
                f"known_in_burst={len(known_rows)} waiting={len(waiting)} leftover_rows={len(leftover)}"
            )
            print("  cohort:")
            for row in sorted(cohort, key=lambda item: item["case_id"]):
                prefix = "account_" if name == "account" else "analytics_"
                owned = sorted(resource_id for resource_id, owner in identified.items() if owner == row["case_id"] and resource_id.startswith(prefix))
                print(f"    {describe_case(row, email_user)} known={owned or 'none'}")
            print("  burst rows:")
            print_side(burst, identified, email_user, requests_by_id)
            if len(waiting) == 1 and len(leftover) == 1:
                print(f"  elimination assigns {leftover[0]['resource_id']} -> {waiting[0]['case_id']}")

    # Print the focus cohorts before assignments mutate later families. Account first.
    run_family("account", account_bursts, True)
    run_family("analytics", analytics_bursts, True)
    print(
        "\nshrink counts (unique elimination, already complete, still ambiguous): "
        f"account={shrink['account']} analytics={shrink['analytics']}"
    )
    print("assignments from a single leftover row:")
    if not assignments:
        print("  none")
    for case_id, pairs in sorted(assignments.items()):
        expected = set()
        if case_id in sample_outputs:
            for step in json.loads(sample_outputs[case_id]["steps_json"]):
                expected.add(step["resource_id"])
        for resource_id, family in pairs:
            verdict = "not a sample case"
            if case_id in sample_outputs:
                verdict = "matches sample resource" if resource_id in expected else "NOT in the sample answer"
            print(f"  {case_id} {family} {resource_id} {verdict}")

    section("2. Rank and sort key inside a shared reported_at cohort")
    families = {
        "account_delete": [
            row for row in worker
            if row["event_type"] == "DELETE_RECORD" and row["target_system"] == "account_service"
        ],
        "search_delete": [
            row for row in worker
            if row["event_type"] == "DELETE_RECORD" and row["target_system"] == "search_service"
        ],
        "analytics_anonymize": [
            row for row in worker
            if row["event_type"] == "ANONYMIZE_RECORD" and row["target_system"] == "analytics_platform" and row["reported_result"] == "SUCCESS"
        ],
        "support_redact": [
            row for row in worker
            if row["event_type"] == "REDACT_RECORD" and row["target_system"] == "support_platform"
        ],
        "identity_redact": [
            row for row in worker
            if row["event_type"] == "REDACT_RECORD" and row["target_system"] == "identity_service"
        ],
        "export_delete": [
            row for row in worker
            if row["event_type"] == "DELETE_RECORD" and canonical(row["target_system"]) == "export_service"
        ],
        "flow_disable": [
            row for row in worker
            if row["event_type"] == "DISABLE_DATA_FLOW"
        ],
        "backup_block": [
            row for row in worker
            if row["event_type"] == "BLOCK_RESTORE"
        ],
    }
    windows = {
        "account_delete": ACCOUNT_WINDOW,
        "search_delete": (0, 130 * 60),
        "analytics_anonymize": ANALYTICS_WINDOW,
        "support_redact": (0, 40 * 60),
        "identity_redact": (0, 40 * 60),
        "export_delete": (0, 40 * 60),
        "flow_disable": (0, 40 * 60),
        "backup_block": (0, 40 * 60),
    }
    prefers = {name: (window[0] + window[1]) // 2 for name, window in windows.items()}
    prefers["account_delete"] = 70 * 60
    prefers["analytics_anonymize"] = 29 * 60
    aligned_families = {
        name: align_bursts(bursts_of(rows), by_reported, windows[name], prefers[name])
        for name, rows in families.items()
    }

    comparable = 0
    agreed = 0
    for moment, cohort in by_reported.items():
        positions: dict[str, dict[str, int]] = defaultdict(dict)
        for name, aligned in aligned_families.items():
            burst = aligned.get(moment)
            if not burst:
                continue
            for index, row in enumerate(burst):
                owner = identified.get(row["resource_id"])
                if owner:
                    positions[owner][name] = index
        for _case_id, ranks in positions.items():
            values = list(ranks.values())
            if len(values) < 2:
                continue
            comparable += 1
            if len(set(values)) == 1:
                agreed += 1
    print(f"cases with a known index in two or more operation bursts: {comparable}")
    print(f"those indexes are identical across operations: {agreed}")

    def case_sort_key(name: str, row: dict[str, str]):
        user = email_user.get(row["email"].lower(), "user_0")
        identity = identity_by_user.get(user, {})
        number = int(user.split("_")[1]) if user.startswith("user_") else 0
        if name == "user_id":
            return number
        if name == "case_id":
            return int(row["case_id"].split("_")[1])
        if name == "requested_at":
            return row["requested_at"]
        if name == "email":
            return row["email"].lower()
        if name == "name":
            return identity.get("name", "").lower()
        if name == "hash":
            return identity.get("email_hash", "")
        if name == "updated_at":
            return identity.get("updated_at", "")
        if name == "phone":
            return re.sub(r"\D", "", identity.get("phone", ""))
        if name == "identity_row":
            return identity_order.get(user, 10**9)
        if name == "sha_user":
            return hashlib.sha256(user.encode()).hexdigest()
        if name == "sha_email":
            return hashlib.sha256(row["email"].lower().encode()).hexdigest()
        return number

    key_names = ["user_id", "case_id", "requested_at", "email", "name", "hash", "updated_at", "phone", "identity_row", "sha_user", "sha_email"]
    key_scores = {name: [0, 0] for name in key_names}
    labeled_bursts = 0
    for aligned in aligned_families.values():
        for moment, burst in aligned.items():
            if len(burst) < 2:
                continue
            labels = []
            cohort_ids = {row["case_id"] for row in by_reported[moment]}
            complete = True
            for row in burst:
                owner = identified.get(row["resource_id"])
                if owner not in cohort_ids:
                    complete = False
                    break
                labels.append(owner)
            if not complete or len(set(labels)) != len(labels):
                continue
            labeled_bursts += 1
            cohort = by_reported[moment]
            for name in key_names:
                ordered = [row["case_id"] for row in sorted(cohort, key=lambda item: case_sort_key(name, item))]
                rank = {case_id: index for index, case_id in enumerate(ordered)}
                good = labels == sorted(labels, key=lambda case_id: rank[case_id])
                key_scores[name][0 if good else 1] += 1
    print(f"operation bursts whose every row is evidence-labeled, length>=2: {labeled_bursts}")
    for name, (good, bad) in sorted(key_scores.items(), key=lambda item: (-item[1][0], item[1][1])):
        print(f"  {name:16} in_order={good:3d} out_of_order={bad:3d}")

    print("\nfocus cohorts, evidence rank of each case in each operation burst:")
    for moment in sorted(focus_moments):
        cohort = by_reported[moment]
        print(f"\nreported_at={moment}")
        for name, aligned in aligned_families.items():
            burst = aligned.get(moment)
            if not burst:
                continue
            rendered = []
            for index, row in enumerate(burst):
                owner = identified.get(row["resource_id"], "?")
                delta = (link.parse_time(moment) - link.parse_time(row["event_time"])).total_seconds() / 60
                rendered.append(f"{index}:{row['resource_id']}->{owner}@{row['event_time']}({delta:.0f}m)")
            print(f"  {name}: {', '.join(rendered)}")
        for row in sorted(cohort, key=lambda item: item["case_id"]):
            ranks = []
            for name, aligned in aligned_families.items():
                burst = aligned.get(moment, [])
                for index, activity_row in enumerate(burst):
                    if identified.get(activity_row["resource_id"]) == row["case_id"]:
                        ranks.append(f"{name}[{index}]={activity_row['resource_id']}")
            if ranks:
                print(f"  {row['case_id']} ranks: {', '.join(ranks)}")

    section("3. Raw records for the 16 leftover resources")
    texts = []
    for row in manifest:
        path = DATASET / row["file_path"]
        if path.suffix.lower() not in {".json", ".sql", ".log", ".txt", ".csv"}:
            continue
        texts.append((row, path.read_text(encoding="utf-8", errors="ignore")))
    activity_by_resource = defaultdict(list)
    for row in activity:
        activity_by_resource[row["resource_id"]].append(row)
    obs_by_resource = defaultdict(list)
    for obs in observations:
        obs_by_resource[obs.resource_id].append(obs)

    for resource_id, sample_case in SAMPLE_FOCUS.items():
        if resource_id.startswith("audit_record_"):
            continue
        print(f"\n{resource_id} sample_case={sample_case} evidence_owner={identified.get(resource_id, 'none')}")
        rows = activity_by_resource.get(resource_id, [])
        if not rows:
            print("  activity: none")
        for row in rows:
            print("  activity " + json.dumps(row, ensure_ascii=False))
        parsed = obs_by_resource.get(resource_id, [])
        if not parsed:
            print("  parsed observations: none")
        for obs in parsed:
            print(
                f"  obs file={obs.file_id} captured={obs.captured_at} observed={obs.observed_at} "
                f"system={obs.system_id} present={obs.present} pattern={obs.pattern} "
                f"emails={sorted(obs.emails)} phones={sorted(obs.phones)} users={sorted(obs.user_ids)} "
                f"hashes={sorted(obs.hashes)}"
            )
        evidence = raw_records(resource_id, texts)
        if not evidence:
            print("  raw evidence: none")
        for blob in evidence:
            print(blob)

    section("3b. case_18 and case_20 windows against the two absent audit ids")
    for case_id, audit_id in (("case_18", "audit_record_6645"), ("case_20", "audit_record_5569")):
        request = requests_by_id[case_id]
        user_ids, tokens = verify.identity_tokens(request["email"], identities, audits)
        print(f"\n{case_id} email={request['email']} users={sorted(user_ids)}")
        print(f"  requested_at={request['requested_at']} reported_at={request['reported_at']} audit_at={request['audit_at']}")
        for user_id in sorted(user_ids):
            identity = identity_by_user.get(user_id, {})
            print(
                f"  identity {user_id} name={identity.get('name')} email={identity.get('email')} "
                f"phone={identity.get('phone')} hash={identity.get('email_hash')} updated={identity.get('updated_at')}"
            )
            blob = json.dumps(identity)
            print(f"  {audit_id} occurs in the identity row: {audit_id.split('_')[-1] in blob}")
        print(f"  activity rows whose resource_id is {audit_id}: {len(activity_by_resource.get(audit_id, []))}")
        print(f"  parsed observations of {audit_id}: {len(obs_by_resource.get(audit_id, []))}")
        start = link.parse_time(request["reported_at"]) - timedelta(hours=3)
        end = link.parse_time(request["audit_at"])
        linked_resources = {resource_id for resource_id, owner in identified.items() if owner == case_id}
        window_rows = []
        for row in activity:
            event = link.parse_time(row["event_time"])
            if not start <= event <= end:
                continue
            detail = row["details"].lower()
            if (
                row["resource_id"] in linked_resources
                or row["resource_id"] == audit_id
                or any(email in detail for email in tokens["emails"])
                or any(user_id in detail for user_id in user_ids)
            ):
                window_rows.append(row)
        print(f"  activity rows in the case window that name this person or the audit id: {len(window_rows)}")
        for row in window_rows:
            print(
                f"    {row['activity_id']} {row['event_time']} {row['event_type']} "
                f"{row['target_system']} {row['resource_id']} {row['reported_result']} {row['details']}"
            )
        print("  evidence observations that touch this person:")
        for obs in observations:
            if not obs.touches(tokens):
                continue
            print(
                f"    {obs.file_id} captured={obs.captured_at} observed={obs.observed_at} "
                f"{obs.system_id} {obs.resource_id} present={obs.present} users={sorted(obs.user_ids)} emails={sorted(obs.emails)}"
            )

    section("4. Rescore the 32 samples after unique elimination assignments")
    extras = []
    for case_id, pairs in assignments.items():
        if case_id not in requests_by_id:
            continue
        email = requests_by_id[case_id]["email"].lower()
        for resource_id, family in pairs:
            system_id = "account_service" if family == "account" else "analytics_platform"
            category = "USER_PROFILE" if family == "account" else "ANALYTICS_PROFILE"
            extras.append(verify.Obs(
                file_id="",
                captured_at="2099-01-01T00:00:00Z",
                observed_at="2099-01-01T00:00:00Z",
                system_id=system_id,
                resource_id=resource_id,
                category=category,
                pattern="cohort_elimination",
                emails={email},
                present=False,
            ))
    crack.score_linker(
        sample_requests,
        sample_outputs,
        observations + extras,
        activity,
        identities,
        audits,
        requests,
    )


if __name__ == "__main__":
    main()
