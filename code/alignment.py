"""Fill anonymous snapshot rows only when every legal order agrees.

Collections whose known user ids increase down the file are user-id order.
An anonymous analytics row may sit in the gap between two anchors. It is
assigned only when the anonymize cohort and the anchors leave exactly one user.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from code.evidence import DATASET, Obs
from code.load_data import parse_time

USER_RE = re.compile(r"user_(\d+)")
RESOURCE_RE = re.compile(r"\b(?:account|analytics|audit_record|search|export|support|backup|tombstone|data_flow)_\d+\b")
ACCOUNT_WINDOW = (50 * 60, 90 * 60)
ANALYTICS_WINDOW = (20 * 60, 40 * 60)
BURST_GAP = 20 * 60


def _bursts_of(rows: list[dict[str, str]]) -> list[list[dict[str, str]]]:
    rows = sorted(rows, key=lambda row: row["event_time"])
    grouped: list[list[dict[str, str]]] = []
    current: list[dict[str, str]] = []
    for row in rows:
        if current and (parse_time(row["event_time"]) - parse_time(current[-1]["event_time"])).total_seconds() > BURST_GAP:
            grouped.append(current)
            current = []
        current.append(row)
    if current:
        grouped.append(current)
    return grouped


def _align_bursts(
    grouped: list[list[dict[str, str]]],
    by_reported: dict[str, list[dict[str, str]]],
    window: tuple[int, int],
    prefer: int,
) -> dict[str, list[dict[str, str]]]:
    candidates = []
    for grouped_rows in grouped:
        start = parse_time(grouped_rows[0]["event_time"])
        for moment, cohort in by_reported.items():
            delta = (parse_time(moment) - start).total_seconds()
            if not window[0] <= delta <= window[1]:
                continue
            candidates.append((abs(len(cohort) - len(grouped_rows)), abs(delta - prefer), moment, grouped_rows))
    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    assigned: dict[str, list[dict[str, str]]] = {}
    used: set[int] = set()
    for _gap, _delta, moment, grouped_rows in candidates:
        identity = id(grouped_rows)
        if moment in assigned or identity in used:
            continue
        assigned[moment] = grouped_rows
        used.add(identity)
    return assigned


def _iter_collections(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("snapshots"), list):
            for snap in payload["snapshots"]:
                label = f"{snap.get('captured_at')} {snap.get('data_store')} {snap.get('collection')}"
                yield label, list(snap.get("records") or [])
        if isinstance(payload, dict) and isinstance(payload.get("service_exports"), dict):
            for service, block in payload["service_exports"].items():
                if not isinstance(block, dict):
                    continue
                for name, records in block.items():
                    if isinstance(records, list):
                        yield f"{service} {name}", list(records)
        return
    if suffix == ".sql":
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
    if suffix in {".log", ".txt"}:
        records = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            found = RESOURCE_RE.findall(line)
            if found:
                records.append({"resource_id": found[0], "line": line.strip()})
        if records:
            yield path.name, records


def _blob(record: dict) -> str:
    if "line" in record:
        return record["line"]
    return json.dumps(record, default=str)


def _on_record_users(record: dict) -> list[int]:
    return [int(value) for value in USER_RE.findall(_blob(record))]


def _collapse(records: list[dict]) -> list[dict]:
    collapsed = []
    for record in records:
        if collapsed and collapsed[-1].get("resource_id") == record.get("resource_id"):
            continue
        collapsed.append(record)
    return collapsed


def _monotonic_analytics(manifest: list[dict[str, str]]) -> list[list[dict]]:
    found = []
    for row in manifest:
        path = DATASET / row["file_path"]
        if path.suffix.lower() not in {".json", ".sql", ".log", ".txt"}:
            continue
        try:
            collections = list(_iter_collections(path))
        except (OSError, json.JSONDecodeError):
            continue
        for _label, records in collections:
            records = _collapse(records)
            if not any(str(record.get("resource_id", "")).startswith("analytics_") for record in records):
                continue
            known = [_on_record_users(record) for record in records]
            anchors = [users[0] for users in known if users]
            if len(anchors) < 2 or anchors != sorted(anchors) or len(set(anchors)) != len(anchors):
                continue
            found.append(records)
    return found


def _cohort_users(requests: list[dict[str, str]], activity: list[dict[str, str]], email_user: dict[str, str]) -> dict[str, set[int]]:
    by_reported: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in requests:
        by_reported[row["reported_at"]].append(row)
    worker = [
        row for row in activity
        if row["source_system"] == "deletion_worker" and "Target resource:" not in row["details"]
    ]
    analytics = _align_bursts(
        _bursts_of([
            row for row in worker
            if row["event_type"] == "ANONYMIZE_RECORD"
            and row["target_system"] == "analytics_platform"
            and row["reported_result"] == "SUCCESS"
        ]),
        by_reported,
        ANALYTICS_WINDOW,
        29 * 60,
    )
    allowed: dict[str, set[int]] = {}
    for moment, rows in analytics.items():
        users = set()
        for case in by_reported[moment]:
            user_id = email_user.get(case["email"].lower(), "")
            if user_id.startswith("user_"):
                users.add(int(user_id.split("_")[1]))
        for row in rows:
            allowed[row["resource_id"]] = users
    return allowed


def _solve(records: list[dict], allowed: dict[str, set[int]]) -> list[dict[str, int]]:
    sequence = [str(record.get("resource_id")) for record in records]
    anchors = {}
    for record in records:
        users = _on_record_users(record)
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


def _unique(solutions: list[dict[str, int]]) -> dict[str, int]:
    if not solutions:
        return {}
    agreed = {}
    keys = set.intersection(*(set(solution) for solution in solutions))
    for resource_id in keys:
        values = {solution[resource_id] for solution in solutions}
        if len(values) == 1:
            agreed[resource_id] = next(iter(values))
    return agreed


def alignment_observations(
    manifest: list[dict[str, str]],
    requests: list[dict[str, str]],
    activity: list[dict[str, str]],
    email_user: dict[str, str],
    user_case: dict[str, str],
    requests_by_id: dict[str, dict[str, str]],
) -> list[Obs]:
    allowed = _cohort_users(requests, activity, email_user)
    agreed: dict[str, int] = {}
    for records in _monotonic_analytics(manifest):
        agreed.update(_unique(_solve(records, allowed)))
    extras = []
    for resource_id, user_number in sorted(agreed.items()):
        case_id = user_case.get(f"user_{user_number}", "")
        if not case_id:
            continue
        extras.append(Obs(
            file_id="",
            captured_at="2099-01-01T00:00:00Z",
            observed_at="2099-01-01T00:00:00Z",
            system_id="analytics_platform",
            resource_id=resource_id,
            category="ANALYTICS_PROFILE",
            pattern="snapshot_user_alignment",
            emails={requests_by_id[case_id]["email"].lower()},
            present=False,
        ))
    return extras
