"""Cite an account as absent from the latest full census at or before audit_at.

A full census is a SQL profile replica of at least three rows, or a
customer_profiles snapshot whose record list is empty. A one-row extract is not
a census. The later census wins.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime

from code.evidence import DATASET, Obs
from code.load_data import load_csv, parse_time


def empty_account_censuses() -> list[tuple[str, str]]:
    cached = getattr(empty_account_censuses, "cache", None)
    if cached is not None:
        return cached
    found: list[tuple[str, str]] = []
    for row in load_csv("evidence_files.csv"):
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


def latest_absence(observations: list[Obs], audit_at: datetime, resource_id: str) -> tuple[str, str] | None:
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
        captured_at = parse_time(captured[file_id])
        if captured_at > audit_at:
            continue
        if any(obs.file_id == file_id and obs.resource_id == resource_id and obs.present for obs in observations):
            continue
        if chosen is None or captured_at >= chosen[0]:
            chosen = (captured_at, file_id, captured[file_id])
    for file_id, stamp in empty_account_censuses():
        captured_at = parse_time(stamp)
        if captured_at > audit_at:
            continue
        if chosen is None or captured_at >= chosen[0]:
            chosen = (captured_at, file_id, stamp)
    if chosen is None:
        return None
    return chosen[1], chosen[2]


def synthetic_absent(resource_id: str, file_id: str, captured_at: str) -> Obs:
    from code.evidence import category_for_resource
    from code.linking import CANONICAL_SYSTEM

    category = category_for_resource(resource_id, "account_service")
    return Obs(
        file_id=file_id,
        captured_at=captured_at,
        observed_at=captured_at,
        system_id=CANONICAL_SYSTEM.get(category, "account_service"),
        resource_id=resource_id,
        category=category,
        pattern="absence_snapshot",
        present=False,
        identifiable=False,
    )


def synthetic_present_audit(resource_id: str, audit_at: datetime) -> Obs:
    stamp = audit_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    return Obs(
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
