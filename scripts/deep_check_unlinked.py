"""Decompress the four PDFs, scan the screenshots, and score leftover pairing.

solve_burst_assignment assigns a burst row only when one case and one row
remain. This script zips equal-length leftovers with the remaining deletion
cases, using case_id, requested_at, or updated_at, and rescores the 32 samples.
"""

from __future__ import annotations

import base64
import json
import re
import struct
import sys
import zlib
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import crack_remaining_16 as crack  # noqa: E402
import solve_burst_assignment as burst  # noqa: E402
import solve_resource_linking as link  # noqa: E402

verify = link.verify
DATASET = link.DATASET

FOCUS = [
    "2026-08-30T12:00:00Z",
    "2026-09-01T10:00:00Z",
    "2026-09-02T12:00:00Z",
    "2026-09-05T12:00:00Z",
    "2026-09-06T12:00:00Z",
    "2026-09-09T11:00:00Z",
    "2026-09-15T11:00:00Z",
]
NEEDLES = [
    "6645", "5569", "6440", "5335", "1895", "4566", "4574", "6077", "9406",
    "4857", "8858", "5521", "5037", "4990", "5482", "7012", "3136", "6829",
    "account_410", "audit_record_6645", "audit_record_5569", "analytics_5335",
]
NON_DELETION = re.compile(
    r"not a request to erase|do not close|leave the account active|keep the account|"
    r"without removing|marketing lists only|leave my profile|continue using the service|"
    r"information request",
    re.IGNORECASE,
)
DELETION = re.compile(
    r"delet|eras|exclu|supprim|삭제|削除|suppression|remov|close the account|closed|"
    r"forget|profile is gone|permanen",
    re.IGNORECASE,
)
SCOPE_WORDS = ("analytics", "search", "backup", "support", "export", "audit", "tombstone", "account", "integration")


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


def pdf_literals(data: bytes) -> list[str]:
    lines = []
    index = 0
    while index < len(data):
        if data[index] != 0x28:
            index += 1
            continue
        index += 1
        chars = bytearray()
        depth = 1
        while index < len(data) and depth:
            char = data[index]
            if char == 0x5C and index + 1 < len(data):
                index += 1
                escaped = data[index]
                mapping = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12, ord("("): 40, ord(")"): 41, ord("\\"): 92}
                if escaped in mapping:
                    chars.append(mapping[escaped])
                elif 48 <= escaped <= 55:
                    octal = bytes([escaped])
                    for _ in range(2):
                        if index + 1 < len(data) and 48 <= data[index + 1] <= 55:
                            index += 1
                            octal += bytes([data[index]])
                    chars.append(int(octal, 8) & 0xFF)
                else:
                    chars.append(escaped)
            elif char == 0x28:
                depth += 1
                chars.append(char)
            elif char == 0x29:
                depth -= 1
                if depth:
                    chars.append(char)
            else:
                chars.append(char)
            index += 1
        text = chars.decode("latin-1", errors="replace").strip()
        if text:
            lines.append(text)
    return lines


def pdf_streams(payload: bytes) -> list[bytes]:
    decoded = []
    pattern = re.compile(br"/Filter\s*\[([^\]]+)\]\s*/Length\s+(\d+)\s*>>\s*stream\r?\n")
    for match in pattern.finditer(payload):
        filters = match.group(1)
        length = int(match.group(2))
        chunk = payload[match.end(): match.end() + length]
        try:
            if b"ASCII85Decode" in filters:
                chunk = base64.a85decode(chunk, adobe=True)
            if b"FlateDecode" in filters:
                chunk = zlib.decompress(chunk)
        except Exception as exc:
            decoded.append(f"[stream decode failed: {exc}]".encode())
            continue
        decoded.append(chunk)
    return decoded


def inspect_pdfs() -> None:
    section("1. Decompressed text from all four PDFs")
    documents = sorted((DATASET / "evidence" / "documents").glob("*.pdf"))
    combined = []
    for path in documents:
        payload = path.read_bytes()
        print(f"\n--- {path.name} bytes={len(payload)} flate={payload.count(b'FlateDecode')} ascii85={payload.count(b'ASCII85Decode')}")
        lines = []
        for stream in pdf_streams(payload):
            if stream.startswith(b"/CIDInit") or stream.startswith(b"\x00\x01"):
                continue
            lines.extend(pdf_literals(stream))
        if not lines:
            print("  no text literals recovered")
        for line in lines:
            print(f"  {line}")
            combined.append(line)
    text = "\n".join(combined)
    print("\nNeedle search in decompressed PDF text:")
    for needle in NEEDLES:
        print(f"  {needle}: {'FOUND' if needle in text else 'absent'}")


def inspect_pngs() -> None:
    section("1b. PNG chunk and byte search (11 screenshots)")
    images = sorted((DATASET / "evidence" / "images").glob("*.png"))
    print(f"png count={len(images)}")
    for path in images:
        payload = path.read_bytes()
        width, height = struct.unpack(">II", payload[16:24])
        chunks = []
        texts = []
        offset = 8
        while offset + 8 <= len(payload):
            length, kind = struct.unpack(">I4s", payload[offset: offset + 8])
            kind_name = kind.decode("latin-1")
            chunks.append(kind_name)
            data = payload[offset + 8: offset + 8 + length]
            if kind_name in {"tEXt", "zTXt", "iTXt"}:
                texts.append(data.decode("latin-1", errors="replace")[:200])
            offset += 12 + length
            if kind_name == "IEND":
                break
        hits = [needle for needle in NEEDLES if needle.encode() in payload]
        print(f"  {path.name} {width}x{height} chunks={chunks} text_chunks={texts or 'none'} byte_needles={hits or 'none'}")


def sort_value(name: str, row: dict[str, str], identity_by_user: dict[str, dict], email_user: dict[str, str]):
    user = email_user[row["email"].lower()]
    identity = identity_by_user[user]
    if name == "case_id":
        return (case_number(row["case_id"]),)
    if name == "requested_at":
        return (row["requested_at"], case_number(row["case_id"]))
    return (identity.get("updated_at", ""), case_number(row["case_id"]))


def main() -> None:
    inspect_pdfs()
    inspect_pngs()

    identities = link.load_csv("user_identities.csv")
    audits = link.load_csv("user_audit_log.csv")
    activity = link.load_csv("system_activity.csv")
    manifest = link.load_csv("evidence_files.csv")
    sample_requests = link.load_csv("sample_deletion_requests.csv")
    eval_requests = link.load_csv("deletion_requests.csv")
    requests = sample_requests + eval_requests
    requests_by_id = {row["case_id"]: row for row in requests}
    identity_by_user = {row["user_id"]: row for row in identities}
    email_user = {row["email"].lower(): row["user_id"] for row in identities}
    for row in audits:
        if row["field_name"] == "email":
            email_user.setdefault(row["old_value"].lower(), row["user_id"])
            email_user.setdefault(row["new_value"].lower(), row["user_id"])
    sample_owner = {}
    for row in link.load_csv("sample_output.csv"):
        for step in json.loads(row["steps_json"]):
            sample_owner[step["resource_id"]] = row["case_id"]
    sample_outputs = {row["case_id"]: row for row in link.load_csv("sample_output.csv")}

    observations, _patterns, _unparsed = verify.load_observations(manifest)
    observations = [obs for obs in observations if obs.pattern not in link.EXCLUDED_PATTERNS]
    identified = burst.evidence_owners(observations, requests, identities, audits)
    for resource_id, case_id in burst.link_owners(activity, requests, identities, audits).items():
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
        return authorizes_deletion(row["request_text"])

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

    def leftovers(moment: str, family: str):
        cohort = by_reported[moment]
        rows = families[family].get(moment, [])
        prefix = "account_" if family == "account" else "analytics_"
        waiting = []
        for row in cohort:
            if not is_deletion(row):
                continue
            if any(resource_id.startswith(prefix) for resource_id in satisfied[row["case_id"]]):
                continue
            waiting.append(row)
        unknown = [row for row in rows if row["resource_id"] not in taken]
        return waiting, unknown

    section("2. Request text scope hints for 2026-09-02 and 2026-09-05")
    for moment in ("2026-09-02T12:00:00Z", "2026-09-05T12:00:00Z"):
        print(f"\n{moment}")
        for row in sorted(by_reported[moment], key=lambda item: case_number(item["case_id"])):
            hints = [word for word in SCOPE_WORDS if word in row["request_text"].lower()]
            print(f"  {row['case_id']} deletion={is_deletion(row)} hints={hints or 'none'}")
            print(f"    {row['request_text']}")

    section("2b. Evidence search for the four unlabeled 2026-09-05 accounts")
    texts = []
    for row in manifest:
        path = DATASET / row["file_path"]
        if path.suffix.lower() in {".json", ".sql", ".log", ".txt", ".csv"}:
            texts.append((row["file_id"], path.read_text(encoding="utf-8", errors="ignore")))
    for resource_id in ("account_294", "account_8832", "account_7015", "account_9155", "account_5605"):
        activity_hits = [row["activity_id"] for row in activity if row["resource_id"] == resource_id]
        file_hits = [file_id for file_id, text in texts if re.search(rf"(?<![A-Za-z0-9_]){resource_id}(?![A-Za-z0-9_])", text)]
        print(f"  {resource_id} activity={activity_hits or 'none'} evidence={file_hits or 'none'} owner={identified.get(resource_id, 'none')}")

    section("2c. Time offsets of unidentified rows versus known rows")
    for moment in FOCUS:
        print(f"\n{moment}")
        cohort = {row["case_id"]: row for row in by_reported[moment]}
        for family in ("account", "analytics"):
            waiting, unknown = leftovers(moment, family)
            burst_rows = families[family].get(moment, [])
            print(f"  {family} burst={len(burst_rows)} waiting={ [row['case_id'] for row in waiting] } unknown={[row['resource_id'] for row in unknown]}")
            known = [row for row in burst_rows if row["resource_id"] in taken]
            for row in known:
                owner = next(case_id for case_id, resources in satisfied.items() if row["resource_id"] in resources)
                request = requests_by_id.get(owner)
                if request is None:
                    continue
                delta = (link.parse_time(row["event_time"]) - link.parse_time(request["requested_at"])).total_seconds()
                print(f"    known {row['resource_id']} {owner} event={row['event_time']} offset_from_requested={delta:.0f}s")
            for row in unknown:
                print(f"    unknown {row['resource_id']} event={row['event_time']}")
                for case in waiting:
                    delta = (link.parse_time(row["event_time"]) - link.parse_time(case["requested_at"])).total_seconds()
                    print(f"      offset from {case['case_id']} requested_at = {delta:.0f}s")

    section("3. Pair equal-length leftovers and rescore the 32 samples")
    print("A cohort is paired only when the number of unidentified burst rows equals the number of deletion cases that still lack that resource.")
    keys = ("case_id", "requested_at", "updated_at")
    assignments = {name: defaultdict(list) for name in keys}
    for moment, cohort in by_reported.items():
        for family in ("account", "analytics"):
            waiting, unknown = leftovers(moment, family)
            if len(waiting) != len(unknown) or not waiting:
                if moment in FOCUS:
                    print(f"  {moment} {family}: waiting={len(waiting)} unknown={len(unknown)} no zip")
                continue
            if moment in FOCUS:
                print(f"  {moment} {family}: zip {len(waiting)} rows")
            for name in keys:
                ordered = sorted(waiting, key=lambda row: sort_value(name, row, identity_by_user, email_user))
                pairs = list(zip(ordered, unknown))
                if moment in FOCUS:
                    rendered = ", ".join(
                        f"{case['case_id']}->{row['resource_id']}"
                        + (f" sample={sample_owner.get(row['resource_id'])}" if row["resource_id"] in sample_owner else "")
                        for case, row in pairs
                    )
                    print(f"    {name}: {rendered}")
                for case, row in pairs:
                    assignments[name][case["case_id"]].append((row["resource_id"], family))

    for name in keys:
        extras = []
        for case_id, pairs in assignments[name].items():
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
                    pattern="leftover_pairing",
                    emails={email},
                    present=False,
                ))
        print()
        print(f"--- rescore pairing key={name} injected={len(extras)}")
        crack.score_linker(sample_requests, sample_outputs, observations + extras, activity, identities, audits, requests)


if __name__ == "__main__":
    main()
