"""Deep-dive the 32 sample cases, system activity, and evidence schemas.

Reads only participant-facing files under dataset/. Prints the step vocabulary,
evidence-id citation rules, five diverse fully expanded cases, system and
origin inventories, how resource ids join to people, file-format samples, and
request-text / CLASSIFY_REQUEST patterns.
"""

from __future__ import annotations

import csv
import json
import re
import sqlite3
import struct
import zlib
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
EVIDENCE = DATASET / "evidence"

OP_ORDER = {
    "FINDING": [
        "REPORT_REMAINING_RECORD",
        "REPORT_EXPOSED_PII",
        "REPORT_ACTIVE_DATA_FLOW",
        "REPORT_RESTORE_RISK",
    ],
    "REMEDIATION": [
        "DISABLE_DATA_FLOW",
        "BLOCK_RESTORE",
        "DELETE_RECORD",
        "REDACT_RECORD",
        "ANONYMIZE_RECORD",
    ],
    "VERIFICATION": [
        "VERIFY_RECORD_ABSENT",
        "VERIFY_RECORD_PRESENT",
        "VERIFY_RECORD_REDACTED",
        "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED",
        "VERIFY_RESTORE_BLOCKED",
    ],
}

FINDING_TO_FIX = {
    "REPORT_REMAINING_RECORD": "DELETE_RECORD",
    "REPORT_ACTIVE_DATA_FLOW": "DISABLE_DATA_FLOW",
    "REPORT_RESTORE_RISK": "BLOCK_RESTORE",
}

EXPOSED_FIXES = {"REDACT_RECORD", "ANONYMIZE_RECORD"}

DELETION_CUES = (
    "delet",
    "eras",
    "erase",
    "remov",
    "close my account",
    "close the account",
    "cerrar",
    "elimin",
    "supprim",
    "effac",
    "borrar",
    "borrad",
    "lösch",
    "losch",
    "cancell",
    "cancelar",
    "excluir",
    "apagar",
    "usuń",
    "usun",
    "silmem",
    "hesabımı",
    "hapus",
    "删除",
    "削除",
    "삭제",
    "حذف",
    "удал",
    "sterge",
    "șterge",
    "obriši",
    "izbriši",
    "töröl",
    "poista",
    "radera",
    "slet",
    "verwijder",
    "supprimer",
    "suppression",
    "gdpr",
    "right to be forgotten",
    "be forgotten",
)

NON_DELETION_CUES = (
    "do not delete",
    "don't delete",
    "not asking you to delete",
    "not a deletion",
    "access my",
    "copy of my",
    "send me a copy",
    "send me my",
    "export my",
    "portability",
    "correct my",
    "rectif",
    "update my address",
    "update my name",
    "change my email",
    "unsubscribe",
    "opt out",
    "opt-out",
    "marketing email",
    "stop emailing",
    "stop sending",
    "accès",
    "acceder",
    "acceso",
    "copie de",
    "corregir",
    "corriger",
    "berichtigen",
    "auskunft",
    "newsletter",
)


def load(name: str) -> list[dict[str, str]]:
    with (DATASET / name).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def section(title: str) -> None:
    print()
    print("=" * 88)
    print(title)
    print("=" * 88)


def token_in(text: str, token: str) -> bool:
    if not token:
        return False
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])", text) is not None


def evidence_prefix(evidence_id: str) -> str:
    if not evidence_id:
        return "(empty)"
    match = re.match(r"^[A-Za-z]+_", evidence_id)
    return match.group(0) if match else evidence_id


def sort_key(step: dict) -> tuple:
    phase = step["phase"]
    ops = OP_ORDER[phase]
    return (list(OP_ORDER).index(phase), ops.index(step["operation"]), step["system_id"], step["resource_id"])


def png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return (0, 0)
    return struct.unpack(">II", data[16:24])


def pdf_text(path: Path, limit: int = 1800) -> str:
    data = path.read_bytes()
    pieces: list[str] = []
    streams = re.findall(rb"stream\r?\n(.*?)\r?\nendstream", data, flags=re.S)
    decoded: list[bytes] = []
    for raw in streams:
        blob = raw.strip(b"\r\n")
        inflated = None
        for decoder in (
            lambda b: zlib.decompress(b),
            lambda b: zlib.decompress(b, -15),
        ):
            try:
                inflated = decoder(blob)
                break
            except zlib.error:
                continue
        decoded.append(inflated if inflated is not None else blob)
    decoded.append(data)
    for blob in decoded:
        for match in re.findall(rb"\((?:\\.|[^\\)]){2,}\)", blob):
            inner = match[1:-1]
            inner = (
                inner.replace(b"\\n", b"\n")
                .replace(b"\\r", b"\r")
                .replace(b"\\t", b"\t")
                .replace(b"\\(", b"(")
                .replace(b"\\)", b")")
                .replace(b"\\\\", b"\\")
            )
            text = inner.decode("latin-1", errors="ignore").strip()
            if text:
                pieces.append(text)
        for match in re.findall(rb"[\x20-\x7e]{12,}", blob):
            pieces.append(match.decode("ascii"))
    unique: list[str] = []
    seen: set[str] = set()
    for piece in pieces:
        if piece in seen:
            continue
        seen.add(piece)
        unique.append(piece)
    rendered = "\n".join(unique)
    useful = [
        word
        for word in re.findall(r"[A-Za-z]{4,}", rendered)
        if word.lower() not in {"stream", "endstream", "endobj", "flatedecode", "length", "filter", "opensource"}
    ]
    if len(useful) < 12:
        return "(stdlib parser could not decode the Flate-compressed text layer)"
    if len(rendered) > limit:
        return rendered[:limit] + "\n...[truncated]..."
    return rendered or "(no extractable text)"


def json_record_samples(obj: object, samples: dict[str, object], label: str) -> None:
    if isinstance(obj, dict):
        if "resource_id" in obj and label not in samples:
            samples[label] = obj
        for key, value in obj.items():
            child = f"{label}.{key}" if label else key
            if isinstance(value, list) and value and isinstance(value[0], dict):
                json_record_samples(value[0], samples, child)
            elif isinstance(value, dict):
                json_record_samples(value, samples, child)
    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
        json_record_samples(obj[0], samples, label)


def main() -> None:
    requests = load("sample_deletion_requests.csv")
    outputs = load("sample_output.csv")
    identities = load("user_identities.csv")
    audits = load("user_audit_log.csv")
    activity = load("system_activity.csv")
    evidence_files = load("evidence_files.csv")
    eval_requests = load("deletion_requests.csv")

    by_case_req = {row["case_id"]: row for row in requests}
    by_case_out = {row["case_id"]: row for row in outputs}
    evidence_by_id = {row["file_id"]: row for row in evidence_files}
    steps_by_case = {row["case_id"]: json.loads(row["steps_json"]) for row in outputs}

    section("1. Distinct (phase, operation, state) combinations")
    combos: Counter[tuple[str, str, str]] = Counter()
    for steps in steps_by_case.values():
        for step in steps:
            combos[(step["phase"], step["operation"], step["state"])] += 1
    for key in sorted(combos, key=lambda item: (list(OP_ORDER).index(item[0]), OP_ORDER[item[0]].index(item[1]))):
        print(f"{combos[key]:4d}  {key[0]:14} {key[1]:28} {key[2]}")

    section("1b. evidence_id prefixes, operations, and systems")
    prefix_counts: Counter[str] = Counter()
    citation: Counter[tuple[str, str, str]] = Counter()
    cited_files: Counter[str] = Counter()
    for case_id, steps in steps_by_case.items():
        for step in steps:
            prefix = evidence_prefix(step["evidence_id"])
            prefix_counts[prefix] += 1
            citation[(prefix, step["operation"], step["system_id"])] += 1
            if step["evidence_id"]:
                cited_files[step["evidence_id"]] += 1
    print("prefix counts:", dict(prefix_counts))
    print("activity_ / audit_ citations:", prefix_counts.get("activity_", 0), prefix_counts.get("audit_", 0))
    print("citation rows (prefix, operation, system_id) -> count:")
    for key, count in sorted(citation.items()):
        print(f"  {count:3d}  {key[0]:12} {key[1]:28} {key[2]}")
    print("cited file ids:")
    for file_id, count in sorted(cited_files.items(), key=lambda item: item[0]):
        meta = evidence_by_id.get(file_id)
        if meta is None:
            print(f"  {file_id} MISSING FROM MANIFEST ({count} citations)")
        else:
            print(f"  {file_id} x{count}  {meta['captured_at']}  {meta['origin']}  {meta['file_path']}")

    section("1c. Invariants across all 32 sample answers")
    violations: list[str] = []
    for case_id, row in by_case_out.items():
        steps = steps_by_case[case_id]
        status = row["deletion_status"]
        if [step["step_no"] for step in steps] != list(range(1, len(steps) + 1)):
            violations.append(f"{case_id} step_no not consecutive")
        if steps != sorted(steps, key=sort_key):
            violations.append(f"{case_id} not ordered by phase, operation table, system_id, resource_id")
        phases = [step["phase"] for step in steps]
        if phases != sorted(phases, key=lambda phase: list(OP_ORDER).index(phase)):
            violations.append(f"{case_id} phase order broken")
        for step in steps:
            if step["operation"] not in OP_ORDER[step["phase"]]:
                violations.append(f"{case_id} bad op {step['operation']} in {step['phase']}")
        if status == "COMPLETE":
            if any(step["phase"] != "VERIFICATION" for step in steps):
                violations.append(f"{case_id} COMPLETE has a non-verification step")
            if any(not step["evidence_id"] for step in steps):
                violations.append(f"{case_id} COMPLETE verification missing evidence_id")
        elif status == "INCOMPLETE":
            findings = [step for step in steps if step["phase"] == "FINDING"]
            remediations = [step for step in steps if step["phase"] == "REMEDIATION"]
            verifications = [step for step in steps if step["phase"] == "VERIFICATION"]
            if not findings:
                violations.append(f"{case_id} INCOMPLETE has no finding")
            if any(not step["evidence_id"] for step in findings):
                violations.append(f"{case_id} finding missing evidence_id")
            if any(step["evidence_id"] for step in remediations + verifications):
                violations.append(f"{case_id} remediation or future verification has evidence_id")
            finding_keys = {(step["system_id"], step["resource_id"]): step["operation"] for step in findings}
            fix_keys = {(step["system_id"], step["resource_id"]): step["operation"] for step in remediations}
            for key, operation in finding_keys.items():
                if key not in fix_keys:
                    violations.append(f"{case_id} finding {operation} {key} has no remediation")
                    continue
                expected = FINDING_TO_FIX.get(operation)
                if expected and fix_keys[key] != expected:
                    violations.append(f"{case_id} {key} finding {operation} remediated by {fix_keys[key]}")
                if operation == "REPORT_EXPOSED_PII" and fix_keys[key] not in EXPOSED_FIXES:
                    violations.append(f"{case_id} exposed PII remediated by {fix_keys[key]}")
        else:
            violations.append(f"{case_id} unexpected status {status}")
    print("violations:" if violations else "no invariant violations on the 32 sample answers")
    for item in violations:
        print(" ", item)

    print("resources verified without a finding (already in the required state):")
    for case_id, steps in steps_by_case.items():
        finding_keys = {(step["system_id"], step["resource_id"]) for step in steps if step["phase"] == "FINDING"}
        extras = [
            f"{step['operation']}:{step['system_id']}/{step['resource_id']}"
            for step in steps
            if step["phase"] == "VERIFICATION" and (step["system_id"], step["resource_id"]) not in finding_keys
        ]
        if extras:
            print(f"  {case_id} {by_case_out[case_id]['deletion_status']}: {', '.join(extras)}")

    prefixes = Counter()
    for steps in steps_by_case.values():
        for step in steps:
            prefix = re.match(r"[a-z_]+", step["resource_id"])
            prefixes[prefix.group(0) if prefix else step["resource_id"]] += 1
    print("resource_id prefixes in sample steps:", dict(sorted(prefixes.items())))

    section("2. Five diverse cases")
    chosen = [
        ("case_26", "COMPLETE across six systems, including retained, redacted, anonymized, disabled flow, blocked restore"),
        ("case_32", "INCOMPLETE whose only finding is REPORT_EXPOSED_PII on an identity tombstone"),
        ("case_15", "INCOMPLETE whose only finding is REPORT_ACTIVE_DATA_FLOW"),
        ("case_09", "INCOMPLETE whose only finding is REPORT_RESTORE_RISK"),
        ("case_11", "INCOMPLETE with remaining record, exposed PII, active flow, redact, and anonymize"),
    ]
    identity_by_email = {row["email"].lower(): row for row in identities}
    audits_by_user: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in audits:
        audits_by_user[row["user_id"]].append(row)

    for case_id, reason in chosen:
        request = by_case_req[case_id]
        steps = steps_by_case[case_id]
        print()
        print("-" * 88)
        print(f"{case_id}  {by_case_out[case_id]['deletion_status']}  — {reason}")
        print("-" * 88)
        print("a) request")
        for field in ("case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"):
            print(f"  {field}: {request[field]}")

        email = request["email"].lower()
        current = identity_by_email.get(email)
        historical = [
            row
            for row in audits
            if row["field_name"] == "email" and email in {row["old_value"].lower(), row["new_value"].lower()}
        ]
        user_ids = set()
        if current:
            user_ids.add(current["user_id"])
        user_ids.update(row["user_id"] for row in historical)
        print("b) identity")
        if current:
            print(
                "  current snapshot:",
                current["user_id"],
                current["name"],
                current["email"],
                current["phone"],
                current["email_hash"],
                current["updated_at"],
            )
        else:
            print("  current snapshot: no row with this email")
        if historical:
            print("  request email matches audit history:")
            for row in historical:
                print(f"    {row['audit_id']} {row['user_id']} {row['event_time']} {row['field_name']} {row['old_value']} -> {row['new_value']}")
        else:
            print("  request email is not an old/new value in user_audit_log")
        known_emails = {email}
        known_phones: set[str] = set()
        known_hashes: set[str] = set()
        if current:
            known_emails.add(current["email"].lower())
            known_phones.add(current["phone"])
            known_hashes.add(current["email_hash"])
        for user_id in sorted(user_ids):
            print(f"  audit rows for {user_id}: {len(audits_by_user[user_id])}")
            for row in audits_by_user[user_id]:
                print(f"    {row['audit_id']} {row['event_time']} {row['field_name']} {row['old_value']} -> {row['new_value']}")
                if row["field_name"] == "email":
                    known_emails.add(row["old_value"].lower())
                    known_emails.add(row["new_value"].lower())
                elif row["field_name"] == "phone":
                    known_phones.add(row["old_value"])
                    known_phones.add(row["new_value"])
                elif row["field_name"] == "email_hash":
                    known_hashes.add(row["old_value"])
                    known_hashes.add(row["new_value"])

        resource_ids = [step["resource_id"] for step in steps]
        print("  step resource ids:", ", ".join(dict.fromkeys(resource_ids)))
        print("c) system_activity rows whose resource_id is in the step list, or whose details name the user")
        tokens = set(resource_ids) | user_ids | known_emails | known_phones | known_hashes
        matched = []
        for row in activity:
            if row["resource_id"] in resource_ids or any(token_in(row["details"], token) for token in tokens):
                matched.append(row)
        print(f"  matched activity rows: {len(matched)}")
        by_type = Counter(row["event_type"] for row in matched)
        print("  by event_type:", dict(sorted(by_type.items())))
        for row in matched:
            print(
                f"  {row['activity_id']} {row['event_time']} {row['event_type']} "
                f"{row['source_system']} -> {row['target_system']} {row['resource_id']} "
                f"{row['reported_result']} | {row['details']}"
            )

        print("d) steps_json")
        print(by_case_out[case_id]["steps_json"])

    section("3. Unique origins and system ids")
    print("evidence_files.origin:")
    for origin, count in sorted(Counter(row["origin"] for row in evidence_files).items()):
        print(f"  {count:3d}  {origin}")
    print("sample step system_id:")
    step_systems: Counter[str] = Counter()
    for steps in steps_by_case.values():
        for step in steps:
            step_systems[step["system_id"]] += 1
    for system_id, count in sorted(step_systems.items()):
        print(f"  {count:3d}  {system_id}")
    print("system_activity.source_system:")
    for name, count in sorted(Counter(row["source_system"] for row in activity).items()):
        print(f"  {count:4d}  {name}")
    print("system_activity.target_system:")
    for name, count in sorted(Counter(row["target_system"] for row in activity).items()):
        print(f"  {count:4d}  {name}")

    section("4. How resource_id joins to a person")
    print("LINK_RESOURCE_IDENTITY rows (the only activity rows that name an email and user_id):")
    link_re = re.compile(
        r"linked (?P<resource>\S+) \((?P<alias>[^)]+)\) to (?P<email>\S+) and (?P<user>user_\d+)"
    )
    attachment_re = re.compile(
        r"confirmed (?P<resource>\S+) \((?P<alias>[^)]+)\) belongs only to (?P<email>\S+) and (?P<user>user_\d+)"
    )
    for row in activity:
        if row["event_type"] != "LINK_RESOURCE_IDENTITY":
            continue
        print(f"  {row['activity_id']} {row['target_system']} {row['details']}")
        parsed = link_re.search(row["details"]) or attachment_re.search(row["details"])
        print("    parsed:" if parsed else "    parsed: UNPARSED", parsed.groupdict() if parsed else "")
    print(f"LINK_RESOURCE_IDENTITY count: {sum(1 for row in activity if row['event_type'] == 'LINK_RESOURCE_IDENTITY')} of {len(activity)} activity rows")
    print("Other activity details do not carry email or user_id. They name the resource and a workflow claim.")
    detail_shapes: Counter[str] = Counter()
    for row in activity:
        shape = re.sub(r"[A-Za-z]+_\d+", "<id>", row["details"])
        detail_shapes[shape] += 1
    print("activity detail templates:")
    for shape, count in detail_shapes.most_common():
        print(f"  {count:4d}  {shape}")

    section("5. Evidence schema samples")
    json_groups: dict[tuple[str, ...], list[Path]] = defaultdict(list)
    record_samples: dict[str, object] = {}
    for path in sorted(EVIDENCE.rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        keys = tuple(payload.keys()) if isinstance(payload, dict) else ("<list>",)
        json_groups[keys].append(path)
        json_record_samples(payload, record_samples, path.name)
    print("JSON top-level shapes:")
    for keys, paths in json_groups.items():
        print(f"  {len(paths):2d} files keys={list(keys)} example={paths[0].name}")
    print("one record per nested collection (first file that contained it):")
    for label, record in record_samples.items():
        rendered = json.dumps(record, ensure_ascii=False)
        if len(rendered) > 500:
            rendered = rendered[:500] + "...[truncated]"
        print(f"  {label}: {rendered}")

    print("SQL families:")
    families: dict[str, Path] = {}
    for path in sorted((EVIDENCE / "databases").glob("*.sql")):
        family = re.sub(r"_\d{8}.*", "", path.stem)
        families.setdefault(family, path)
    for family, path in families.items():
        print(f"  family {family} example {path.name}")
        script = path.read_text(encoding="utf-8")
        connection = sqlite3.connect(":memory:")
        connection.executescript(script)
        tables = [
            name
            for (name,) in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        for table in tables:
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
            count = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            sample = connection.execute(f"SELECT * FROM {table} LIMIT 1").fetchone()
            print(f"    {table} rows={count} columns={columns}")
            print(f"      sample={sample}")
        connection.close()

    print("TXT handover:")
    handover = EVIDENCE / "records" / "customer_account_handover_20261001.txt"
    lines = handover.read_text(encoding="utf-8").splitlines()
    print("\n".join(f"  {line}" for line in lines[:8]))
    parsed_rows = []
    for line in lines:
        parts = [part.strip() for part in line.split("|")]
        if len(parts) == 6:
            parsed_rows.append(parts)
    print(f"  parsed pipe rows: {len(parsed_rows)}")
    print("  record types:", dict(sorted(Counter(row[3] for row in parsed_rows).items())))
    print("  results:", dict(sorted(Counter(row[4] for row in parsed_rows).items())))

    print("LOG families:")
    log_paths = sorted((EVIDENCE / "logs").glob("*.log"))
    lookup = [path for path in log_paths if path.name.startswith("resource_lookup_trace_")]
    other_logs = [path for path in log_paths if path not in lookup]
    for label, group in (("resource_lookup_trace", lookup), ("other_logs", other_logs)):
        path = group[0]
        text = path.read_text(encoding="utf-8")
        events = Counter(re.findall(r"event=([A-Za-z0-9_]+)", text))
        print(f"  {label} files={len(group)} example={path.name} lines={text.count(chr(10)) + 1}")
        print("    events:", dict(events.most_common(12)))
        for line in text.splitlines()[:6]:
            print("   ", line[:240])

    print("PDF text extracts:")
    for path in sorted((EVIDENCE / "documents").glob("*.pdf")):
        print(f"  --- {path.name} ---")
        print(pdf_text(path))

    print("PNG screenshots (no text layer expected; dimensions and tEXt chunks):")
    for path in sorted((EVIDENCE / "images").glob("*.png")):
        width, height = png_size(path)
        raw = path.read_bytes()
        text_chunks = [
            chunk.decode("latin-1", errors="ignore")
            for chunk in re.findall(rb"(?:tEXt|zTXt|iTXt).{0,80}", raw)
        ]
        print(f"  {path.name} {width}x{height} bytes={path.stat().st_size} text_chunks={text_chunks or 'none'}")

    section("6. Request text and CLASSIFY_REQUEST")
    print("All 32 sample request texts (every sample answer is COMPLETE or INCOMPLETE; none are NOT_APPLICABLE):")
    for row in requests:
        print(f"  {row['case_id']} [{row['reported_status']}] {row['request_text']}")

    def cues(text: str, vocabulary: tuple[str, ...]) -> list[str]:
        lowered = text.lower()
        return [cue for cue in vocabulary if cue in lowered]

    print("Eval request cue buckets:")
    bucket = Counter()
    neither: list[dict[str, str]] = []
    non_deletion_hits: list[tuple[dict[str, str], list[str]]] = []
    for row in eval_requests:
        deletion = cues(row["request_text"], DELETION_CUES)
        other = cues(row["request_text"], NON_DELETION_CUES)
        if deletion and not other:
            bucket["deletion_cue_only"] += 1
        elif other and not deletion:
            bucket["non_deletion_cue_only"] += 1
            non_deletion_hits.append((row, other))
        elif deletion and other:
            bucket["both"] += 1
            non_deletion_hits.append((row, other))
        else:
            bucket["neither_lexicon"] += 1
            neither.append(row)
    print(dict(bucket))
    print("rows with a non-deletion cue:")
    for row, matched in non_deletion_hits:
        print(f"  {row['case_id']} {row['email']} cues={matched}")
        print(f"    {row['request_text']}")
    print("rows matching neither lexicon:")
    for row in neither:
        print(f"  {row['case_id']} {row['email']}")
        print(f"    {row['request_text']}")

    print("CLASSIFY_REQUEST events, joined through same-record subject_reference fields:")
    classify_rows = [row for row in activity if row["event_type"] == "CLASSIFY_REQUEST"]
    print(f"count={len(classify_rows)}")
    account_ids = {row["resource_id"] for row in classify_rows}
    email_by_account: dict[str, set[str]] = defaultdict(set)

    def walk_records(node: object) -> list[dict]:
        found: list[dict] = []
        if isinstance(node, dict):
            if "resource_id" in node:
                found.append(node)
            for value in node.values():
                found.extend(walk_records(value))
        elif isinstance(node, list):
            for value in node:
                found.extend(walk_records(value))
        return found

    for path in EVIDENCE.rglob("*.json"):
        for record in walk_records(json.loads(path.read_text(encoding="utf-8"))):
            resource_id = str(record.get("resource_id", ""))
            subject = str(record.get("subject_reference", ""))
            if resource_id in account_ids and "@" in subject:
                email_by_account[resource_id].add(subject.lower())
    eval_by_email = {row["email"].lower(): row for row in eval_requests}
    for row in classify_rows:
        account_id = row["resource_id"]
        emails = sorted(email_by_account[account_id])
        print(f"  {row['activity_id']} {row['event_time']} {account_id} subject_emails={emails}")
        print(f"    {row['details']}")
        for email in emails:
            hit = eval_by_email.get(email)
            if hit:
                print(f"    matched request {hit['case_id']} text={hit['request_text']}")
            else:
                print(f"    email {email} is not a request email in the 518")


if __name__ == "__main__":
    main()
