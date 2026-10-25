"""Read evidence files into observations.

Identity on a record may come from a nested profile or from subject_ref,
owner_key, customer_key, subject_reference, correlation_key, and lookup_key.
An analytics row is identifiable only from an email, phone, or user id.
A historical email hash alone does not make it identifiable.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from code.load_data import DATASET, parse_time

DELETE_CATEGORIES = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "SUPPORT_ATTACHMENT",
    "USER_EXPORT",
    "MARKETING_PROFILE",
}
ANONYMIZE_CATEGORIES = {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}
REDACT_CATEGORIES = {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}
RETAIN_CATEGORIES = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}

COLLECTION_CATEGORY = {
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "support_records": "SUPPORT_MESSAGE",
    "ticket_attachments": "SUPPORT_ATTACHMENT",
    "customer_exports": "USER_EXPORT",
    "connector_subscriptions": "DATA_FLOW",
    "backup_restore_entries": "BACKUP_ARCHIVE",
    "security_audit_records": "SECURITY_AUDIT_LOG",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "profile_lookups": "USER_PROFILE",
    "profiles": "ANALYTICS_PROFILE",
    "restore_entries": "BACKUP_ARCHIVE",
    "exports": "USER_EXPORT",
    "connectors": "DATA_FLOW",
    "index_queries": "SEARCH_INDEX_ENTRY",
    "audit_records": "SECURITY_AUDIT_LOG",
    "tickets": "SUPPORT_MESSAGE",
}

TABLE_CATEGORY = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_profiles_primary": ("account_service", "USER_PROFILE"),
    "customer_profiles_failover_replica": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"user_\d+")
PHONE_RE = re.compile(r"\+\d[\d\s().-]{6,}\d")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def clean(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def emails_in(value: object) -> set[str]:
    return {item.lower() for item in EMAIL_RE.findall(clean(value))}


def users_in(value: object) -> set[str]:
    return set(USER_RE.findall(clean(value)))


def phones_in(value: object) -> set[str]:
    found = set()
    for item in PHONE_RE.findall(clean(value)):
        digits = re.sub(r"\D", "", item)
        if len(digits) >= 8:
            found.add(digits)
    return found


def hashes_in(value: object) -> set[str]:
    return set(HASH_RE.findall(clean(value).lower()))


def is_blank(value: object) -> bool:
    return clean(value).lower() in {"", "none", "null"}


@dataclass
class Obs:
    file_id: str
    captured_at: str
    observed_at: str
    system_id: str
    resource_id: str
    category: str
    pattern: str
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    user_ids: set[str] = field(default_factory=set)
    present: bool = True
    identifiable: bool = False
    enabled: bool | None = None
    restore_allowed: bool | None = None
    retention_until: str = ""
    copy_role: str = "primary"

    def touches(self, tokens: dict[str, set[str]]) -> bool:
        return bool(
            self.emails & tokens["emails"]
            or self.phones & tokens["phones"]
            or self.hashes & tokens["hashes"]
            or self.user_ids & tokens["user_ids"]
        )


def add_id_fields(obs: Obs, record: dict) -> None:
    flat = dict(record)
    for key in ("profile", "document", "customer", "subject"):
        child = record.get(key)
        if isinstance(child, dict):
            flat.update({item_key: item_value for item_key, item_value in child.items() if not isinstance(item_value, (dict, list))})
    record = flat
    for key in (
        "email",
        "owner_email",
        "customer_email",
        "requester_email",
        "subject_reference",
        "lookup_key",
        "correlation_key",
        "subject_key",
        "matched_value",
        "full_name",
        "display_name",
        "requester_name",
        "name",
    ):
        obs.emails |= emails_in(record.get(key))
    for key in ("phone", "owner_phone", "requester_phone", "matched_value", "subject_reference"):
        obs.phones |= phones_in(record.get(key))
    for key in ("email_hash", "subject_reference"):
        obs.hashes |= hashes_in(record.get(key))
    for key in (
        "user_id",
        "customer_reference",
        "subject_reference",
        "subject_ref",
        "owner_key",
        "customer_key",
        "lookup_key",
        "correlation_key",
        "subject_key",
    ):
        obs.user_ids |= users_in(record.get(key))
        obs.emails |= emails_in(record.get(key))
        obs.phones |= phones_in(record.get(key))
        obs.hashes |= hashes_in(record.get(key))
    direct = bool(obs.emails or obs.phones or obs.hashes or clean(record.get("full_name")) or clean(record.get("display_name")) or clean(record.get("requester_name")))
    stable = bool(obs.user_ids)
    if obs.category in ANONYMIZE_CATEGORIES:
        obs.identifiable = bool(obs.emails or obs.phones or obs.user_ids)
    elif obs.category in REDACT_CATEGORIES:
        obs.identifiable = direct
    elif obs.category == "ACCOUNT_TOMBSTONE":
        obs.identifiable = direct
    elif obs.category in DELETE_CATEGORIES:
        obs.identifiable = direct or stable or obs.present
    else:
        obs.identifiable = direct


def apply_result_word(obs: Obs, result: str) -> None:
    token = clean(result).upper()
    if token in {"NOT_FOUND", "ABSENT", "MISS"}:
        obs.present = False
        obs.identifiable = False
    elif token == "ANONYMIZED":
        obs.present = True
        obs.identifiable = False
    elif token == "REDACTED":
        obs.present = True
        obs.identifiable = False
    elif token == "DISABLED":
        obs.present = True
        obs.enabled = False
    elif token == "BLOCKED":
        obs.present = True
        obs.restore_allowed = False
    elif token == "ACTIVE":
        obs.present = True
        if obs.category == "DATA_FLOW":
            obs.enabled = True
        elif obs.category == "BACKUP_ARCHIVE":
            obs.restore_allowed = True
    elif token in {"FOUND", "IDENTIFIABLE", "PRESENT"}:
        obs.present = True


def category_for_resource(resource_id: str, system_id: str) -> str:
    if resource_id.startswith("account_"):
        return "USER_PROFILE"
    if resource_id.startswith("search_"):
        return "SEARCH_INDEX_ENTRY"
    if resource_id.startswith("analytics_"):
        return "ANALYTICS_PROFILE"
    if resource_id.startswith("support_"):
        return "SUPPORT_MESSAGE" if system_id == "support_platform" else "SUPPORT_ATTACHMENT"
    if resource_id.startswith("export_"):
        return "USER_EXPORT"
    if resource_id.startswith("backup_"):
        return "BACKUP_ARCHIVE"
    if resource_id.startswith("data_flow_"):
        return "DATA_FLOW"
    if resource_id.startswith("audit_record_"):
        return "SECURITY_AUDIT_LOG"
    if resource_id.startswith("tombstone_"):
        return "ACCOUNT_TOMBSTONE"
    if resource_id.startswith("cache_"):
        return "CACHE_ENTRY"
    if resource_id.startswith("marketing_"):
        return "MARKETING_PROFILE"
    if resource_id.startswith("email_delivery_") or resource_id.startswith("email_"):
        return "EMAIL_DELIVERY_LOG"
    if resource_id.startswith("legal_"):
        return "LEGAL_HOLD_RECORD"
    if resource_id.startswith("object_"):
        return "SUPPORT_ATTACHMENT"
    if resource_id.startswith("telemetry_"):
        return "PRODUCT_TELEMETRY"
    return "USER_PROFILE"


# Inspected contents of the 4 PDFs and 11 PNGs. These files do not expose a text layer.
MULTIMODAL = [
    {
        "path": "evidence/documents/delivery_correction_attachment.pdf",
        "pattern": "pdf_support_attachment",
        "system_id": "support_platform",
        "resource_id": "support_001",
        "category": "SUPPORT_ATTACHMENT",
        "emails": ["priya.raman@gmail.com"],
        "phones": ["+91 98765 73142"],
        "user_ids": [],
        "present": True,
        "notes": "Delivery address correction, order ORD-20264827, captured 12 Sep 2026 07:30 UTC.",
    },
    {
        "path": "evidence/documents/account_history_report_20260718.pdf",
        "pattern": "pdf_customer_statement",
        "system_id": "export_service",
        "resource_id": "export_1842",
        "category": "USER_EXPORT",
        "emails": ["ingrid.dahl@outlook.com"],
        "phones": [],
        "user_ids": ["user_18"],
        "present": True,
        "notes": "Statement NST-2026-0718-1842, the catalog alias of export_1842. Address and order ORD-20261260.",
    },
    {
        "path": "evidence/documents/legal_retention_register_20260529.pdf",
        "pattern": "pdf_legal_hold",
        "system_id": "legal_service",
        "resource_id": "legal_hold_may_2026",
        "category": "LEGAL_HOLD_RECORD",
        "emails": [],
        "phones": [],
        "user_ids": ["user_08", "user_12", "user_17", "user_21", "user_24", "user_29"],
        "present": True,
        "notes": "Six disputed-order rows. Retain-until dates run from 04 May 2033 through 28 May 2033.",
    },
    {
        "path": "evidence/documents/security_retention_extract.pdf",
        "pattern": "pdf_security_audit",
        "system_id": "security_service",
        "resource_id": "audit_record_003",
        "category": "SECURITY_AUDIT_LOG",
        "emails": [],
        "phones": [],
        "user_ids": ["user_03"],
        "present": True,
        "retention_until": "2027-08-25T04:03:00Z",
        "notes": "Account closure recorded 25 Aug 2026. Retain until 25 Aug 2027.",
    },
    {
        "path": "evidence/images/account_admin_console_20260926.png",
        "pattern": "png_account_console",
        "system_id": "account_service",
        "resource_id": "account_5762",
        "category": "USER_PROFILE",
        "emails": ["haruka.s1838@zoho.com"],
        "phones": ["+81 90 7610 2507"],
        "user_ids": ["user_11"],
        "present": True,
        "notes": "Haruka Sato, address in Tokyo, orders ORD-20265762 and ORD-20265518.",
    },
    {
        "path": "evidence/images/search_index_inspector_20260901.png",
        "pattern": "png_search_console",
        "rows": [
            ("search_428", "g.silva76@gmail.com", "user_13", "Gabriel Silva"),
            ("search_1874", "g.silva76.jr@gmail.com", "", ""),
        ],
        "system_id": "search_service",
        "category": "SEARCH_INDEX_ENTRY",
        "notes": "Index customer_directory_v3 at 01 Sep 2026 06:00:14 UTC. The .jr document has a null customer reference.",
    },
    {
        "path": "evidence/images/connector_management_console_20260807.png",
        "pattern": "png_connector_console",
        "rows": [
            ("data_flow_1121", "jain.aditi@gmail.com"),
            ("data_flow_9846", "lucia-torres@gmail.com"),
        ],
        "system_id": "integration_service",
        "category": "DATA_FLOW",
        "enabled": True,
        "notes": "Both connectors are Continuous and recently contacted. Side panel is data_flow_1121.",
    },
    {
        "path": "evidence/images/analytics_profile_view_20260713.png",
        "pattern": "png_analytics_console",
        "system_id": "analytics_platform",
        "resource_id": "analytics_7438",
        "category": "ANALYTICS_PROFILE",
        "emails": ["darwish.omar@icloud.com"],
        "phones": [],
        "user_ids": ["user_20"],
        "present": True,
        "notes": "Omar Darwish, last activity 13 Jul 2026 14:22 UTC. Identifiable analytics profile.",
    },
    {
        "path": "evidence/images/customer_export_console_20260618.png",
        "pattern": "png_export_console",
        "system_id": "export_service",
        "resource_id": "export_1260",
        "category": "USER_EXPORT",
        "emails": ["ingrid.dahl@outlook.com"],
        "phones": [],
        "user_ids": [],
        "present": True,
        "notes": "Ready customer_export_1260.zip. Nearby rows export_1261, export_1259, and export_1258 are @northstar.shop operator mailboxes.",
    },
    {
        "path": "evidence/images/support_ticket_console_20260524.png",
        "pattern": "png_support_console",
        "system_id": "support_platform",
        "resource_id": "support_1034",
        "category": "SUPPORT_MESSAGE",
        "emails": ["kagyeman8947@fastmail.com"],
        "phones": [],
        "user_ids": [],
        "present": True,
        "notes": "Shared thread: customer Kofi Agyeman, agent Maya Chen, order ORD-20260534. Redact, do not delete.",
    },
    {
        "path": "evidence/images/backup_restore_console_20260429.png",
        "pattern": "png_backup_console",
        "system_id": "backup_service",
        "resource_id": "backup_9287",
        "category": "BACKUP_ARCHIVE",
        "emails": ["areed1433@gmail.com"],
        "phones": [],
        "user_ids": [],
        "present": True,
        "restore_allowed": True,
        "notes": "Archive tier, retention end 26 Jul 2026. Activity lists completed restores of backup_9286 and backup_9281.",
    },
    {
        "path": "evidence/images/security_audit_explorer_20260905.png",
        "pattern": "png_security_console",
        "system_id": "security_service",
        "category": "SECURITY_AUDIT_LOG",
        "user_ids": ["user_03"],
        "resource_ids": [
            "audit_record_003",
            "audit_record_002",
            "audit_record_001",
            "audit_record_006",
            "audit_record_005",
            "audit_record_004",
        ],
        "notes": "Subject filter user_03, 18-26 Aug 2026. Six signed events. audit_record_003 is account closure.",
    },
    {
        "path": "evidence/images/deleted_account_reference_20260310.png",
        "pattern": "png_retained_reference",
        "system_id": "identity_service",
        "resource_id": "user_17",
        "category": "ACCOUNT_TOMBSTONE",
        "emails": [],
        "phones": [],
        "user_ids": ["user_17"],
        "present": True,
        "identifiable": False,
        "notes": "Customer key user_17 marked Retained reference. Linked ORD-20263246, CS-3245, CS-3378, FIN-7742. No direct identifier on screen.",
    },
    {
        "path": "evidence/images/object_storage_browser_20260213.png",
        "pattern": "png_object_browser",
        "system_id": "object_storage",
        "category": "SUPPORT_ATTACHMENT",
        "resource_ids": [
            "delivery_confirmation_19.pdf",
            "delivery_confirmation_20.pdf",
            "return_label_4821.pdf",
            "return_label_4676.pdf",
            "invoice_NS-10493.pdf",
            "parcel_damage_7713.jpg",
            "customer_export_2026-02-10.zip",
            "customer_export_2026-02-12.zip",
        ],
        "notes": "Bucket northstar-customer-data, captured 13 Feb 2026. No owner email is printed. delivery_confirmation_19.pdf is also the filename on someone else's SQL attachment.",
    },
    {
        "path": "evidence/images/marketing_profile_console.png",
        "pattern": "png_marketing_console",
        "system_id": "marketing_platform",
        "resource_id": "marketing_001",
        "category": "MARKETING_PROFILE",
        "emails": ["sj.park@naver.com"],
        "phones": ["+82 10-5837-9451"],
        "user_ids": [],
        "present": True,
        "notes": "Soo-jin Park, email opt-in Yes, refreshed 15 Sep 2026 23:40 UTC. The catalog LINK for marketing_001 instead names kwame-mensah@proton.me and user_09.",
    },
]
def parse_kv_line(line: str) -> dict[str, str]:
    fields = {}
    for match in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)=(?:\"([^\"]*)\"|(\S+))", line):
        fields[match.group(1)] = match.group(2) if match.group(2) is not None else match.group(3)
    bracket = re.match(r"\S+ \[[A-Z]+\] \[([^\]]+)\] \[([^\]]+)\] ([a-z_]+):", line)
    if bracket:
        fields.setdefault("service", bracket.group(1))
        fields.setdefault("trace_id", bracket.group(2))
        fields.setdefault("event", bracket.group(3))
    return fields


def observation_from_trace(file_id: str, captured_at: str, fields: dict[str, str], pattern: str) -> Obs | None:
    resource_id = clean(fields.get("resource_id"))
    if not resource_id:
        return None
    system_id = clean(fields.get("service") or fields.get("system") or "")
    category = category_for_resource(resource_id, system_id)
    if not system_id:
        system_id = {
            "USER_PROFILE": "account_service",
            "SEARCH_INDEX_ENTRY": "search_service",
            "ANALYTICS_PROFILE": "analytics_platform",
            "SUPPORT_MESSAGE": "support_platform",
            "SUPPORT_ATTACHMENT": "support_platform",
            "USER_EXPORT": "export_service",
            "DATA_FLOW": "integration_service",
            "BACKUP_ARCHIVE": "backup_service",
            "SECURITY_AUDIT_LOG": "security_service",
        }.get(category, system_id)
    observed = clean(fields.get("timestamp") or captured_at)
    obs = Obs(
        file_id=file_id,
        captured_at=captured_at,
        observed_at=observed,
        system_id=system_id,
        resource_id=resource_id,
        category=category,
        pattern=pattern,
    )
    add_id_fields(obs, fields)
    event = clean(fields.get("event"))
    http = clean(fields.get("http_status"))
    rows = clean(fields.get("rows"))
    result = clean(fields.get("result"))
    # A cache_lookup miss on the same trace is not the record's state.
    # rows=1 / http 200 on the completion line wins over an earlier result=miss.
    if rows == "1" or http == "200":
        obs.present = True
    elif http == "404" or rows == "0" or result in {"miss", "not_found"}:
        obs.present = False
        obs.identifiable = False
    if "enabled" in fields:
        obs.enabled = clean(fields.get("enabled")).lower() == "true"
        obs.present = True
    if "restore_allowed" in fields:
        obs.restore_allowed = clean(fields.get("restore_allowed")).lower() == "true"
        obs.present = True
    if event in {"message_pii_scan", "attachment_pii_scan"} and obs.emails:
        obs.present = True
        obs.identifiable = True
        if event == "attachment_pii_scan":
            obs.category = "SUPPORT_ATTACHMENT"
    if category in ANONYMIZE_CATEGORIES and not (obs.emails or obs.phones or obs.hashes or obs.user_ids):
        obs.identifiable = False
    return obs


def parse_logs(path: Path, file_id: str, captured_at: str) -> list[Obs]:
    grouped: dict[str, dict[str, str]] = defaultdict(dict)
    order: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        stamp = line.split(" ", 1)[0]
        payload = line.split(" ", 1)[1] if " " in line else ""
        if payload.startswith("{"):
            try:
                decoded = json.loads(payload)
            except json.JSONDecodeError:
                decoded = None
            fields = {key: clean(value) for key, value in decoded.items()} if isinstance(decoded, dict) else parse_kv_line(line)
        else:
            fields = parse_kv_line(line)
        if re.match(r"\d{4}-\d{2}-\d{2}T", stamp):
            fields["timestamp"] = stamp
        trace = clean(fields.get("trace_id") or fields.get("trace") or "")
        key = trace or f"line-{len(order)}"
        if key not in grouped:
            order.append(key)
        grouped[key].update({k: v for k, v in fields.items() if v})
        if path.name.startswith("resource_lookup_trace_"):
            pattern = "resource_lookup_trace"
        elif path.name.startswith("structured_service_events_"):
            pattern = "structured_json_log"
        else:
            pattern = "service_log"
    found = []
    for key in order:
        obs = observation_from_trace(file_id, captured_at, grouped[key], pattern)
        if obs:
            found.append(obs)
    return found


def parse_handover(path: Path, file_id: str, captured_at: str) -> list[Obs]:
    found = []
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = [part.strip() for part in line.split("|")]
        if len(parts) != 6:
            continue
        observed, system_id, resource_id, category, result, subject = parts
        obs = Obs(
            file_id=file_id,
            captured_at=captured_at,
            observed_at=observed,
            system_id=system_id,
            resource_id=resource_id,
            category=category,
            pattern="handover_pipe",
        )
        add_id_fields(obs, {"subject_reference": subject})
        apply_result_word(obs, result)
        found.append(obs)
    return found


def walk_json(node: object, sink: list[dict], inherited: dict | None = None) -> None:
    inherited = dict(inherited or {})
    if isinstance(node, dict):
        context = dict(inherited)
        for key in ("data_store", "source", "collection", "captured_at", "exported_at", "recorded_at", "observed_at"):
            if key in node and not isinstance(node[key], (dict, list)):
                context[key] = node[key]
        if "resource_id" in node:
            record = dict(context)
            record.update(node)
            sink.append(record)
        for key, value in node.items():
            child = dict(context)
            if key in {"profile_lookups", "profiles", "restore_entries", "exports", "connectors", "index_queries", "audit_records", "tickets"}:
                child["collection"] = key
            if isinstance(value, (dict, list)):
                walk_json(value, sink, child)
    elif isinstance(node, list):
        for value in node:
            walk_json(value, sink, inherited)


def json_pattern(payload: dict) -> str:
    keys = set(payload)
    if "snapshots" in keys:
        return "snapshot_bundle"
    if "service_exports" in keys:
        return "service_resource_export"
    if "record_count" in keys:
        return "ledger_rows"
    return "collection_records"


def parse_json(path: Path, file_id: str, captured_at: str) -> list[Obs]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    pattern = json_pattern(payload) if isinstance(payload, dict) else "collection_records"
    records: list[dict] = []
    walk_json(payload, records)
    found = []
    for record in records:
        resource_id = clean(record.get("resource_id"))
        if not resource_id:
            continue
        collection = clean(record.get("collection"))
        category = clean(record.get("record_type")) or COLLECTION_CATEGORY.get(collection, "")
        system_id = clean(record.get("system") or record.get("data_store") or record.get("source") or "")
        if not category:
            category = category_for_resource(resource_id, system_id)
        if system_id.endswith("_service") or system_id.endswith("_platform"):
            pass
        elif collection in {"profile_lookups"}:
            system_id = "account_service"
        elif collection in {"profiles"}:
            system_id = "analytics_platform"
        elif collection in {"restore_entries"}:
            system_id = "backup_service"
        elif collection in {"exports"}:
            system_id = "export_service"
        elif collection in {"connectors"}:
            system_id = "integration_service"
        elif collection in {"index_queries"}:
            system_id = "search_service"
        elif collection in {"audit_records"}:
            system_id = "security_service"
        elif collection in {"tickets"}:
            system_id = "support_platform"
        observed = clean(record.get("observed_at") or record.get("recorded_at") or record.get("captured_at") or captured_at)
        obs = Obs(
            file_id=file_id,
            captured_at=captured_at,
            observed_at=observed,
            system_id=system_id,
            resource_id=resource_id,
            category=category,
            pattern=pattern,
        )
        flat = dict(record)
        profile = record.get("profile")
        if isinstance(profile, dict):
            flat.update(profile)
        document = record.get("document")
        if isinstance(document, dict):
            flat.update(document)
        hits = record.get("hits")
        if isinstance(hits, dict):
            for document in hits.get("documents") or []:
                if isinstance(document, dict):
                    flat.update(document)
        add_id_fields(obs, flat)
        if "status_code" in flat:
            obs.present = int(flat.get("status_code") or 0) != 404
            if not obs.present:
                obs.identifiable = False
        if "enabled" in flat:
            obs.enabled = bool(flat.get("enabled"))
        if "restore_allowed" in flat:
            obs.restore_allowed = bool(flat.get("restore_allowed"))
        if "retention_until" in flat:
            obs.retention_until = clean(flat.get("retention_until"))
        if "result" in record:
            apply_result_word(obs, clean(record.get("result")))
        if category in ANONYMIZE_CATEGORIES:
            obs.identifiable = bool(obs.emails or obs.phones or obs.hashes or obs.user_ids)
            obs.present = True
        found.append(obs)
    return found


def parse_sql(path: Path, file_id: str, captured_at: str) -> list[Obs]:
    script = path.read_text(encoding="utf-8")
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(script)
    tables = [
        name
        for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    ]
    found = []
    header = script.splitlines()[3] if len(script.splitlines()) > 3 else ""
    captured_match = re.search(r"Captured at:\s*(\S+)", script)
    file_observed = captured_match.group(1) if captured_match else captured_at
    for table in tables:
        columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
        if "record_json" in columns:
            pattern = "sqlite_record_json"
            for row in connection.execute(f"SELECT * FROM {table}"):
                payload = json.loads(row["record_json"])
                resource_id = clean(row["resource_id"] or payload.get("resource_id"))
                system_id = clean(row["origin_system"])
                collection = clean(row["collection_name"])
                category = COLLECTION_CATEGORY.get(collection, category_for_resource(resource_id, system_id))
                role = "replica" if "replica" in table else "primary"
                obs = Obs(
                    file_id=file_id,
                    captured_at=captured_at,
                    observed_at=clean(row["updated_at"] or file_observed),
                    system_id=system_id,
                    resource_id=resource_id,
                    category=category,
                    pattern=pattern,
                    copy_role=role,
                )
                add_id_fields(obs, payload if isinstance(payload, dict) else {})
                if category == "DATA_FLOW" and "enabled" in payload:
                    obs.enabled = bool(payload.get("enabled"))
                if category == "BACKUP_ARCHIVE" and "restore_allowed" in payload:
                    obs.restore_allowed = str(payload.get("restore_allowed")) in {"1", "true", "True"}
                if "retention_until" in payload:
                    obs.retention_until = clean(payload.get("retention_until"))
                found.append(obs)
            continue
        if table not in TABLE_CATEGORY and table != "snapshot_scope":
            continue
        if table == "snapshot_scope":
            continue
        system_id, category = TABLE_CATEGORY[table]
        role = "replica" if "replica" in table and "primary" not in table else "primary"
        pattern = "sqlite_failover_profiles" if "failover" in path.name or "replica" in table else "sqlite_typed_table"
        for row in connection.execute(f"SELECT * FROM {table}"):
            item = {key: row[key] for key in row.keys()}
            resource_id = clean(item.get("resource_id"))
            obs = Obs(
                file_id=file_id,
                captured_at=captured_at,
                observed_at=clean(item.get("updated_at") or item.get("indexed_at") or file_observed),
                system_id=system_id,
                resource_id=resource_id,
                category=category,
                pattern=pattern,
                copy_role=role,
            )
            add_id_fields(obs, item)
            if "enabled" in item:
                obs.enabled = str(item.get("enabled")) in {"1", "true", "True"}
            if "restore_allowed" in item:
                obs.restore_allowed = str(item.get("restore_allowed")) in {"1", "true", "True"}
            if "retention_until" in item:
                obs.retention_until = clean(item.get("retention_until"))
            found.append(obs)
    connection.close()
    if "failover" in header:
        pass
    return found


def multimodal_observations(manifest: dict[str, dict[str, str]]) -> list[Obs]:
    by_path = {row["file_path"]: row for row in manifest.values()}
    found = []
    for item in MULTIMODAL:
        meta = by_path[item["path"]]
        rows = item.get("rows")
        resource_ids = item.get("resource_ids") or [item.get("resource_id")]
        if rows:
            for resource_id, email, *rest in rows:
                user_id = rest[0] if rest else ""
                obs = Obs(
                    file_id=meta["file_id"],
                    captured_at=meta["captured_at"],
                    observed_at=meta["captured_at"],
                    system_id=item["system_id"],
                    resource_id=resource_id,
                    category=item["category"],
                    pattern=item["pattern"],
                    emails={email.lower()} if email else set(),
                    user_ids={user_id} if user_id else set(),
                    present=True,
                    identifiable=bool(email or user_id),
                    enabled=item.get("enabled"),
                    restore_allowed=item.get("restore_allowed"),
                )
                found.append(obs)
            continue
        for resource_id in resource_ids:
            if not resource_id:
                continue
            obs = Obs(
                file_id=meta["file_id"],
                captured_at=meta["captured_at"],
                observed_at=meta["captured_at"],
                system_id=item["system_id"],
                resource_id=resource_id,
                category=item["category"],
                pattern=item["pattern"],
                emails={value.lower() for value in item.get("emails", [])},
                phones=phones_in(" ".join(item.get("phones", []))),
                user_ids=set(item.get("user_ids", [])),
                present=item.get("present", True),
                identifiable=item.get("identifiable", bool(item.get("emails") or item.get("phones"))),
                enabled=item.get("enabled"),
                restore_allowed=item.get("restore_allowed"),
                retention_until=item.get("retention_until", ""),
            )
            found.append(obs)
    return found


def load_observations(manifest_rows: list[dict[str, str]]) -> tuple[list[Obs], Counter]:
    observations: list[Obs] = []
    patterns: Counter[str] = Counter()
    unparsed = []
    for row in manifest_rows:
        path = DATASET / row["file_path"]
        suffix = path.suffix.lower()
        parsed: list[Obs] = []
        if suffix == ".json":
            parsed = parse_json(path, row["file_id"], row["captured_at"])
        elif suffix == ".sql":
            parsed = parse_sql(path, row["file_id"], row["captured_at"])
            if not parsed:
                patterns["sqlite_scope_only"] += 1
                continue
        elif suffix == ".log":
            parsed = parse_logs(path, row["file_id"], row["captured_at"])
        elif suffix == ".txt":
            parsed = parse_handover(path, row["file_id"], row["captured_at"])
        elif suffix in {".pdf", ".png"}:
            continue
        else:
            unparsed.append(row["file_path"])
        if suffix in {".json", ".sql", ".log", ".txt"} and not parsed:
            unparsed.append(row["file_path"])
        observations.extend(parsed)
        for obs in parsed:
            patterns[obs.pattern] += 1
    observations.extend(multimodal_observations({row["file_id"]: row for row in manifest_rows}))
    system_for_category = {
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
    }
    known_systems = set(system_for_category.values()) | {"object_storage"}
    for obs in observations:
        if obs.system_id not in known_systems and obs.category in system_for_category:
            obs.system_id = system_for_category[obs.category]
    for obs in observations:
        if obs.pattern.startswith("pdf_") or obs.pattern.startswith("png_"):
            patterns[obs.pattern] += 1
    return observations, patterns, unparsed
