"""Turn one deletion request into a status and an ordered step list."""

from __future__ import annotations

import csv
import json

from code.absence import latest_absence, synthetic_absent, synthetic_present_audit
from code.identity import identity_tokens
from code.intent import authorizes_deletion
from code.linking import World, linked_resource_ids, load_world
from code.load_data import OUTPUT_PATH, case_number, load_csv, parse_time
from code.policy import hash_only_analytics, plan_resource, steps_from_plans, violate
from code.state import reduce_states


def _during_request(obs, requested_at) -> bool:
    raw = obs.observed_at or obs.captured_at
    try:
        return parse_time(raw) >= requested_at
    except ValueError:
        return parse_time(obs.captured_at) >= requested_at


def audit_case(world: World, request: dict[str, str]) -> tuple[str, list[dict]]:
    if not authorizes_deletion(request["request_text"]):
        return "NOT_APPLICABLE", []
    user_ids, tokens = identity_tokens(request["email"], world.identities, world.audits)
    if not user_ids:
        return "NOT_APPLICABLE", []
    linked_ids = linked_resource_ids(world, request, user_ids, tokens)
    if any(resource_id in world.classified_accounts for _system_id, resource_id in linked_ids):
        return "NOT_APPLICABLE", []
    audit_at = parse_time(request["audit_at"])
    requested_at = parse_time(request["requested_at"])
    in_time = [obs for obs in world.observations if parse_time(obs.captured_at) <= audit_at]
    linked = [obs for obs in in_time if (obs.system_id, obs.resource_id) in linked_ids]
    had_evidence = {(obs.system_id, obs.resource_id) for obs in linked}
    linked = [obs for obs in linked if obs.present or _during_request(obs, requested_at)]
    seen = {(obs.system_id, obs.resource_id) for obs in linked}
    for system_id, resource_id in sorted(linked_ids):
        if (system_id, resource_id) in had_evidence or (system_id, resource_id) in seen:
            continue
        if resource_id.startswith("account_"):
            proof = latest_absence(world.observations, audit_at, resource_id)
            if proof:
                linked.append(synthetic_absent(resource_id, proof[0], proof[1]))
            continue
        if resource_id.startswith("audit_record_"):
            linked.append(synthetic_present_audit(resource_id, audit_at))
    plans = []
    for obs in reduce_states(linked):
        if hash_only_analytics(obs):
            plans.append(violate(
                "REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT", obs,
            ))
            continue
        plan = plan_resource(obs)
        if plan:
            plans.append(plan)
    status, steps = steps_from_plans(plans)
    if status == "COMPLETE":
        cited = [step for step in steps if step["evidence_id"]]
        for number, step in enumerate(cited, start=1):
            step["step_no"] = number
        return status, cited
    return status, steps


def audit_requests(world: World, requests: list[dict[str, str]]) -> list[dict[str, str]]:
    rows = []
    for request in sorted(requests, key=lambda row: case_number(row["case_id"])):
        status, steps = audit_case(world, request)
        rows.append({
            "case_id": request["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, separators=(",", ":"), ensure_ascii=False),
        })
    return rows


def write_output(rows: list[dict[str, str]], path=OUTPUT_PATH) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    world = load_world()
    rows = audit_requests(world, load_csv("deletion_requests.csv"))
    write_output(rows)
    print(f"wrote {len(rows)} rows to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
