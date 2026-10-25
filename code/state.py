"""Collapse replica copies to the state that matters at audit time.

A copy that still holds a delete-category row wins over an absent copy.
"""

from __future__ import annotations

from collections import defaultdict

from code.evidence import DELETE_CATEGORIES, Obs


def reduce_states(observations: list[Obs]) -> list[Obs]:
    grouped: dict[tuple[str, str, str], Obs] = {}
    for obs in observations:
        key = (obs.system_id, obs.resource_id, obs.copy_role)
        current = grouped.get(key)
        if current is None or (obs.observed_at, obs.captured_at) >= (current.observed_at, current.captured_at):
            grouped[key] = obs
    by_resource: dict[tuple[str, str], list[Obs]] = defaultdict(list)
    for obs in grouped.values():
        by_resource[(obs.system_id, obs.resource_id)].append(obs)
    reduced = []
    for copies in by_resource.values():
        if any(copy.present and copy.category in DELETE_CATEGORIES for copy in copies):
            winner = max(
                (copy for copy in copies if copy.present),
                key=lambda copy: (copy.observed_at, copy.captured_at),
            )
        else:
            def severity(obs: Obs) -> tuple:
                risky = obs.present and (
                    obs.identifiable
                    or obs.enabled is True
                    or obs.restore_allowed is True
                    or obs.category in DELETE_CATEGORIES
                )
                return (risky, obs.present, obs.observed_at, obs.captured_at)

            winner = max(copies, key=severity)
        reduced.append(winner)
    return reduced
