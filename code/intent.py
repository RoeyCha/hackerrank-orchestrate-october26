"""Decide whether the request text authorizes deletion.

Negations are tested before deletion verbs. A CLASSIFY_REQUEST row that names
one of the case's resources as non-deletion also makes the case not applicable.
"""

from __future__ import annotations

import re

NON_DELETION = re.compile(
    r"not a request to erase|do not close|leave the account active|keep the account|"
    r"without removing|marketing lists only|leave my profile|continue using the service|"
    r"information request",
    re.IGNORECASE,
)
DELETION = re.compile(
    r"delet|eras|exclu|elimin|supprim|삭제|削除|suppression|remov|close the account|closed|"
    r"forget|profile is gone|permanen",
    re.IGNORECASE,
)


def authorizes_deletion(text: str) -> bool:
    if NON_DELETION.search(text):
        return False
    return bool(DELETION.search(text))


def non_deletion_accounts(activity: list[dict[str, str]]) -> set[str]:
    return {
        row["resource_id"]
        for row in activity
        if row["event_type"] == "CLASSIFY_REQUEST" and "non-deletion" in row["details"].lower()
    }
