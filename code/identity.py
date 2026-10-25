"""Current and historical identifiers for the person named on a request."""

from __future__ import annotations

from code.evidence import emails_in, hashes_in, phones_in


def identity_tokens(
    email: str,
    identities: list[dict[str, str]],
    audits: list[dict[str, str]],
) -> tuple[set[str], dict[str, set[str]]]:
    wanted = email.lower()
    user_ids: set[str] = set()
    for row in identities:
        if row["email"].lower() == wanted:
            user_ids.add(row["user_id"])
    for row in audits:
        if row["field_name"] == "email" and wanted in {row["old_value"].lower(), row["new_value"].lower()}:
            user_ids.add(row["user_id"])
    emails = {wanted}
    phones: set[str] = set()
    hashes: set[str] = set()
    for row in identities:
        if row["user_id"] not in user_ids:
            continue
        emails.add(row["email"].lower())
        phones |= phones_in(row["phone"])
        if row["email_hash"]:
            hashes.add(row["email_hash"].lower())
    for row in audits:
        if row["user_id"] not in user_ids:
            continue
        if row["field_name"] == "email":
            emails.add(row["old_value"].lower())
            emails.add(row["new_value"].lower())
        elif row["field_name"] == "phone":
            phones |= phones_in(row["old_value"])
            phones |= phones_in(row["new_value"])
        elif row["field_name"] == "email_hash":
            hashes.add(row["old_value"].lower())
            hashes.add(row["new_value"].lower())
    hashes |= hashes_in(" ".join(emails))
    return user_ids, {"emails": emails, "phones": phones, "hashes": hashes, "user_ids": user_ids}
