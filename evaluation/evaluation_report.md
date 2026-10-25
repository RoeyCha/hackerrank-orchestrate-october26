# Evaluation report

The public sample file is the scorecard for the 32 cases below. It is not an input to resource assignment. The five custom cases are defined in this report and in `code/evaluation/custom_cases.py`.

## Sample scorecard

- Case-level deletion-status accuracy: 32/32 (100.0%)
- Case-level exact match (status and ordered steps): 20/32 (62.5%)
- Sequence accuracy: 20/32 (62.5%)
- Step-level accuracy: recall 177/193 (91.7%); precision 177/177 (100.0%)
- Field-level accuracy: 1062/1158 (91.7%) across phase, operation, system_id, resource_id, state, and evidence_id

## Custom cases

### negated erasure request (pass)

- Input: `This is not a request to erase my account. It is an information request.`
- Expected: `NOT_APPLICABLE`
- Actual: `NOT_APPLICABLE`

### Japanese deletion verb (pass)

- Input: `個人データを削除してください`
- Expected: `DELETION`
- Actual: `DELETION`

### tombstone keeps the record and redacts identifiers (pass)

- Input: `present ACCOUNT_TOMBSTONE with an email`
- Expected: `REPORT_EXPOSED_PII -> REDACT_RECORD -> VERIFY_RECORD_REDACTED`
- Actual: `REPORT_EXPOSED_PII -> REDACT_RECORD -> VERIFY_RECORD_REDACTED`

### hash-only analytics is deleted rather than anonymized (pass)

- Input: `present ANALYTICS_PROFILE with an email hash and no email, phone, or user id`
- Expected: `DELETE`
- Actual: `DELETE`

### later empty account census outranks the earlier replica (pass)

- Input: `account_custom_absent at 2026-09-02T23:00:00Z and at 2026-09-15T12:00:00Z`
- Expected: `evidence_54 then evidence_51`
- Actual: `evidence_54 then evidence_51`

## Failures found and improvements made

- case_03 status COMPLETE->COMPLETE missing=[('analytics_platform', 'analytics_9406')] extra=none
- case_18 status INCOMPLETE->INCOMPLETE missing=[('account_service', 'account_5521'), ('security_service', 'audit_record_6645')] extra=none
- case_20 status INCOMPLETE->INCOMPLETE missing=[('account_service', 'account_5037'), ('security_service', 'audit_record_5569')] extra=none
- case_21 status COMPLETE->COMPLETE missing=[('account_service', 'account_6440'), ('analytics_platform', 'analytics_5335')] extra=none
- case_22 status INCOMPLETE->INCOMPLETE missing=[('account_service', 'account_4990')] extra=none
- case_23 status INCOMPLETE->INCOMPLETE missing=[('account_service', 'account_410')] extra=none
- case_25 status COMPLETE->COMPLETE missing=[('account_service', 'account_3136'), ('analytics_platform', 'analytics_1895')] extra=none
- case_26 status COMPLETE->COMPLETE missing=[('analytics_platform', 'analytics_4566')] extra=none
- case_28 status COMPLETE->COMPLETE missing=[('account_service', 'account_5482')] extra=none
- case_29 status INCOMPLETE->INCOMPLETE missing=[('account_service', 'account_7012')] extra=none
- case_31 status COMPLETE->COMPLETE missing=[('account_service', 'account_4857')] extra=none
- case_32 status INCOMPLETE->INCOMPLETE missing=[('account_service', 'account_8858')] extra=none

Twelve of the 32 public cases still miss a resource. The misses are anonymous analytics rows whose snapshot position is consistent with more than one user, and account-delete bursts whose emit order is not a stable sort of case id, request time, or identity-file order. Equal-count pairing by case id was measured and left out: it added an account to a case that does not own it. Phantom audit ids that never appear in activity or evidence are not invented.

Improvements retained from that measurement:

- An empty `customer_profiles` snapshot is a full-store census. It outranks an earlier SQL replica when the audit time allows it.
- Identity on a record may come from any capture time. The state citation still has to be captured at or before `audit_at`.
- A one-row account burst is assigned only when one request is reported 50 to 80 minutes later.
- Analytics is identifiable only from an email, phone, or user id. A hash alone is a remaining record to delete.
- Negation is tested before deletion verbs, including 削除.
