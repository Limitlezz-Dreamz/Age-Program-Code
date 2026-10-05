"""Short original learner notes with ATT&CK links. Do not vendor MITRE text."""

from __future__ import annotations

from authtriage.triage import KIND_BRUTE, KIND_MIXED, KIND_SPRAY, TriageResult

# Technique IDs + our own one-sentence study notes. Link out; do not copy
# ATT&CK page body into this tree.
_T1110 = (
    "T1110",
    "Brute Force",
    "https://attack.mitre.org/techniques/T1110/",
    "Lots of failed logons in a lab file are a guessing pattern. This tool "
    "only counts them; it does not tell you to block an address.",
)
_T1110_001 = (
    "T1110.001",
    "Password Guessing",
    "https://attack.mitre.org/techniques/T1110/001/",
    "Same source IP hammering one username looks like classic password "
    "guessing (our brute heuristic). Study the counts, don't copy a ban list.",
)
_T1110_003 = (
    "T1110.003",
    "Password Spraying",
    "https://attack.mitre.org/techniques/T1110/003/",
    "One IP trying many distinct usernames looks like a spray. Distinct-user "
    "count is the signal here, not a verdict.",
)
_T1078 = (
    "T1078",
    "Valid Accounts",
    "https://attack.mitre.org/techniques/T1078/",
    "Accepted after prior failures from the same IP can mean a guess finally "
    "hit a real account — or a tired human. The report flags the sequence only.",
)


def learner_blurbs(result: TriageResult) -> list[tuple[str, str, str, str]]:
    """Return (technique_id, name, url, blurb) rows relevant to this result."""
    rows: list[tuple[str, str, str, str]] = []
    kinds = {item.kind for item in result.spray_brute}
    if result.total_failed or result.total_invalid_user:
        rows.append(_T1110)
    if KIND_BRUTE in kinds or KIND_MIXED in kinds:
        rows.append(_T1110_001)
    if KIND_SPRAY in kinds or KIND_MIXED in kinds:
        rows.append(_T1110_003)
    if result.fail_then_success:
        rows.append(_T1078)
    return rows
