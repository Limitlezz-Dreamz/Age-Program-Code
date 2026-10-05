"""Markdown one-pager for AuthTriage findings."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from authtriage.learn import learner_blurbs
from authtriage.parsers.base import ParseStats
from authtriage.triage import BRUTE_MIN_FAILS, SPRAY_MIN_USERS, TriageResult

LAB_BANNER = "LAB / PUBLIC DATA ONLY — never use employer or production logs"


def write_markdown(
    result: TriageResult,
    stats: ParseStats,
    out_path: Path,
    input_name: str,
    parser_version: str,
) -> Path:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# AuthTriage report",
        "",
        f"**Generated:** {generated}",
        f"**Input:** `{input_name}`",
        f"**Parser:** `{parser_version}`",
        "",
        f"> {LAB_BANNER}",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Total lines | {stats.total_lines} |",
        f"| Parsed events | {stats.parsed} |",
        f"| Unparsed lines | {stats.unparsed} |",
        f"| Failed password | {result.total_failed} |",
        f"| Invalid user | {result.total_invalid_user} |",
        f"| Accepted | {result.total_accepted} |",
        "",
        "## Top source IPs",
        "",
        "| IP | Failed / invalid | Accepted |",
        "| --- | ---: | ---: |",
    ]
    if result.top_source_ips:
        for row in result.top_source_ips:
            lines.append(
                f"| `{row.ip}` | {row.failed_count} | {row.accepted_count} |"
            )
    else:
        lines.append("| *(none)* | 0 | 0 |")

    lines.extend(
        [
            "",
            "## Top targeted / invalid usernames",
            "",
            "| Username | Failed / invalid attempts |",
            "| --- | ---: |",
        ]
    )
    if result.top_usernames:
        for row in result.top_usernames:
            lines.append(f"| `{row.username}` | {row.count} |")
    else:
        lines.append("| *(none)* | 0 |")

    lines.extend(
        [
            "",
            "## Fail → success",
            "",
            "Same source IP had at least one failed or invalid attempt "
            "**before** an accepted logon (file appearance order).",
            "",
        ]
    )
    if result.fail_then_success:
        lines.extend(
            [
                "| IP | Accepted user | Prior failures | Note |",
                "| --- | --- | ---: | --- |",
            ]
        )
        for finding in result.fail_then_success:
            lines.append(
                f"| `{finding.source_ip}` | `{finding.username}` | "
                f"{finding.prior_failures} | {finding.note} |"
            )
    else:
        lines.append("_No fail→success findings in this file._")

    lines.extend(
        [
            "",
            "## Spray vs brute (heuristic)",
            "",
            f"Spray: **{SPRAY_MIN_USERS}+** distinct failed/invalid usernames "
            f"from one IP. Brute: **{BRUTE_MIN_FAILS}+** failures against one "
            "username from one IP. Whole-file appearance order — not a detector.",
            "",
        ]
    )
    if result.spray_brute:
        lines.extend(
            [
                "| IP | Kind | Distinct users | Max per user | Note |",
                "| --- | --- | ---: | ---: | --- |",
            ]
        )
        for finding in result.spray_brute:
            lines.append(
                f"| `{finding.source_ip}` | {finding.kind} | "
                f"{finding.distinct_users} | {finding.max_user_fails} | "
                f"{finding.note} |"
            )
    else:
        lines.append("_No spray/brute heuristic hits (thresholds not met)._")

    blurbs = learner_blurbs(result)
    lines.extend(
        [
            "",
            "## ATT&CK learner notes",
            "",
            "Original study blurbs with links. We do **not** copy ATT&CK page "
            "text into this report.",
            "",
        ]
    )
    if blurbs:
        for tech_id, name, url, blurb in blurbs:
            lines.append(f"- [{tech_id} {name}]({url}) — {blurb}")
    else:
        lines.append("_No ATT&CK notes for this file (no matching patterns)._")

    lines.extend(
        [
            "",
            "## Unparsed lines",
            "",
            f"`authlog_v1` skipped **{stats.unparsed}** line(s). Unknown lines "
            "are counted and ignored (soft-fail). Add `authlog_v2` later; do "
            "not change v1 goldens in place.",
            "",
            "## How to read this",
            "",
            "This is **triage**, not remediation. Use the tables to see which "
            "IPs and names showed up in a **lab / public** log. It does not "
            "ban, block, or talk to fail2ban. Patterns (spray of invalid "
            "users, then a valid account; accepted after failures from the "
            "same IP) are study signals, not an ops playbook.",
            "",
        ]
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path
