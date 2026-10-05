"""JSON findings dump. Lab / public data only — not a feed for blockers."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from authtriage.parsers.base import ParseStats
from authtriage.report import LAB_BANNER
from authtriage.triage import TriageResult


def write_json(
    result: TriageResult,
    stats: ParseStats,
    out_path: Path,
    input_name: str,
    parser_version: str,
) -> Path:
    payload = {
        "banner": LAB_BANNER,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "input": input_name,
        "parser": parser_version,
        "stats": {
            "total_lines": stats.total_lines,
            "parsed": stats.parsed,
            "unparsed": stats.unparsed,
            "by_type": dict(stats.by_type),
        },
        "top_source_ips": [asdict(row) for row in result.top_source_ips],
        "top_usernames": [asdict(row) for row in result.top_usernames],
        "fail_then_success": [asdict(row) for row in result.fail_then_success],
        "spray_brute": [asdict(row) for row in result.spray_brute],
        "sudo_after_fail_success": [
            asdict(row) for row in result.sudo_after_fail_success
        ],
        "timeline": [asdict(row) for row in result.timeline],
        "totals": {
            "failed_password": result.total_failed,
            "invalid_user": result.total_invalid_user,
            "accepted": result.total_accepted,
            "sudo": result.total_sudo,
            "unparsed": result.unparsed,
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out_path
