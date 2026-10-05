"""IOC IP CSV helpers. Lab / public data only — not a blocklist feed."""

from __future__ import annotations

import csv
from pathlib import Path

from authtriage.triage import TriageResult


def write_csv(result: TriageResult, out_path: Path) -> Path:
    fail_then = {finding.source_ip for finding in result.fail_then_success}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["ip", "failed_count", "accepted_count", "fail_then_success"]
        )
        for row in result.all_source_ips:
            writer.writerow(
                [
                    row.ip,
                    row.failed_count,
                    row.accepted_count,
                    "yes" if row.ip in fail_then else "no",
                ]
            )
    return out_path
