"""IOC IP CSV helpers. Lab / public data only — not a blocklist feed."""

from __future__ import annotations

import csv
from pathlib import Path

from authtriage.triage import KIND_BRUTE, KIND_MIXED, KIND_SPRAY, TriageResult


def write_csv(result: TriageResult, out_path: Path) -> Path:
    fail_then = {finding.source_ip for finding in result.fail_then_success}
    spray_ips = {
        item.source_ip
        for item in result.spray_brute
        if item.kind in {KIND_SPRAY, KIND_MIXED}
    }
    brute_ips = {
        item.source_ip
        for item in result.spray_brute
        if item.kind in {KIND_BRUTE, KIND_MIXED}
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "ip",
                "failed_count",
                "accepted_count",
                "fail_then_success",
                "spray",
                "brute",
            ]
        )
        for row in result.all_source_ips:
            writer.writerow(
                [
                    row.ip,
                    row.failed_count,
                    row.accepted_count,
                    "yes" if row.ip in fail_then else "no",
                    "yes" if row.ip in spray_ips else "no",
                    "yes" if row.ip in brute_ips else "no",
                ]
            )
    return out_path
