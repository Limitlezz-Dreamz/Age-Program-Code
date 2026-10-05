"""AuthTriage command-line entry. Read-only; no host mutation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from authtriage import __version__
from authtriage.ioc import write_csv
from authtriage.parsers.authlog_v1 import PARSER_VERSION, AuthlogV1Parser
from authtriage.parsers.base import parse_lines
from authtriage.report import LAB_BANNER, write_markdown
from authtriage.triage import triage

DEFAULT_OUTDIR = Path("out")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authtriage",
        description=(
            "Read-only Linux auth.log / syslog-style triage. "
            "Lab and public sample logs only."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to an auth.log or syslog-style text export",
    )
    parser.add_argument(
        "-o",
        "--outdir",
        type=Path,
        default=DEFAULT_OUTDIR,
        help="Directory for report.md and iocs.csv (default: ./out)",
    )
    parser.add_argument(
        "--format",
        choices=("md", "csv", "both"),
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"authtriage {__version__} parser={PARSER_VERSION}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    print(LAB_BANNER, file=sys.stderr)
    args = build_parser().parse_args(argv)
    log_path: Path = args.path
    if not log_path.is_file():
        print(f"error: log file not found: {log_path}", file=sys.stderr)
        return 2

    text = log_path.read_text(encoding="utf-8", errors="replace")
    events, stats = parse_lines(text.splitlines(), AuthlogV1Parser())
    print(
        f"parser={PARSER_VERSION} total_lines={stats.total_lines} "
        f"parsed={stats.parsed} unparsed={stats.unparsed} "
        f"by_type={dict(stats.by_type)}",
        file=sys.stderr,
    )

    result = triage(events, stats)
    outdir: Path = args.outdir
    written: list[Path] = []
    if args.format in ("md", "both"):
        written.append(
            write_markdown(
                result,
                stats,
                outdir / "report.md",
                input_name=log_path.name,
                parser_version=PARSER_VERSION,
            )
        )
    if args.format in ("csv", "both"):
        written.append(write_csv(result, outdir / "iocs.csv"))

    for path in written:
        print(str(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
