"""AuthTriage command-line entry. Read-only; no host mutation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from authtriage import __version__
from authtriage.html import serve_local, write_html
from authtriage.ingest import resolve_sources
from authtriage.jsonout import write_json
from authtriage.ioc import write_csv
from authtriage.parsers.authlog_v1 import PARSER_VERSION, AuthlogV1Parser
from authtriage.parsers.base import AuthEvent, ParseStats, merge_stats, parse_lines
from authtriage.report import LAB_BANNER, format_summary, write_markdown
from authtriage.triage import triage

DEFAULT_OUTDIR = Path("out")
MD_FORMATS = {"md", "both", "all"}
CSV_FORMATS = {"csv", "both", "all"}
HTML_FORMATS = {"html", "all"}
JSON_FORMATS = {"json", "all"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authtriage",
        description=(
            "Read-only Linux/macOS auth.log / syslog-style triage. "
            "Lab and public sample logs only."
        ),
        epilog=(
            "Linux lab VM: sudo journalctl -u ssh -u sshd -o short-iso --no-pager | authtriage - -o out/\n"
            "macOS lab: log show --style syslog --predicate "
            '\'process == "sshd" OR process == "sshd-session" OR process == "sudo"\' '
            "--last 24h | authtriage - -o out/\n"
            "Never a work/employer host. AuthTriage does not run sudo or log show itself."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        help="Log file, directory of .log/.txt files, or - for stdin",
    )
    parser.add_argument(
        "-o",
        "--outdir",
        type=Path,
        default=DEFAULT_OUTDIR,
        help="Directory for reports (default: ./out)",
    )
    parser.add_argument(
        "--format",
        choices=("md", "csv", "html", "json", "both", "all"),
        default="all",
        help="Output format (default: all = md+csv+html+json; both = md+csv)",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="When PATH is a directory, include .log/.txt files in subfolders",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="After writing, serve outdir on 127.0.0.1 (read-only, lab use)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for --serve (default: 8765, bound to 127.0.0.1 only)",
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
    try:
        if args.path == "-":
            sources = resolve_sources("-", stdin_text=sys.stdin.read())
        else:
            sources = resolve_sources(args.path, recursive=args.recursive)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    events, stats = _parse_sources(sources)
    print(
        f"parser={PARSER_VERSION} inputs={len(sources)} "
        f"total_lines={stats.total_lines} parsed={stats.parsed} "
        f"unparsed={stats.unparsed} by_type={dict(stats.by_type)}",
        file=sys.stderr,
    )
    result = triage(events, stats)
    print(format_summary(result, stats), file=sys.stderr)
    outdir: Path = args.outdir
    input_name = ", ".join(name for name, _ in sources)
    fmt = args.format

    written: list[Path] = []
    if fmt in MD_FORMATS:
        written.append(
            write_markdown(
                result,
                stats,
                outdir / "report.md",
                input_name=input_name,
                parser_version=PARSER_VERSION,
            )
        )
    if fmt in CSV_FORMATS:
        written.append(write_csv(result, outdir / "iocs.csv"))
    if fmt in HTML_FORMATS or args.serve:
        written.append(
            write_html(
                result,
                stats,
                outdir / "report.html",
                input_name=input_name,
                parser_version=PARSER_VERSION,
            )
        )
    if fmt in JSON_FORMATS:
        written.append(
            write_json(
                result,
                stats,
                outdir / "report.json",
                input_name=input_name,
                parser_version=PARSER_VERSION,
            )
        )

    for path in written:
        print(str(path))

    if args.serve:
        try:
            serve_local(outdir, port=args.port)
        except KeyboardInterrupt:
            print("stopped", file=sys.stderr)
            return 0
    return 0


def _parse_sources(
    sources: list[tuple[str, list[str]]],
) -> tuple[list[AuthEvent], ParseStats]:
    parser = AuthlogV1Parser()
    chunks: list[tuple[list[AuthEvent], ParseStats]] = []
    for name, lines in sources:
        events, stats = parse_lines(lines, parser)
        for event in events:
            event.source = name
        chunks.append((events, stats))
    all_events = [event for events, _ in chunks for event in events]
    return all_events, merge_stats(stats for _, stats in chunks)


if __name__ == "__main__":
    raise SystemExit(main())
