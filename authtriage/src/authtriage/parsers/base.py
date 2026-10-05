"""Shared parser types and a soft-fail line walker.

Unknown lines increment ``unparsed`` and are skipped. Parsers must not raise
on garbage input; ``parse_lines`` also catches unexpected exceptions so a run
never crashes on a bad line.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional, Protocol


EVENT_FAILED_PASSWORD = "failed_password"
EVENT_INVALID_USER = "invalid_user"
EVENT_ACCEPTED = "accepted"
EVENT_SUDO = "sudo"
EVENT_OTHER = "other"


@dataclass
class AuthEvent:
    timestamp: str | None
    host: str | None
    process: str | None
    event_type: str
    username: str | None
    source_ip: str | None
    raw_line: str
    parser_version: str = "authlog_v1"
    source: str | None = None
    command: str | None = None
    runas: str | None = None


@dataclass
class ParseStats:
    total_lines: int = 0
    parsed: int = 0
    unparsed: int = 0
    by_type: dict[str, int] = field(default_factory=dict)

    def bump(self, event_type: str) -> None:
        self.by_type[event_type] = self.by_type.get(event_type, 0) + 1


class LineParser(Protocol):
    version: str

    def parse_line(self, line: str) -> Optional[AuthEvent]:
        """Return an AuthEvent or None if the line is not recognized."""


def parse_lines(
    lines: Iterable[str],
    parser: LineParser,
) -> tuple[list[AuthEvent], ParseStats]:
    events: list[AuthEvent] = []
    stats = ParseStats()
    for line in lines:
        raw = line.rstrip("\n")
        stats.total_lines += 1
        if not raw.strip():
            stats.unparsed += 1
            continue
        try:
            event = parser.parse_line(raw)
        except Exception:
            stats.unparsed += 1
            continue
        if event is None:
            stats.unparsed += 1
            continue
        stats.parsed += 1
        stats.bump(event.event_type)
        events.append(event)
    return events, stats


def merge_stats(parts: Iterable[ParseStats]) -> ParseStats:
    out = ParseStats()
    for stats in parts:
        out.total_lines += stats.total_lines
        out.parsed += stats.parsed
        out.unparsed += stats.unparsed
        for key, value in stats.by_type.items():
            out.by_type[key] = out.by_type.get(key, 0) + value
    return out
