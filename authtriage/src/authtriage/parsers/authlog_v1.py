"""Versioned sshd syslog parser (authlog_v1).

Recognizes common OpenSSH ``auth.log`` / syslog-style lines:

* ``Failed password for (invalid user )?USER from IP``
* ``Accepted password|publickey for USER from IP``
* ``Invalid user USER from IP``

Anything else (sudo, cron, PAM noise, truncated lines) is a soft-fail miss.
Keep ``PARSER_VERSION`` stable so goldens stay pinned to v1 while v2 can be
added later as a separate module.
"""

from __future__ import annotations

import re
from typing import Optional

from authtriage.parsers.base import (
    EVENT_ACCEPTED,
    EVENT_FAILED_PASSWORD,
    EVENT_INVALID_USER,
    AuthEvent,
)

PARSER_VERSION = "authlog_v1"

# Classic syslog: "Apr 19 03:12:01 host sshd[9821]: message"
_SYSLOG_PREFIX = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^:\[\s]+)(?:\[\d+\])?:\s+"
    r"(?P<msg>.*)$"
)

# journalctl short-iso-ish: "2024-04-19T03:12:01 host sshd[9821]: message"
_ISO_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^:\[\s]+)(?:\[\d+\])?:\s+"
    r"(?P<msg>.*)$"
)

_IP = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,})"

_FAILED_INVALID = re.compile(
    rf"Failed password for invalid user (?P<user>\S+) from {_IP}(?:\s+port\s+\d+)?"
)
_FAILED = re.compile(
    rf"Failed password for (?P<user>\S+) from {_IP}(?:\s+port\s+\d+)?"
)
_ACCEPTED = re.compile(
    rf"Accepted (?:password|publickey) for (?P<user>\S+) from {_IP}(?:\s+port\s+\d+)?"
)
_INVALID = re.compile(
    rf"Invalid user (?P<user>\S+) from {_IP}(?:\s+port\s+\d+)?"
)


class AuthlogV1Parser:
    version = PARSER_VERSION

    def parse_line(self, line: str) -> Optional[AuthEvent]:
        stripped = line.strip()
        match = _SYSLOG_PREFIX.match(stripped) or _ISO_PREFIX.match(stripped)
        if match:
            timestamp = match.group("ts")
            host = match.group("host")
            process = match.group("proc")
            msg = match.group("msg")
        else:
            timestamp = None
            host = None
            process = None
            msg = stripped

        event_type, username, source_ip = _classify_sshd(msg)
        if event_type is None:
            return None
        return AuthEvent(
            timestamp=timestamp,
            host=host,
            process=process,
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            raw_line=line,
            parser_version=PARSER_VERSION,
        )


def _classify_sshd(msg: str) -> tuple[str | None, str | None, str | None]:
    m = _FAILED_INVALID.search(msg)
    if m:
        return EVENT_INVALID_USER, m.group("user"), m.group("ip")
    m = _FAILED.search(msg)
    if m:
        return EVENT_FAILED_PASSWORD, m.group("user"), m.group("ip")
    m = _ACCEPTED.search(msg)
    if m:
        return EVENT_ACCEPTED, m.group("user"), m.group("ip")
    m = _INVALID.search(msg)
    if m:
        return EVENT_INVALID_USER, m.group("user"), m.group("ip")
    return None, None, None
