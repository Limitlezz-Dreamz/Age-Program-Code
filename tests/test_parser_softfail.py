"""Soft-fail: mixed valid sshd lines and garbage never raise."""

from authtriage.parsers.authlog_v1 import PARSER_VERSION, AuthlogV1Parser
from authtriage.parsers.base import parse_lines

MIXED = """
this is not a log line at all
Apr 19 03:12:01 prod-web-01 sshd[9821]: Invalid user admin from 185.220.101.45 port 49234
Apr 19 03:14:22 prod-web-01 sshd[9930]: Failed password for ec2-user from 185.220.101.45 port 49300 ssh2
Apr 19 03:14:26 prod-web-01 sshd[9930]: Accepted password for ec2-user from 185.220.101.45 port 49306 ssh2
Apr 19 03:15:10 prod-web-01 sudo:     ec2-user : TTY=pts/0 ; PWD=/home/ec2-user ; USER=root ; COMMAND=/bin/bash
;;;;; totally garbage ;;;;
Apr 19 09:30:00 prod-web-01 sshd[12100]: Accepted publickey for deploy from 10.0.0.5 port 22 ssh2
""".strip()


def test_softfail_counts_garbage_and_does_not_raise():
    events, stats = parse_lines(MIXED.splitlines(), AuthlogV1Parser())
    assert stats.unparsed > 0
    assert stats.parsed >= 4
    assert stats.total_lines == stats.parsed + stats.unparsed
    assert all(ev.parser_version == PARSER_VERSION for ev in events)
    types = {ev.event_type for ev in events}
    assert "invalid_user" in types
    assert "failed_password" in types
    assert "accepted" in types


def test_journalctl_short_iso_line():
    line = (
        "2024-04-19T03:12:01+00:00 lab-vm sshd[12]: "
        "Failed password for alice from 192.0.2.77 port 22 ssh2"
    )
    events, stats = parse_lines([line], AuthlogV1Parser())
    assert stats.parsed == 1
    assert events[0].event_type == "failed_password"
    assert events[0].username == "alice"
    assert events[0].source_ip == "192.0.2.77"
    assert events[0].timestamp and events[0].timestamp.startswith("2024-04-19T03:12:01")
