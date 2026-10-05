"""Sudo parse + sudo after fail→success (lab study signal only)."""

from authtriage.parsers.authlog_v1 import AuthlogV1Parser
from authtriage.parsers.base import AuthEvent, ParseStats, parse_lines
from authtriage.triage import triage


def _ev(event_type: str, ip: str | None, user: str, **kwargs) -> AuthEvent:
    return AuthEvent(
        timestamp="Apr 19 03:00:00",
        host="lab",
        process="sshd" if event_type != "sudo" else "sudo",
        event_type=event_type,
        username=user,
        source_ip=ip,
        raw_line="",
        parser_version="authlog_v1",
        **kwargs,
    )


def test_parse_sudo_line():
    line = (
        "Apr 19 03:15:10 prod-web-01 sudo:     ec2-user : TTY=pts/0 ; "
        "PWD=/home/ec2-user ; USER=root ; COMMAND=/bin/bash"
    )
    events, stats = parse_lines([line], AuthlogV1Parser())
    assert stats.parsed == 1
    assert events[0].event_type == "sudo"
    assert events[0].username == "ec2-user"
    assert events[0].runas == "root"
    assert events[0].command == "/bin/bash"
    assert events[0].source_ip is None


def test_sudo_after_fail_then_success():
    events = [
        _ev("failed_password", "203.0.113.10", "root"),
        _ev("accepted", "203.0.113.10", "ubuntu"),
        _ev("sudo", None, "ubuntu", runas="root", command="/bin/id"),
        _ev("sudo", None, "deploy", runas="root", command="/usr/bin/rsync"),
    ]
    stats = ParseStats(total_lines=4, parsed=4, unparsed=0)
    stats.by_type.update(
        {"failed_password": 1, "accepted": 1, "sudo": 2}
    )
    result = triage(events, stats)
    assert result.total_sudo == 2
    assert len(result.sudo_after_fail_success) == 1
    hit = result.sudo_after_fail_success[0]
    assert hit.username == "ubuntu"
    assert hit.source_ip == "203.0.113.10"
    assert hit.command == "/bin/id"
    assert "deploy" not in {row.username for row in result.sudo_after_fail_success}


def test_sudo_before_success_is_not_flagged():
    events = [
        _ev("sudo", None, "ubuntu", runas="root", command="/bin/id"),
        _ev("failed_password", "203.0.113.11", "ubuntu"),
        _ev("accepted", "203.0.113.11", "ubuntu"),
    ]
    stats = ParseStats(total_lines=3, parsed=3, unparsed=0)
    stats.by_type.update({"sudo": 1, "failed_password": 1, "accepted": 1})
    result = triage(events, stats)
    assert result.fail_then_success
    assert result.sudo_after_fail_success == []
