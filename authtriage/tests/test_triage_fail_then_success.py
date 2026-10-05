"""Fail→success: same IP, failures before an accepted event."""

from authtriage.parsers.base import AuthEvent, ParseStats
from authtriage.triage import triage


def _ev(event_type: str, ip: str, user: str, ts: str = "Apr 19 03:00:00") -> AuthEvent:
    return AuthEvent(
        timestamp=ts,
        host="lab",
        process="sshd",
        event_type=event_type,
        username=user,
        source_ip=ip,
        raw_line="",
        parser_version="authlog_v1",
    )


def test_fail_then_success_same_ip():
    events = [
        _ev("failed_password", "203.0.113.10", "root"),
        _ev("invalid_user", "203.0.113.10", "admin"),
        _ev("accepted", "203.0.113.10", "ubuntu"),
        _ev("accepted", "198.51.100.8", "alice"),
    ]
    stats = ParseStats(total_lines=4, parsed=4, unparsed=0)
    stats.by_type.update(
        {"failed_password": 1, "invalid_user": 1, "accepted": 2}
    )
    result = triage(events, stats)
    assert len(result.fail_then_success) == 1
    finding = result.fail_then_success[0]
    assert finding.source_ip == "203.0.113.10"
    assert finding.username == "ubuntu"
    assert finding.prior_failures == 2
    assert result.top_source_ips[0].ip == "203.0.113.10"
    assert result.top_source_ips[0].failed_count == 2
    assert result.top_source_ips[0].accepted_count == 1
    users = {row.username: row.count for row in result.top_usernames}
    assert users["root"] == 1
    assert users["admin"] == 1
    assert "alice" not in users
    assert "ubuntu" not in users


def test_success_without_prior_fail_is_not_flagged():
    events = [_ev("accepted", "203.0.113.50", "deploy")]
    stats = ParseStats(total_lines=1, parsed=1, unparsed=0)
    stats.by_type["accepted"] = 1
    result = triage(events, stats)
    assert result.fail_then_success == []
