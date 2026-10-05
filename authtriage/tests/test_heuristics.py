"""Spray vs brute heuristic (distinct users vs same-user volume)."""

from authtriage.parsers.base import AuthEvent, ParseStats
from authtriage.triage import KIND_BRUTE, KIND_MIXED, KIND_SPRAY, triage


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


def test_spray_many_users_one_ip():
    users = ["admin", "root", "test", "ubuntu", "git"]
    events = [_ev("invalid_user", "203.0.113.80", name) for name in users]
    stats = ParseStats(total_lines=5, parsed=5, unparsed=0)
    stats.by_type["invalid_user"] = 5
    result = triage(events, stats)
    assert len(result.spray_brute) == 1
    hit = result.spray_brute[0]
    assert hit.source_ip == "203.0.113.80"
    assert hit.kind == KIND_SPRAY
    assert hit.distinct_users == 5
    assert result.timeline


def test_brute_same_user_many_fails():
    events = [_ev("failed_password", "203.0.113.81", "alice") for _ in range(5)]
    stats = ParseStats(total_lines=5, parsed=5, unparsed=0)
    stats.by_type["failed_password"] = 5
    result = triage(events, stats)
    assert result.spray_brute[0].kind == KIND_BRUTE
    assert result.spray_brute[0].max_user_fails == 5


def test_mixed_spray_and_brute():
    events = [_ev("invalid_user", "203.0.113.82", f"u{i}") for i in range(5)]
    events.extend([_ev("failed_password", "203.0.113.82", "u0") for _ in range(4)])
    stats = ParseStats(total_lines=9, parsed=9, unparsed=0)
    stats.by_type.update({"invalid_user": 5, "failed_password": 4})
    result = triage(events, stats)
    assert result.spray_brute[0].kind == KIND_MIXED


def test_below_threshold_is_quiet():
    events = [
        _ev("failed_password", "203.0.113.83", "bob"),
        _ev("failed_password", "203.0.113.83", "bob"),
        _ev("invalid_user", "203.0.113.83", "carol"),
    ]
    stats = ParseStats(total_lines=3, parsed=3, unparsed=0)
    stats.by_type.update({"failed_password": 2, "invalid_user": 1})
    result = triage(events, stats)
    assert result.spray_brute == []
