"""macOS log show / compact OpenSSH lines (lab fixtures only)."""

from pathlib import Path

from authtriage.parsers.authlog_v1 import AuthlogV1Parser
from authtriage.parsers.base import parse_lines
from authtriage.triage import triage

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / "testdata" / "macos_sshd_snippet.log"


def test_macos_compact_and_sshd_session():
    compact = (
        "2024-10-05 10:05:12.456 lab-mac.local sshd-session[5101]: "
        "Failed password for alex from 10.0.0.8 port 61002 ssh2"
    )
    events, stats = parse_lines([compact], AuthlogV1Parser())
    assert stats.parsed == 1
    assert events[0].process == "sshd-session"
    assert events[0].username == "alex"
    assert events[0].source_ip == "10.0.0.8"


def test_macos_failed_publickey_and_keyboard():
    lines = [
        "Oct  5 09:12:05 lab-mac.local sshd[4012]: Failed publickey for alex from 198.51.100.40 port 49238 ssh2",
        "Oct  5 09:12:06 lab-mac.local sshd[4012]: Failed keyboard-interactive/pam for alex from 198.51.100.40 port 49239 ssh2",
    ]
    events, stats = parse_lines(lines, AuthlogV1Parser())
    assert stats.parsed == 2
    assert all(ev.event_type == "failed_password" for ev in events)


def test_macos_snippet_fail_then_success_and_sudo():
    events, stats = parse_lines(
        MAC.read_text(encoding="utf-8").splitlines(),
        AuthlogV1Parser(),
    )
    result = triage(events, stats)
    assert stats.unparsed >= 1
    assert result.fail_then_success
    assert any(item.source_ip == "198.51.100.40" for item in result.fail_then_success)
    users = {item.username for item in result.sudo_after_fail_success}
    assert "alex" in users
    assert "deploy" not in users
