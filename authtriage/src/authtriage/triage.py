"""Aggregate parsed auth events into a triage findings object.

Heuristics (intentionally simple; no spray/brute classifier):

* **Top source IPs** — count ``failed_password`` + ``invalid_user`` as failed,
  ``accepted`` as accepted. Sort by failed desc, then accepted desc, then IP.
  Cap at 20.
* **Top usernames** — failed/invalid attempts only. Sort by count desc, then
  name. Cap at 20.
* **Fail → success** — same ``source_ip`` had at least one failed/invalid
  event *before* an ``accepted`` event. Ordering is **file appearance order**
  (not wall-clock). Syslog timestamps omit year and can wrap, so appearance
  is the documented v0.1 rule. One finding per IP (first accepted after prior
  failures); username is the accepted account.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from authtriage.parsers.base import (
    EVENT_ACCEPTED,
    EVENT_FAILED_PASSWORD,
    EVENT_INVALID_USER,
    AuthEvent,
    ParseStats,
)

TOP_N = 20
FAIL_TYPES = {EVENT_FAILED_PASSWORD, EVENT_INVALID_USER}


@dataclass(frozen=True)
class IpCounts:
    ip: str
    failed_count: int
    accepted_count: int


@dataclass(frozen=True)
class UserCount:
    username: str
    count: int


@dataclass(frozen=True)
class FailThenSuccess:
    source_ip: str
    username: str
    prior_failures: int
    note: str = "successful logon after prior failures from same IP"


@dataclass
class TriageResult:
    top_source_ips: list[IpCounts]
    all_source_ips: list[IpCounts]
    top_usernames: list[UserCount]
    fail_then_success: list[FailThenSuccess]
    total_failed: int
    total_accepted: int
    total_invalid_user: int
    unparsed: int


def triage(events: list[AuthEvent], stats: ParseStats) -> TriageResult:
    failed_by_ip: Counter[str] = Counter()
    accepted_by_ip: Counter[str] = Counter()
    users: Counter[str] = Counter()
    prior_fail_by_ip: dict[str, int] = defaultdict(int)
    saw_success: set[str] = set()
    findings: list[FailThenSuccess] = []

    for event in events:
        ip = event.source_ip
        if event.event_type in FAIL_TYPES:
            if event.username:
                users[event.username] += 1
            if ip:
                failed_by_ip[ip] += 1
                if ip not in saw_success:
                    prior_fail_by_ip[ip] += 1
        elif event.event_type == EVENT_ACCEPTED:
            if ip:
                accepted_by_ip[ip] += 1
                if ip not in saw_success and prior_fail_by_ip[ip] >= 1:
                    findings.append(
                        FailThenSuccess(
                            source_ip=ip,
                            username=event.username or "",
                            prior_failures=prior_fail_by_ip[ip],
                        )
                    )
                    saw_success.add(ip)
                elif ip not in saw_success:
                    saw_success.add(ip)

    ips = set(failed_by_ip) | set(accepted_by_ip)
    all_ips = sorted(
        (
            IpCounts(
                ip=ip,
                failed_count=failed_by_ip[ip],
                accepted_count=accepted_by_ip[ip],
            )
            for ip in ips
        ),
        key=lambda row: (-row.failed_count, -row.accepted_count, row.ip),
    )
    top_ips = all_ips[:TOP_N]

    top_users = sorted(
        (UserCount(username=name, count=count) for name, count in users.items()),
        key=lambda row: (-row.count, row.username),
    )[:TOP_N]

    return TriageResult(
        top_source_ips=top_ips,
        all_source_ips=all_ips,
        top_usernames=top_users,
        fail_then_success=findings,
        total_failed=stats.by_type.get(EVENT_FAILED_PASSWORD, 0),
        total_accepted=stats.by_type.get(EVENT_ACCEPTED, 0),
        total_invalid_user=stats.by_type.get(EVENT_INVALID_USER, 0),
        unparsed=stats.unparsed,
    )
