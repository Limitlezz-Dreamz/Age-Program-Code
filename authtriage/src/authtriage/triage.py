"""Aggregate parsed auth events into a triage findings object.

Heuristics (intentionally simple):

* **Top source IPs** — count ``failed_password`` + ``invalid_user`` as failed,
  ``accepted`` as accepted. Sort by failed desc, then accepted desc, then IP.
  Cap at 20.
* **Top usernames** — failed/invalid attempts only. Sort by count desc, then
  name. Cap at 20.
* **Fail → success** — same ``source_ip`` had at least one failed/invalid
  event *before* an ``accepted`` event. Ordering is **file appearance order**
  (not wall-clock). Syslog timestamps omit year and can wrap, so appearance
  is the documented rule. One finding per IP (first accepted after prior
  failures); username is the accepted account.
* **Spray vs brute** (per source IP, whole file, appearance order):
  - spray: ``>= SPRAY_MIN_USERS`` distinct failed/invalid usernames
  - brute: ``>= BRUTE_MIN_FAILS`` failures against a *single* username
  - mixed: both
  Not a classifier and not a detector. Thresholds are documented constants.
* **Timeline** — failed vs accepted counts bucketed by syslog hour / ISO hour
  for HTML sparklines.
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
SPRAY_MIN_USERS = 5
BRUTE_MIN_FAILS = 5
KIND_SPRAY = "spray"
KIND_BRUTE = "brute"
KIND_MIXED = "mixed"


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


@dataclass(frozen=True)
class SprayBruteFinding:
    source_ip: str
    kind: str
    distinct_users: int
    max_user_fails: int
    total_fails: int
    note: str


@dataclass(frozen=True)
class TimelineBucket:
    label: str
    failed_count: int
    accepted_count: int


@dataclass
class TriageResult:
    top_source_ips: list[IpCounts]
    all_source_ips: list[IpCounts]
    top_usernames: list[UserCount]
    fail_then_success: list[FailThenSuccess]
    spray_brute: list[SprayBruteFinding]
    timeline: list[TimelineBucket]
    total_failed: int
    total_accepted: int
    total_invalid_user: int
    unparsed: int


def triage(events: list[AuthEvent], stats: ParseStats) -> TriageResult:
    failed_by_ip: Counter[str] = Counter()
    accepted_by_ip: Counter[str] = Counter()
    users: Counter[str] = Counter()
    fails_by_ip_user: dict[str, Counter[str]] = defaultdict(Counter)
    prior_fail_by_ip: dict[str, int] = defaultdict(int)
    saw_success: set[str] = set()
    findings: list[FailThenSuccess] = []
    timeline_fail: Counter[str] = Counter()
    timeline_ok: Counter[str] = Counter()
    timeline_order: list[str] = []

    for index, event in enumerate(events):
        label = _bucket_label(event.timestamp, index)
        ip = event.source_ip
        if event.event_type in FAIL_TYPES:
            timeline_fail[label] += 1
            if label not in timeline_order:
                timeline_order.append(label)
            if event.username:
                users[event.username] += 1
            if ip:
                failed_by_ip[ip] += 1
                if event.username:
                    fails_by_ip_user[ip][event.username] += 1
                if ip not in saw_success:
                    prior_fail_by_ip[ip] += 1
        elif event.event_type == EVENT_ACCEPTED:
            timeline_ok[label] += 1
            if label not in timeline_order:
                timeline_order.append(label)
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

    spray_brute = _spray_brute(fails_by_ip_user)
    timeline = [
        TimelineBucket(
            label=label,
            failed_count=timeline_fail[label],
            accepted_count=timeline_ok[label],
        )
        for label in timeline_order
    ]

    return TriageResult(
        top_source_ips=top_ips,
        all_source_ips=all_ips,
        top_usernames=top_users,
        fail_then_success=findings,
        spray_brute=spray_brute,
        timeline=timeline,
        total_failed=stats.by_type.get(EVENT_FAILED_PASSWORD, 0),
        total_accepted=stats.by_type.get(EVENT_ACCEPTED, 0),
        total_invalid_user=stats.by_type.get(EVENT_INVALID_USER, 0),
        unparsed=stats.unparsed,
    )


def _spray_brute(
    fails_by_ip_user: dict[str, Counter[str]],
) -> list[SprayBruteFinding]:
    findings: list[SprayBruteFinding] = []
    for ip, user_counts in fails_by_ip_user.items():
        distinct = len(user_counts)
        max_user = max(user_counts.values()) if user_counts else 0
        total = sum(user_counts.values())
        is_spray = distinct >= SPRAY_MIN_USERS
        is_brute = max_user >= BRUTE_MIN_FAILS
        if is_spray and is_brute:
            kind = KIND_MIXED
            note = (
                f"same IP hit {distinct} usernames and >= {BRUTE_MIN_FAILS} "
                "fails on one account (spray + brute heuristic)"
            )
        elif is_spray:
            kind = KIND_SPRAY
            note = (
                f"{distinct} distinct failed/invalid usernames from one IP "
                f"(threshold {SPRAY_MIN_USERS})"
            )
        elif is_brute:
            kind = KIND_BRUTE
            note = (
                f"{max_user} failures against one username from one IP "
                f"(threshold {BRUTE_MIN_FAILS})"
            )
        else:
            continue
        findings.append(
            SprayBruteFinding(
                source_ip=ip,
                kind=kind,
                distinct_users=distinct,
                max_user_fails=max_user,
                total_fails=total,
                note=note,
            )
        )
    findings.sort(key=lambda row: (-row.total_fails, row.source_ip))
    return findings


def _bucket_label(timestamp: str | None, index: int) -> str:
    if not timestamp:
        return f"seq-{index // 25}"
    parts = timestamp.split()
    if len(parts) >= 3 and ":" in parts[2]:
        hour = parts[2].split(":", 1)[0]
        return f"{parts[0]} {parts[1]} {hour}h"
    if "T" in timestamp:
        return timestamp[:13] + "h"
    return timestamp[:16]
