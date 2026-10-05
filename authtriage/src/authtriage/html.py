"""Self-contained HTML report with SVG sparklines. Stdlib only."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from authtriage.learn import learner_blurbs
from authtriage.parsers.base import ParseStats
from authtriage.report import LAB_BANNER
from authtriage.triage import TriageResult


def write_html(
    result: TriageResult,
    stats: ParseStats,
    out_path: Path,
    input_name: str,
    parser_version: str,
) -> Path:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    spark = _sparkline_svg(result)
    blurbs = learner_blurbs(result)
    body = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8"/>',
        "<title>AuthTriage report</title>",
        "<style>",
        "body{font:16px/1.4 system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#111}",
        "table{border-collapse:collapse;width:100%;margin:0.75rem 0 1.5rem}",
        "th,td{border:1px solid #ccc;padding:0.35rem 0.5rem;text-align:left}",
        "td.num,th.num{text-align:right}",
        ".banner{background:#fff3cd;border:1px solid #f0c36d;padding:0.75rem 1rem}",
        "code{font-size:0.9em}",
        ".spark{margin:1rem 0}",
        "footer{color:#555;font-size:0.9rem;margin-top:2rem}",
        "</style>",
        "</head>",
        "<body>",
        "<h1>AuthTriage report</h1>",
        f"<p><strong>Generated:</strong> {html.escape(generated)}<br/>",
        f"<strong>Input:</strong> <code>{html.escape(input_name)}</code><br/>",
        f"<strong>Parser:</strong> <code>{html.escape(parser_version)}</code></p>",
        f'<p class="banner">{html.escape(LAB_BANNER)}</p>',
        "<h2>Fails / successes over time</h2>",
        '<div class="spark">',
        spark,
        "</div>",
        "<p>Red = failed/invalid &nbsp; Green = accepted. Hour buckets from the log timestamps (appearance order).</p>",
        "<h2>Summary</h2>",
        "<table>",
        "<tr><th>Metric</th><th class='num'>Count</th></tr>",
        f"<tr><td>Total lines</td><td class='num'>{stats.total_lines}</td></tr>",
        f"<tr><td>Parsed events</td><td class='num'>{stats.parsed}</td></tr>",
        f"<tr><td>Unparsed lines</td><td class='num'>{stats.unparsed}</td></tr>",
        f"<tr><td>Failed password</td><td class='num'>{result.total_failed}</td></tr>",
        f"<tr><td>Invalid user</td><td class='num'>{result.total_invalid_user}</td></tr>",
        f"<tr><td>Accepted</td><td class='num'>{result.total_accepted}</td></tr>",
        f"<tr><td>Sudo</td><td class='num'>{result.total_sudo}</td></tr>",
        "</table>",
        "<h2>Top source IPs</h2>",
        _ip_table(result),
        "<h2>Top targeted / invalid usernames</h2>",
        _user_table(result),
        "<h2>Fail → success</h2>",
        "<p>Same source IP had failed or invalid attempts <strong>before</strong> an accepted logon (file order).</p>",
        _fail_table(result),
        "<h2>Spray vs brute (heuristic)</h2>",
        "<p>Spray: many distinct usernames from one IP. Brute: many failures against one username from one IP. Not a detector.</p>",
        _spray_table(result),
        "<h2>Sudo after fail → success</h2>",
        "<p>Invoking user matches an accepted account that had prior failures from the same IP. Sequence only — not a verdict.</p>",
        _sudo_table(result),
        "<h2>ATT&amp;CK learner notes</h2>",
        "<p>Original study blurbs with links. We do not copy ATT&amp;CK page text into this report.</p>",
        _blurb_html(blurbs),
        "<h2>Unparsed lines</h2>",
        f"<p><code>authlog_v1</code> skipped <strong>{stats.unparsed}</strong> line(s). Unknown lines are counted and ignored (soft-fail).</p>",
        "<h2>How to read this</h2>",
        "<p>This is <strong>triage</strong>, not remediation. Open this file locally. AuthTriage does not ban, block, or talk to fail2ban.</p>",
        "<footer>AuthTriage — lab / public data only. MIT.</footer>",
        "</body>",
        "</html>",
        "",
    ]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(body), encoding="utf-8")
    return out_path


def serve_local(directory: Path, port: int = 8765) -> None:
    """Bind 127.0.0.1 only and serve ``directory``. Read-only. Lab use."""
    import http.server
    import socketserver

    directory = directory.resolve()

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(directory), **kwargs)

    class Server(socketserver.TCPServer):
        allow_reuse_address = True

    with Server(("127.0.0.1", port), Handler) as httpd:
        print(
            f"serving {directory} at http://127.0.0.1:{port}/report.html "
            "(Ctrl+C to stop)",
            flush=True,
        )
        httpd.serve_forever()


def _sparkline_svg(result: TriageResult) -> str:
    buckets = result.timeline
    if not buckets:
        return "<p><em>No timestamped sshd events to chart.</em></p>"
    failed = [row.failed_count for row in buckets]
    accepted = [row.accepted_count for row in buckets]
    width, height = 640, 80
    peak = max(max(failed), max(accepted), 1)
    n = len(buckets)

    def points(values: list[int]) -> str:
        coords: list[str] = []
        for i, value in enumerate(values):
            x = 8 + (width - 16) * (i / max(n - 1, 1))
            y = height - 8 - (height - 16) * (value / peak)
            coords.append(f"{x:.1f},{y:.1f}")
        if n == 1:
            coords.append(f"{width - 8:.1f},{coords[0].split(',')[1]}")
        return " ".join(coords)

    labels = "".join(
        f'<title>{html.escape(row.label)}: fail {row.failed_count}, '
        f"ok {row.accepted_count}</title>"
        for row in buckets
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" aria-label="fail vs accepted sparkline">'
        f"{labels}"
        f'<polyline fill="none" stroke="#b42318" stroke-width="2" points="{points(failed)}"/>'
        f'<polyline fill="none" stroke="#0f7b3a" stroke-width="2" points="{points(accepted)}"/>'
        "</svg>"
    )


def _ip_table(result: TriageResult) -> str:
    rows = [
        "<table><tr><th>IP</th><th class='num'>Failed / invalid</th>"
        "<th class='num'>Accepted</th></tr>"
    ]
    if result.top_source_ips:
        for row in result.top_source_ips:
            rows.append(
                f"<tr><td><code>{html.escape(row.ip)}</code></td>"
                f"<td class='num'>{row.failed_count}</td>"
                f"<td class='num'>{row.accepted_count}</td></tr>"
            )
    else:
        rows.append("<tr><td colspan='3'><em>none</em></td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def _user_table(result: TriageResult) -> str:
    rows = [
        "<table><tr><th>Username</th><th class='num'>Failed / invalid attempts</th></tr>"
    ]
    if result.top_usernames:
        for row in result.top_usernames:
            rows.append(
                f"<tr><td><code>{html.escape(row.username)}</code></td>"
                f"<td class='num'>{row.count}</td></tr>"
            )
    else:
        rows.append("<tr><td colspan='2'><em>none</em></td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def _fail_table(result: TriageResult) -> str:
    if not result.fail_then_success:
        return "<p><em>No fail→success findings in this file.</em></p>"
    rows = [
        "<table><tr><th>IP</th><th>Accepted user</th>"
        "<th class='num'>Prior failures</th><th>Note</th></tr>"
    ]
    for finding in result.fail_then_success:
        rows.append(
            f"<tr><td><code>{html.escape(finding.source_ip)}</code></td>"
            f"<td><code>{html.escape(finding.username)}</code></td>"
            f"<td class='num'>{finding.prior_failures}</td>"
            f"<td>{html.escape(finding.note)}</td></tr>"
        )
    rows.append("</table>")
    return "\n".join(rows)


def _spray_table(result: TriageResult) -> str:
    if not result.spray_brute:
        return "<p><em>No spray/brute heuristic hits (thresholds not met).</em></p>"
    rows = [
        "<table><tr><th>IP</th><th>Kind</th><th class='num'>Distinct users</th>"
        "<th class='num'>Max per user</th><th>Note</th></tr>"
    ]
    for finding in result.spray_brute:
        rows.append(
            f"<tr><td><code>{html.escape(finding.source_ip)}</code></td>"
            f"<td>{html.escape(finding.kind)}</td>"
            f"<td class='num'>{finding.distinct_users}</td>"
            f"<td class='num'>{finding.max_user_fails}</td>"
            f"<td>{html.escape(finding.note)}</td></tr>"
        )
    rows.append("</table>")
    return "\n".join(rows)


def _sudo_table(result: TriageResult) -> str:
    if not result.sudo_after_fail_success:
        return "<p><em>No sudo-after-fail→success findings.</em></p>"
    rows = [
        "<table><tr><th>User</th><th>Source IP</th><th>Runas</th><th>Command</th></tr>"
    ]
    for item in result.sudo_after_fail_success:
        rows.append(
            f"<tr><td><code>{html.escape(item.username)}</code></td>"
            f"<td><code>{html.escape(item.source_ip)}</code></td>"
            f"<td><code>{html.escape(item.runas)}</code></td>"
            f"<td><code>{html.escape(item.command)}</code></td></tr>"
        )
    rows.append("</table>")
    return "\n".join(rows)


def _blurb_html(blurbs: list[tuple[str, str, str, str]]) -> str:
    if not blurbs:
        return "<p><em>No ATT&amp;CK notes for this file (no matching patterns).</em></p>"
    parts = ["<ul>"]
    for tech_id, name, url, blurb in blurbs:
        parts.append(
            "<li>"
            f'<a href="{html.escape(url, quote=True)}">{html.escape(tech_id)}</a> '
            f"<strong>{html.escape(name)}</strong> — {html.escape(blurb)}"
            "</li>"
        )
    parts.append("</ul>")
    return "\n".join(parts)
