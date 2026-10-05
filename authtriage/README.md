# AuthTriage for Linux

Read-only CLI that ingests a Linux `auth.log` (or syslog-style / `journalctl` text export) and writes a **markdown one-pager**, an **IOC IP CSV**, and a **self-contained HTML report** (SVG sparkline of fails vs successes).

> **LAB / PUBLIC DATA ONLY — never use employer or production logs.**

This is **triage, not ops**. No ban, no fail2ban hooks, no host mutation. Unknown lines are counted and skipped; the run does not crash.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

authtriage --help
# or: python -m authtriage --help

authtriage testdata/sentinel_sample_auth.log -o out/
pytest -q
```

Writes `out/report.md`, `out/iocs.csv`, `out/report.html`, and `out/report.json`. `--format` is `md`, `csv`, `html`, `json`, `both` (md+csv), or `all` (default).

Open `out/report.html` in a browser, or serve it on localhost only:

```bash
authtriage testdata/sentinel_sample_auth.log -o out/ --serve
# http://127.0.0.1:8765/report.html  — Ctrl+C to stop
```

`--serve` binds **127.0.0.1** only. It does not scan the network or change the host.

## journalctl pipe (lab VM only)

AuthTriage never runs `sudo` and never talks to the journal itself. You export text, then pipe it. **Not a work host.**

```bash
# short-iso matches authlog_v1. sudo only if your user cannot read the journal
# (not in systemd-journal / adm). Skip sudo when `journalctl --user` is enough.
sudo journalctl -u ssh -u sshd -o short-iso --no-pager | authtriage - -o out/
```

If `ssh` / `sshd` unit names differ on the distro, list units first (`systemctl list-units '*ssh*'`). Still lab-only.

## Multi-file batch

```bash
authtriage testdata/ -o out/
authtriage /path/to/lab-logs --recursive -o out/
```

Collects `*.log` and `*.txt` in that folder (and subfolders with `--recursive`).

## How to read a report

1. **Top source IPs** and **targeted/invalid usernames**
2. **Fail→success** — same IP had failures/invalids *before* an accepted logon (file order)
3. **Spray vs brute** (heuristic, not a detector):
   - spray: 5+ distinct failed/invalid usernames from one IP
   - brute: 5+ failures against one username from one IP
   - mixed: both
4. **Sudo after fail→success** — that accepted user later ran sudo (file order)
5. **ATT&CK learner notes** — short original blurbs with links to T1110 / T1110.001 / T1110.003 / T1078 / T1548.003. We do **not** copy ATT&CK page text.

These are study patterns on lab samples — not a remediation or ban list.

## Lab sample logs (public only)

Do **not** ingest work/employer logs. Fetch public teaching samples into `testdata/` yourself if you want a larger golden:

| Dataset | Role | URL |
| --- | --- | --- |
| Elastic `suspicious_login` `auth.log` | Primary large public golden | [elastic/examples auth.log](https://github.com/elastic/examples/blob/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity/data/auth.log) |
| Sentinel `sample-auth.log` | Small fail→success fixture (committed excerpt) | [BrandoBank/sentinel](https://github.com/BrandoBank/sentinel) |
| Loghub SSH / Linux | Larger corpora (cite upstream if you redistribute) | [logpai/loghub](https://github.com/logpai/loghub) · [Zenodo 3227177](https://zenodo.org/records/3227177) |
| Linux_2k.log | Tiny teaching slice | [chowdhuryrz/linux-log-analysis](https://github.com/chowdhuryrz/linux-log-analysis) |

See `testdata/README.md` for curl one-liners. Sample logs remain under **their upstream terms**; this repo’s code is MIT.

## Parser versioning + soft-fail

`authlog_v1` extracts sshd failed / invalid / accepted lines and sudo COMMAND lines. Everything else (PAM, cron, useradd, garbage) increments `unparsed` and is skipped. Exit code is **0** on unknown lines; there is no traceback.

To extend: add `src/authtriage/parsers/authlog_v2.py` with a new `PARSER_VERSION`. Keep v1 and its goldens unchanged. Wire v2 behind an explicit flag later; do not silently replace v1.

## Out of scope

- Auto-block, fail2ban, iptables, or any host mutation
- SIEM pipelines
- Work / employer / production logs
- AuthTriage calling `journalctl` or `sudo` for you

## Study, don’t clone

Closest public shapes (read them; this tree is original MIT code):

- [soc-auth-triage](https://github.com/daniel-ploetzl/soc-auth-triage)
- [pylast](https://github.com/ForensicFoundry/pylast)
- [BrandoBank/sentinel](https://github.com/BrandoBank/sentinel)

## License

MIT for AuthTriage code (copyright Adrian / Limitlezz Dreamz). Do not vendor GPL/AGPL. Runtime is **stdlib-only**.
