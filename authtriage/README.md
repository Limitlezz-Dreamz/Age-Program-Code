# AuthTriage for Linux

Read-only CLI that ingests a Linux `auth.log` (or syslog-style / `journalctl` text export) and prints a **markdown one-pager**: top source IPs, targeted/invalid users, fail→success from the same IP, plus an IOC IP CSV.

> **LAB / PUBLIC DATA ONLY — never use employer or production logs.**

This is **triage, not ops**. No ban, no fail2ban hooks, no host mutation. Unknown lines are counted and skipped (`unparsed_lines`); the run does not crash.

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

Writes `out/report.md` and `out/iocs.csv`. Default `--format` is `both` (`md`, `csv`, or `both`).

## How to read a report

Look at **top source IPs** and **targeted/invalid usernames** first, then the **fail→success** section (same IP had failures/invalids *before* an accepted logon, in file order). These are study patterns on lab samples — not a remediation or ban list.

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

`authlog_v1` extracts sshd failed / invalid / accepted lines. Everything else (sudo, PAM, cron, garbage) increments `unparsed` and is skipped. Exit code is **0** on unknown lines; there is no traceback.

To extend: add `src/authtriage/parsers/authlog_v2.py` with a new `PARSER_VERSION`. Keep v1 and its goldens unchanged. Wire v2 behind an explicit flag later; do not silently replace v1.

## Out of scope

- Auto-block, fail2ban, iptables, or any host mutation
- SIEM pipelines
- Work / employer / production logs
- Live `journalctl` pipe (nice-to-have; stdin later)
- HTML sparklines, ATT&CK blurbs, spray-vs-brute classifier, multi-file batch

## Study, don’t clone

Closest public shapes (read them; this tree is original MIT code):

- [soc-auth-triage](https://github.com/daniel-ploetzl/soc-auth-triage)
- [pylast](https://github.com/ForensicFoundry/pylast)
- [BrandoBank/sentinel](https://github.com/BrandoBank/sentinel)

## License

MIT for AuthTriage code (copyright Adrian / Limitlezz Dreamz). Do not vendor GPL/AGPL. Runtime is **stdlib-only**.
