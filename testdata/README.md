# testdata — lab / public samples only

**Never drop employer or production logs in this folder.**

This tree may contain **small public excerpts** for tests. Large corpora stay upstream; download them locally if you need them. We do **not** own these logs. Attribute the projects below; their licenses apply to their files.

## Sources

| File / fetch | Upstream | Notes |
| --- | --- | --- |
| `sentinel_sample_auth.log` | [BrandoBank/sentinel](https://github.com/BrandoBank/sentinel) `sample-logs/sample-auth.log` | Small intentional findings, including fail→success. Committed because it is tiny and needed for golden tests. |
| `elastic_auth_snippet.log` | [elastic/examples](https://github.com/elastic/examples/blob/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity/data/auth.log) | Short slice of sshd invalid/accepted lines. **Not** the full Elastic file. |
| Elastic full `auth.log` (optional) | same URL, raw file ~800KB | Do not commit unless you need it; fetch locally. |
| Loghub SSH + Linux | [logpai/loghub](https://github.com/logpai/loghub) · [Zenodo 3227177](https://zenodo.org/records/3227177) (`SSH.tar.gz`, `Linux.tar.gz`) | Cite Loghub/Zenodo if you redistribute. |
| `macos_sshd_snippet.log` | Original synthetic fixture | Lab-style macOS syslog + compact `log show` lines (RFC1918 IPs). Not copied from a real Mac. |

## Fetch locally (optional)

Elastic full file:

```bash
curl -L -o testdata/elastic_auth.log \
  "https://raw.githubusercontent.com/elastic/examples/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity/data/auth.log"
```

Sentinel sample (already committed; re-fetch if you want a fresh copy):

```bash
curl -L -o testdata/sentinel_sample_auth.log \
  "https://raw.githubusercontent.com/BrandoBank/sentinel/master/sample-logs/sample-auth.log"
```

Optional Linux_2k:

```bash
curl -L -o testdata/Linux_2k.log \
  "https://raw.githubusercontent.com/chowdhuryrz/linux-log-analysis/main/Linux_2k.log"
```

Then:

```bash
authtriage testdata/sentinel_sample_auth.log -o out/
# or
authtriage testdata/elastic_auth.log -o out/
```

## Generate your own (still lab-only)

Disposable Ubuntu VM — **not a work host**:

```bash
sudo journalctl -u ssh -u sshd -o short-iso --no-pager | authtriage - -o out/
# or save first:
journalctl -u ssh -o short-iso --no-pager > testdata/ssh.journal.txt
authtriage testdata/ssh.journal.txt -o out/
```

AuthTriage never invokes `sudo`, `journalctl`, or `log show` itself.

macOS lab Mac (not a work Mac):

```bash
log show --style syslog --predicate \
  'process == "sshd" OR process == "sshd-session" OR process == "sudo"' \
  --last 24h | authtriage - -o out/
```

Or use the committed synthetic snippet:

```bash
authtriage testdata/macos_sshd_snippet.log -o out/
```

