# Extending AuthTriage

## Adding `authlog_v2`

1. Copy `src/authtriage/parsers/authlog_v1.py` to `authlog_v2.py`.
2. Set `PARSER_VERSION = "authlog_v2"` and keep v1 **unchanged**.
3. Add tests that pin v2 behavior; do not rewrite v1 goldens.
4. Wire v2 behind an explicit CLI flag (for example `--parser authlog_v2`). Default stays v1 until a later major bump.

Unknown lines must still soft-fail: increment `unparsed`, never raise, exit 0.

## Heuristics

Spray/brute thresholds live in `triage.py` (`SPRAY_MIN_USERS`, `BRUTE_MIN_FAILS`). Change them in one place and document the new numbers in the README. Do not turn them into a “detector” or a ban list.

## Rules

- Lab / public sample logs only. No employer or production logs in `testdata/` or issues.
- No ban/block, fail2ban, or host mutation.
- Stdlib-only for runtime. New dependencies must be MIT, Apache-2.0, or BSD.
- No GPL/AGPL in the tree.
