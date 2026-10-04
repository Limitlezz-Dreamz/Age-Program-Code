# Test fixtures

## Layout

- `cc0/` — small CC0 / own fixtures vendored for offline `cargo test`.
- `ext/` — **gitignored**. Populated by `just fixtures` / `scripts/fetch-fixtures.sh`.
- `PINS` — commit pins written by the fetch scripts.

## Datasets (do not commit into this repo)

| Dataset | License | Notes |
|---|---|---|
| EVTX-ATTACK-SAMPLES | GPL-3.0 (data) | Fetch only |
| hayabusa-sample-evtx | No license declared | Fetch only |
| EVTX-to-MITRE-Attack | CC0 | Small subset may be vendored under `cc0/` |

Fixture-heavy tests are `#[ignore]` unless `LW_FIXTURES=1`.
