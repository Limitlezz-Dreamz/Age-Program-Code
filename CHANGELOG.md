# Changelog

## 0.1.0 — M4 Dashboard / Detections / Event detail (unreleased)

### Added

- Dashboard: severity cards, sparkline, tops, evidence, coverage warnings
- Detections: virtualized paged table, sort/filter/group, triage, detail drawer
- Event detail: fields / raw JSON / XML / detections / decoded tabs (XSS-safe text)
- Store + Tauri IPC: `dashboard_summary`, `query_detections`, `get_detection`, `get_event`, `set_triage`

## 0.1.0 — M3 GUI shell (unreleased)

### Added

- Tauri IPC for case create/open/close/recent, add inputs, start/cancel analysis (Channel progress), settings
- React app shell: left nav, global filter bar state, Case ingest screen, Settings
- Drag-and-drop EVTX intake via Tauri webview events + dialog plugin
- Placeholder screens for later milestones

## 0.1.0 — M2 rules/detection (unreleased)

### Added

- `lw-rules`: Sigma pack import (dir/zip), SigmaHQ download, manifests/blake3, profiles, logsource mapping
- `lw-detect`: `RsigmaEngine`, built-ins B001–B027, analyzers A001/A002, event-time correlations, hunt orchestration
- `lw-store`: detection writes, ordered event iteration for re-detect
- `lw hunt` / `lw detections` CLI commands
- Conformance + golden (fixture) detection tests

## 0.1.0 — M1 ingest/normalize/store (unreleased)

### Added

- `lw-ingest`: EVTX discovery (extension + magic), SHA-256, parallel `evtx` parse, cancellation
- `lw-normalize`: flat event model per Section 6 (attributes shapes, UserData, Data[], aliases)
- `lw-store`: SQLite case DB, writer thread, batch insert, FTS finalize, paged queries
- `lw ingest` / `lw stats` CLI commands
- CC0 sample under `tests/fixtures/cc0/`; fixture-backed tests (`LW_FIXTURES=1`)

## 0.1.0 — M0 scaffolding

### Added

- Cargo workspace with crates: `lw-core`, `lw-ingest`, `lw-normalize`, `lw-rules`, `lw-detect`, `lw-store`, `lw-report`, `lw-cli`
- Tauri 2 + React + TypeScript + Vite shell
- Tailwind CSS + minimal shadcn-style `Button` component (dark theme)
- `justfile` targets: `dev`, `ci`, `bench`, `fixtures`, `bundle`
- `deny.toml` license allowlist (MIT/Apache/BSD/ISC/Zlib/Unicode/MPL/CC0)
- GitHub Actions `ci.yml` (ubuntu, windows, macos-14) and `release.yml` stub
- Fixture fetch scripts (`scripts/fetch-fixtures.sh`, `.ps1`)
- Stub mapping / event-description resources
