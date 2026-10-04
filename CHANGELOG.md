# Changelog

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
