# Changelog

## 0.1.0 — M0 scaffolding (unreleased)

### Added

- Cargo workspace with crates: `lw-core`, `lw-ingest`, `lw-normalize`, `lw-rules`, `lw-detect`, `lw-store`, `lw-report`, `lw-cli`
- Tauri 2 + React + TypeScript + Vite shell
- Tailwind CSS + minimal shadcn-style `Button` component (dark theme)
- `justfile` targets: `dev`, `ci`, `bench`, `fixtures`, `bundle`
- `deny.toml` license allowlist (MIT/Apache/BSD/ISC/Zlib/Unicode/MPL/CC0)
- GitHub Actions `ci.yml` (ubuntu, windows, macos-14) and `release.yml` stub
- Fixture fetch scripts (`scripts/fetch-fixtures.sh`, `.ps1`)
- Stub mapping / event-description resources
