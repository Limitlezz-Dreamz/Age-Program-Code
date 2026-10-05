# Changelog

## 0.1.1 — Post-release polish (unreleased)

### Added

- In-app updater (Tauri plugin) against GitHub Releases; Settings → Check for updates
- Optional Apple / Windows / updater signing hooks in the release workflow
- Expanded MITRE ATT&CK technique map for built-in rules
- Rules screen: filter Enabled / Disabled / All

### Changed

- Product branding finalized as **Logwarden** (removed placeholder note)
- Packaging docs cover updater keys and code-signing secrets

## 0.1.0 — 2026-10-04

First public release. Installers: https://github.com/Limitlezz-Dreamz/Age-Program-Code/releases/tag/v0.1.0

### Added

- **M0** Scaffolding: Tauri 2 + React/TS workspace, CI, license deny
- **M1** Headless EVTX ingest, normalize, SQLite case store, `lw ingest` / `lw stats`
- **M2** Sigma packs, built-ins B001–B027, hunt engine, `lw hunt` / `lw detections`
- **M3** GUI shell: case ingest, progress, settings, global filters
- **M4** Dashboard, detections list/triage, event detail (XSS-safe)
- **M5** Timeline, Explorer (FTS), Pivots / logons
- **M6** Rules manager, suppressions, re-run; CSV/JSON/JSONL/HTML export
- **M7** Packaging: deb / AppImage / NSIS / MSI / DMG; release workflow
