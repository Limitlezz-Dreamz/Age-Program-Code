# Logwarden

Cross-platform EVTX threat-hunting desktop app (Chainsaw-style workflow with a GUI).

**Stack:** Tauri 2 · Rust · React · TypeScript · SQLite · Sigma

> Product name is a placeholder — rename via `lw_core::APP_NAME` / `src/lib/constants.ts`.

## Status

Milestone **M0** (scaffolding + CI) in progress. See `docs/milestones/` and the build spec.

## Develop

```bash
npm install
just ci          # fmt, clippy, tests, deny, tsc, eslint, vitest
just dev         # tauri dev (needs OS webview deps)
```

## License hygiene

- App code: MIT OR Apache-2.0
- No GPL / AGPL / LGPL dependencies (`cargo deny` + npm license check)
- Sigma rule packs are downloaded at runtime (DRL 1.1); author attribution required on every match
- Do **not** copy code or mapping files from Chainsaw, Hayabusa, Velociraptor, DeepBlueCLI, APT-Hunter, or Zircolite

## Docs

- Build spec and research report (project planning docs)
- `CHANGELOG.md`
- `docs/milestones/M0.md`
