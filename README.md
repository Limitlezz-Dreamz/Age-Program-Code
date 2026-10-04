# Logwarden

Cross-platform EVTX threat-hunting desktop app (Chainsaw-style workflow with a GUI).

**Stack:** Tauri 2 · Rust · React · TypeScript · SQLite · Sigma

> Product name is a placeholder — rename via `lw_core::APP_NAME` / `src/lib/constants.ts`.

## Status

Milestone **M1** (headless ingest / normalize / store) complete. See `docs/milestones/`.

## Develop

```bash
npm install
just ci          # fmt, clippy, tests, deny, tsc, eslint, vitest
just fixtures    # optional: fetch external EVTX sample sets
cargo run -p lw-cli -- release 2>/dev/null || cargo build -p lw-cli --release
./target/release/lw ingest path/to/logs --case /tmp/demo.lwcase --bench
./target/release/lw stats --case /tmp/demo.lwcase
just dev         # tauri GUI shell (M3+)
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
