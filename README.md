# Logwarden

Cross-platform EVTX threat-hunting desktop app (Chainsaw-style workflow with a GUI).

**Stack:** Tauri 2 · Rust · React · TypeScript · SQLite · Sigma

> Product name is a placeholder — rename via `lw_core::APP_NAME` / `src/lib/constants.ts`.

## Status

Milestone **M6** (Rules manager + exports) complete. See `docs/milestones/`.

## Develop

```bash
npm install
just ci          # fmt, clippy, tests, deny, tsc, eslint, vitest
just fixtures    # optional: fetch external EVTX sample sets
just dev         # Tauri GUI: create case, add EVTX, start/cancel analysis
cargo build -p lw-cli --release
./target/release/lw ingest path/to/logs --case /tmp/demo.lwcase --bench
./target/release/lw hunt --case /tmp/demo.lwcase --profile all
./target/release/lw detections --case /tmp/demo.lwcase
./target/release/lw export --case /tmp/demo.lwcase --format csv -o /tmp/dets.csv
```

## License hygiene

- App code: MIT OR Apache-2.0
- No GPL / AGPL / LGPL dependencies (`cargo deny` + npm license check)
- Sigma rule packs are downloaded at runtime (DRL 1.1); author attribution required on every match
- Do **not** copy code or mapping files from Chainsaw, Hayabusa, Velociraptor, DeepBlueCLI, APT-Hunter, or Zircolite

## Docs

- Build spec and research report (project planning docs)
- `CHANGELOG.md`
- `docs/milestones/M0.md` … `M6.md`
