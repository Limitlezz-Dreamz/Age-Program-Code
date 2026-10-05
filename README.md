# Logwarden

Cross-platform offline EVTX threat-hunting desktop app (Chainsaw-style workflow with a GUI).

**Stack:** Tauri 2 · Rust · React · TypeScript · SQLite · Sigma

**Download:** [v0.1.0 releases](https://github.com/Limitlezz-Dreamz/Age-Program-Code/releases/tag/v0.1.0)

## Status

Milestones **M0–M7** shipped. Post-release polish (updater, signing hooks, MITRE map) is in progress on `main` via PRs. See `docs/milestones/` and `docs/packaging.md`.

## Develop

```bash
npm install
just ci          # fmt, clippy, tests, deny, tsc, eslint, vitest, bundle-check
just fixtures    # optional: fetch external EVTX sample sets
just dev         # Tauri GUI
just bundle      # platform installers
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

- `CHANGELOG.md`
- `docs/milestones/M0.md` … `M7.md`
- `docs/packaging.md` — installers, signing, updater keys
- `docs/perf.md`
