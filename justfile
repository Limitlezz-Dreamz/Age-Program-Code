# Logwarden task runner
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

# Start the Tauri + Vite dev app
dev:
    npm run tauri dev

# Format Rust sources
fmt:
    cargo fmt --all

# Check formatting without writing
fmt-check:
    cargo fmt --all -- --check

# Clippy with warnings as errors
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Rust unit/integration tests
test-rust:
    cargo test --workspace

# Frontend typecheck
tsc:
    npx tsc --noEmit

# ESLint
eslint:
    npx eslint .

# Vitest unit tests
vitest:
    npx vitest run

# License checks (Rust + npm)
deny:
    cargo deny check licenses
    # OFL-1.1: self-hosted UI fonts (e.g. IBM Plex). Not used for Rust crates.
    # excludePrivatePackages: skip the app root package itself (we own it).
    npx license-checker-rseidelsohn --production --excludePrivatePackages --onlyAllow 'MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC;0BSD;CC0-1.0;Unlicense;BlueOak-1.0.0;Python-2.0;OFL-1.1'

# Full CI gate (M0+)
ci: fmt-check clippy test-rust deny tsc eslint vitest
    @echo "CI checks passed"

# Placeholder for criterion benches (M1+)
bench:
    @echo "No benches yet (M1). Run: cargo bench -p lw-ingest"

# Fetch external EVTX fixtures (gitignored)
fixtures:
    bash scripts/fetch-fixtures.sh

# Production bundle (requires platform-specific tooling)
bundle:
    npm run tauri build
