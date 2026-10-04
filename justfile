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
ci: fmt-check clippy test-rust deny tsc eslint vitest bundle-check
    @echo "CI checks passed"

# Quick ingest benchmark against local fixtures
bench:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p lw-cli --release
    CASE=$(mktemp -d)/bench.lwcase
    ./target/release/lw ingest tests/fixtures/cc0/sample.evtx --case "$CASE" --no-hash --no-fts --bench
    echo "Case: $CASE"

# Fetch external EVTX fixtures (gitignored)
fixtures:
    bash scripts/fetch-fixtures.sh

# Production bundle (requires platform-specific tooling)
bundle:
    npm run tauri build

# Validate packaging config + resource layout without a full installer build
bundle-check:
    #!/usr/bin/env bash
    set -euo pipefail
    test -f src-tauri/tauri.conf.json
    test -d resources/builtin-rules
    test -d resources/mappings
    test -d resources/mitre
    test -f resources/event-descriptions.yml
    python3 - <<'PY'
    import json
    from pathlib import Path
    root = Path("src-tauri")
    conf = json.loads((root / "tauri.conf.json").read_text())
    assert conf["identifier"] == "io.logwarden.app"
    assert conf["bundle"]["active"] is True
    resources = conf["bundle"]["resources"]
    assert isinstance(resources, dict) and resources
    for src, dest in resources.items():
        path = (root / src).resolve()
        assert path.exists(), f"missing resource {src} -> {path}"
        assert str(dest).startswith("resources/"), dest
    assert conf["bundle"]["macOS"].get("signingIdentity") == "-"
    print("bundle-check ok:", len(resources), "resource mappings")
    PY
    cargo test -p lw-core --lib
    cargo test -p lw-rules loads_builtins
