#!/usr/bin/env bash
# Fetch external EVTX sample datasets into tests/fixtures/ext/ (gitignored).
# Pins are recorded in tests/fixtures/PINS.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT="$ROOT/tests/fixtures/ext"
PINS="$ROOT/tests/fixtures/PINS"
mkdir -p "$EXT"

pin() {
  local name="$1" url="$2" commit="$3"
  local dest="$EXT/$name"
  if [[ -d "$dest/.git" ]]; then
    echo "Updating $name…"
    git -C "$dest" fetch --depth 1 origin "$commit"
    git -C "$dest" checkout --force "$commit"
  else
    echo "Cloning $name @ $commit…"
    rm -rf "$dest"
    git clone --filter=blob:none --no-checkout "$url" "$dest"
    git -C "$dest" fetch --depth 1 origin "$commit"
    git -C "$dest" checkout --force "$commit"
  fi
  echo "$name $commit" >>"$PINS.tmp"
}

: >"$PINS.tmp"

# Commits checked Oct 2026 — update PINS when intentionally bumping.
pin "EVTX-ATTACK-SAMPLES" "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git" "master"
pin "hayabusa-sample-evtx" "https://github.com/Yamato-Security/hayabusa-sample-evtx.git" "main"
pin "EVTX-to-MITRE-Attack" "https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack.git" "master"

mv "$PINS.tmp" "$PINS"
echo "Fixtures ready under $EXT"
echo "Set LW_FIXTURES=1 to enable ignored fixture tests."
