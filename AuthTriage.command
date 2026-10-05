#!/bin/bash
# Double-click in Finder on macOS. Lab / public sample logs only.
set -euo pipefail
cd "$(dirname "$0")"

echo "LAB / PUBLIC DATA ONLY — never use employer or production logs"
echo "AuthTriage on macOS — no Linux VM needed."

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is missing. Install from https://www.python.org/downloads/macos/ or: brew install python"
  exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Need Python 3.11+. This python3 is: $(python3 --version 2>&1)"
  echo "Install a newer one: brew install python"
  exit 1
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python3 -m pip install -q -e .

mkdir -p out
python3 -m authtriage testdata/macos_sshd_snippet.log -o out
echo
echo "Wrote out/report.html  (also report.md, iocs.csv, report.json)"
if command -v open >/dev/null 2>&1; then
  open out/report.html
fi
echo "Done. You can drop another lab .log on Terminal later:"
echo "  python3 -m authtriage /path/to/lab.log -o out && open out/report.html"
