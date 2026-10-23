#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "[*] Setting up bugsBounty Python environment & verifying .bin/ arsenal..."
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -e ".[dev]"

find "$ROOT/.bin" -maxdepth 1 -type f ! -name '_*' -exec chmod +x {} + 2>/dev/null || true
./.venv/bin/bughunter tools
echo "[+] Ready! Try: ./.venv/bin/bughunter warroom --lab   or   ./.venv/bin/bughunter ui --lab"
