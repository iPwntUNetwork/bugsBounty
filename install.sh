#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "[*] Setting up bugsBounty Python environment & verifying .bin/ arsenal..."
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -e ".[dev]"

chmod +x "$ROOT"/.bin/* 2>/dev/null || true
./.venv/bin/python bughunter.py tools
echo "[+] Ready! Run: ./.venv/bin/python bughunter.py autopilot <target>"
