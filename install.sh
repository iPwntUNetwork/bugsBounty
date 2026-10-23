#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

OS="$(uname -s)"
ARCH="$(uname -m)"

echo "=================================================================="
echo "  bugsBounty Installer — OS: ${OS} (${ARCH})"
echo "=================================================================="

# 1. Check baseline system prerequisites
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Missing 'python3' (>= 3.10 required)."
    echo "    Ubuntu/Debian/Kali: sudo apt update && sudo apt install -y python3 python3-venv python3-pip perl xz-utils"
    echo "    macOS (Homebrew):   brew install python@3.11 xz"
    exit 1
fi

if ! python3 -c 'import sys, venv; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    echo "[!] Python >= 3.10 with the 'venv' module is required."
    echo "    Ubuntu/Debian/Kali: sudo apt update && sudo apt install -y python3 python3-venv"
    exit 1
fi

if ! command -v perl >/dev/null 2>&1; then
    echo "[!] Warning: 'perl' not found — Nikto requires perl (sudo apt install -y perl)."
fi

# 2. Create Python virtual environment & install bugsBounty + Python dependencies
echo "[1/4] Creating Python virtual environment (.venv) & installing packages..."
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -e ".[dev]"

# 3. Unpack bundled pure-Python security tools (sqlmap, arjun, paramspider, wafw00f)
echo "[2/4] Unpacking bundled Python offensive tools into .cache/pytools..."
mkdir -p "$ROOT/.cache/pytools"
./.venv/bin/python -m zipfile -e "$ROOT/.bin/_pytools.zip" "$ROOT/.cache/pytools"
touch "$ROOT/.cache/pytools/.ready"

# 4. Unpack pre-compiled Linux x86_64 Go binaries OR native-compile on macOS / ARM64
mkdir -p "$ROOT/.cache/gobins"
if [ "$OS" = "Linux" ] && [ "$ARCH" = "x86_64" ]; then
    echo "[3/4] Unpacking pre-compiled Linux x86_64 Go binaries into .cache/gobins..."
    cat "$ROOT"/.bin/_gobins.txz.* | tar -xJ -C "$ROOT/.cache/gobins"
    chmod 0755 "$ROOT/.cache/gobins"/*
else
    echo "[3/4] Detected ${OS}/${ARCH} (bundled .bin/_gobins.txz.* binaries are Linux/x86_64)."
    if command -v go >/dev/null 2>&1; then
        echo "      Found Go toolchain ($(go version)) — compiling native binaries into .cache/gobins..."
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/projectdiscovery/katana/cmd/katana@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/hahwul/dalfox/v2@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/OJ/gobuster/v3@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/ffuf/ffuf/v2@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/tomnomnom/waybackurls@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/lc/gau/v2/cmd/gau@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/tomnomnom/assetfinder@latest
        GOBIN="$ROOT/.cache/gobins" go install -v github.com/hakluke/hakrawler@latest
    else
        echo "      [!] Note: Install Go ('brew install go' or 'sudo apt install golang-go') and re-run ./install.sh to compile the 12 native Go binaries for ${OS}/${ARCH}."
    fi
fi

find "$ROOT/.bin" -maxdepth 1 -type f ! -name '_*' -exec chmod +x {} + 2>/dev/null || true

# 5. Verify all 22 tools report READY
echo "[4/4] Verifying all 22 .bin/ & built-in offensive tools..."
./.venv/bin/bughunter tools

echo ""
echo "=================================================================="
echo "  [+] Installation Complete!"
echo "  • Interactive Terminal Crew + Safe Lab: ./.venv/bin/bughunter warroom --lab"
echo "  • Browser War-Room UI + Safe Lab:       ./.venv/bin/bughunter ui --port 8787 --lab"
echo "  • Full 6-Agent Autopilot against URL:   ./.venv/bin/bughunter autopilot https://target.tld"
echo "=================================================================="
