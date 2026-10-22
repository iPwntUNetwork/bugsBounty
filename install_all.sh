#!/usr/bin/env bash
# Interactive installer for the Bug Bounty Toolkit (bountytime)
# Installs all dependencies, Go modules, external tools, and configures Groq.
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo -e "${CYAN}"
echo "  ____  _   _ ____  _   _ _____ ___  ____  "
echo " | __ )| | | |  _ \\| | | |_   _/ _ \\|  _ \\ "
echo " |  _ \\| | | | |_) | | | | | || | | | |_) |"
echo " | |_) | |_| |  _ <| |_| | | || |_| |  _ < "
echo " |____/ \\___/|_| \\_\\\\___/  |_| \\___/|_| \\_\\"
echo "       Bug Bounty Toolkit — Interactive Installer"
echo -e "${NC}"

# ---------- OS detection ----------
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS="unknown"
fi
info "Detected OS: $OS"

# ---------- System packages ----------
info "Updating package lists..."
sudo apt update -y

info "Installing base system packages..."
sudo apt install -y \
    python3 python3-pip python3-venv python3-dev \
    git zip unzip curl wget build-essential \
    libssl-dev libffi-dev zlib1g-dev \
    golang-go \
    nmap masscan dnsrecon whois \
    nikto gobuster dirb wfuzz 2>/dev/null || true

ok "Base packages installed."

# ---------- Go setup ----------
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
mkdir -p "$GOPATH/bin"
if ! grep -q 'GOPATH' ~/.bashrc 2>/dev/null; then
    echo 'export GOPATH="$HOME/go"' >> ~/.bashrc
    echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
fi
ok "Go environment configured."

# ---------- Go modules ----------
info "Installing Go-based recon/scanning tools..."
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/OJ/gobuster/v3@latest"
)
for tool in "${GO_TOOLS[@]}"; do
    name=$(basename "$tool" | cut -d@ -f1)
    info "  Installing $name..."
    go install "$tool" 2>/dev/null && ok "    $name installed" || warn "    $name failed (continuing)"
done

# ---------- Python venv ----------
info "Creating Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel

info "Installing Python dependencies..."
pip install \
    requests beautifulsoup4 lxml typer rich pydantic \
    pyyaml dnspython mmh3 httpx aiohttp jinja2

ok "Python dependencies installed."

# ---------- Nuclei templates ----------
if command -v nuclei &>/dev/null; then
    info "Updating Nuclei templates..."
    nuclei -update-templates 2>/dev/null || true
    ok "Nuclei templates updated."
fi

# ---------- SecLists / wordlists ----------
if [ ! -d /usr/share/seclists ]; then
    info "Installing SecLists wordlists..."
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null || warn "SecLists clone failed (optional)"
else
    ok "SecLists already present."
fi

# ---------- Install bugsBounty command ----------
info "Installing bugsBounty CLI..."
BIN="${HOME}/.local/bin"
mkdir -p "$BIN"
cat > "$BIN/bugsBounty" <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$DIR:\$PYTHONPATH"
source "$DIR/.venv/bin/activate" 2>/dev/null
exec python3 "$DIR/bugsBounty.py" "\$@"
EOF
chmod +x "$BIN/bugsBounty"
if ! grep -q '.local/bin' ~/.bashrc 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
fi
ok "bugsBounty command installed."

# ---------- Groq API key ----------
echo ""
echo -e "${CYAN}=== Groq API Configuration ===${NC}"
echo "Get your free API key at: https://console.groq.com/keys"
echo ""
read -p "Enter your Groq API key (or press Enter to skip): " GROQ_KEY

# ---------- .env file ----------
cat > "$DIR/.env" <<EOF
# Bug Bounty Toolkit Configuration
GROQ_API_KEY=${GROQ_KEY}
GROQ_BASE_URL=https://api.groq.com/openai/v1
BUGHUNTER_MODEL=llama-3.3-70b-versatile
BUGHUNTER_HOME=$HOME/.bugsBounty

# Authenticated scanning (optional)
# BUGHUNTER_USERNAME=
# BUGHUNTER_PASSWORD=
# BUGHUNTER_LOGIN_URL=

# OSINT (optional)
# HUNTER_API_KEY=

# Proxy (optional)
# BUGHUNTER_PROXY=
EOF

if [ -n "$GROQ_KEY" ]; then
    ok "Groq API key saved to .env"
else
    warn "No API key provided. Deterministic mode will be used (no LLM)."
fi

# ---------- Validate ----------
echo ""
info "Validating installation..."
source .venv/bin/activate
python3 -c "import requests, bs4, lxml, typer, rich, yaml; print('Python deps OK')" && ok "Python OK"
command -v bugsBounty &>/dev/null && ok "bugsBounty CLI OK" || warn "bugsBounty not in PATH (restart shell or source ~/.bashrc)"
command -v nuclei &>/dev/null && ok "nuclei OK" || warn "nuclei not found"
command -v subfinder &>/dev/null && ok "subfinder OK" || warn "subfinder not found"
command -v httpx &>/dev/null && ok "httpx OK" || warn "httpx not found"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "  Restart your shell or run: source ~/.bashrc"
echo "  Then: bugsBounty setup"
echo "  Then: bugsBounty autopilot target.com"
echo ""
echo "  For authenticated scans:"
echo "  bugsBounty autopilot target.com --username USER --password PASS"
echo ""
