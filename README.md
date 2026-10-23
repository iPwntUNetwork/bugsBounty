# bugsBounty — Autonomous 6-Agent Offensive Security & Bug Bounty Framework

`bugsBounty` wires **19 self-contained `.bin/` security binaries** + **3 built-in live exploitation/OOB engines** (`BeefServer` XSS Hook C2, `OOBManager` HTTP/Interactsh callback server, and declarative YAML `Nuclei` engine) into a strict **6-agent war-room workflow** supporting **interactive crew chat (`warroom` / `ui`)**, a **built-in vulnerable target lab (`lab`)**, **Groq**, and **local Ollama** models (plus 100% deterministic execution with zero API keys required).

---

## Full Installation Guide (Step-by-Step from Scratch)

Why is installation so short on Linux? Because **all 19 external security tools** (`subfinder`, `katana`, `dalfox`, `interactsh-client`, `gobuster`, `httpx`, `ffuf`, `dnsx`, `waybackurls`, `gau`, `assetfinder`, `hakrawler`, `sqlmap`, `arjun`, `paramspider`, `wafw00f`, `nikto`, `commix`, `nuclei`) are **already pre-bundled inside `.bin/` in this repository**!

### Step 1 — System Prerequisites
- **Ubuntu / Debian / Kali / Parrot / WSL2 (`x86_64`)**:
  ```bash
  sudo apt update && sudo apt install -y git python3 python3-venv python3-pip perl xz-utils
  ```
  *(No Go compiler needed on Linux `x86_64` — pre-compiled binaries are unpacked directly from `.bin/_gobins.txz.*`.)*
- **macOS (Apple Silicon / Intel) or ARM64 Linux**:
  ```bash
  # macOS (Homebrew):
  brew install git python@3.11 xz go
  # ARM64 Debian/Ubuntu:
  sudo apt update && sudo apt install -y git python3 python3-venv python3-pip perl xz-utils golang-go
  ```
  *(`install.sh` automatically detects non-`Linux/x86_64` hosts and uses `go install` to compile native binaries straight into `.cache/gobins/`.)*

### Step 2 — Clone & Run the One-Command Installer
```bash
git clone https://github.com/iPwntUNetwork/bugsBounty.git
cd bugsBounty
./install.sh
```
`./install.sh` automatically:
1. Creates `.venv/` and installs all Python dependencies + CLI entrypoints (`.venv/bin/bughunter`, `.venv/bin/bugsbounty`, `.venv/bin/crew`),
2. Unpacks `sqlmap`, `arjun`, `paramspider`, and `wafw00f` into `.cache/pytools/`,
3. Unpacks all 12 pre-compiled Go tools into `.cache/gobins/` (or compiles native binaries on macOS/ARM64),
4. Runs `./.venv/bin/bughunter tools` to verify all **22 / 22** tools report **`READY`**.

### Step 3 — (Optional) Connect an LLM Provider (`Ollama` or `Groq`)
`bugsBounty` runs **out of the box with zero API keys** (all scanning, WAF bypasses, `SWITCH` escalations, and `RAZOR` critic checks execute deterministically). If you also want live LLM reasoning & tool-calling banter from the crew:
- **Local Ollama (100% free & offline)**:
  ```bash
  curl -fsSL https://ollama.com/install.sh | sh
  ollama pull llama3.1:8b
  ```
- **Or Groq Cloud API**:
  ```bash
  export GROQ_API_KEY="gsk_your_key_here"
  ```

---

## 1. Running Against a Target (or Built-in Vulnerable Lab)

### Option A — Spin Up the Built-in Safe Target Lab (`VulnCorp Portal`)
Want to see the whole crew rip through a live Cloudflare-like WAF, SQLite SQLi, reflected XSS + BeEF hook, SSRF callback, OS command injection, `/admin` 403 bypass, exposed `/.env`, AND watch `RAZOR` bin 6 false-positive traps?

```bash
# Terminal 1: Start local vulnerable target lab on http://127.0.0.1:8080
./.venv/bin/bughunter lab --port 8080

# Terminal 2: Unleash all 6 agents end-to-end against it
./.venv/bin/bughunter autopilot http://127.0.0.1:8080
```

### Option B — Run Against Any Authorized Target
```bash
# Full 6-agent pipeline (GHOST -> BLITZ -> SWITCH -> RAZOR -> CHAINSAW -> FIXER)
./.venv/bin/bughunter autopilot https://authorized-target.tld -o report.md

# With a local Ollama model powering crew reasoning & tool loops
./.venv/bin/bughunter --provider ollama --ollama-model llama3.1:8b autopilot https://authorized-target.tld

# With Groq API key
GROQ_API_KEY="gsk_..." ./.venv/bin/bughunter --provider groq autopilot https://authorized-target.tld

# Run individual phases or individual scanners step-by-step
./.venv/bin/bughunter recon https://authorized-target.tld
./.venv/bin/bughunter hunt https://authorized-target.tld
./.venv/bin/bughunter escalate https://authorized-target.tld
./.venv/bin/bughunter critic https://authorized-target.tld
./.venv/bin/bughunter scan sqli "https://authorized-target.tld/item?id=1"
```

---

## 2. Calling & Interacting Directly With the Crew

You have **three ways** to call and interact live with `GHOST`, `BLITZ`, `SWITCH`, `RAZOR`, `CHAINSAW`, and `FIXER`:

### Way 1 — Interactive Terminal War-Room REPL (`#basement-ops`)
```bash
# Drop straight into the basement war-room (with --lab to auto-boot a local target!)
./.venv/bin/bughunter warroom --lab

# Or attach to a specific target + local Ollama model:
./.venv/bin/bughunter --provider ollama --ollama-model llama3.1:8b warroom http://127.0.0.1:8080
# (Shortcut alias also installed in .venv/bin:)
./.venv/bin/crew
```
Inside `YOU(...)>`, talk naturally, `@mention` specific hackers, or run slash commands:
- `@ghost map all endpoints and hidden parameters`
- `@blitz crack the WAF and hunt for sqli and xss`
- `@switch run sqlmap, dalfox + beef hook, and oob callbacks on everything`
- `@razor audit every claim — brown-eye anything fake`
- `@chainsaw build P1 attack chains` / `@fixer write the bounty report`
- Slash commands: `/lab`, `/target <url>`, `/autopilot`, `/recon`, `/hunt`, `/escalate`, `/critic`, `/chains`, `/report`, `/status`, `/quit`

### Way 2 — Live Web War-Room Console (`ui`)
```bash
./.venv/bin/bughunter ui --port 8787 --lab
# Open http://127.0.0.1:8787 in your browser!
```

### Way 3 — Single-Shot CLI Call (`crew -m`)
```bash
./.venv/bin/bughunter crew --to ghost -t http://127.0.0.1:8080 -m "Recon this box and hand off to BLITZ"
```

---

## The 20-Year War-Room Crew (`agents/crew.py`)

| Handle | Role | Responsibility |
|---|---|---|
| **GHOST** | Recon Cartographer | `subfinder`, `assetfinder`, `dnsx`, `httpx`, `wafw00f`, `katana`, `hakrawler`, `arjun`, `ffuf`, `gobuster`, `gau`, `waybackurls`, `paramspider` |
| **BLITZ** | Active Vuln Hunter | Multi-threaded scanning with `PAYLOAD_MUTEX`, 20-vendor WAF detection, 24 polymorphic tamper scripts & User-Agent rotation |
| **SWITCH** | Escalation Specialist | Suspected SQLi → `.bin/sqlmap`; XSS → `.bin/dalfox` + live **BeEF Hook C2** (`hook.js`); SSRF → `Interactsh`/OOB callback; CMDi → `.bin/commix` + OOB |
| **RAZOR** | **Deterministic Critic** | **Zero-LLM adversarial verifier**. Enforces `SeparationOfDutiesError` (detector may NEVER self-certify). Cheers valid exploits; dishes out Aussie brown-eye roasts on false positives! |
| **CHAINSAW** | Chain Architect | Stitches RAZOR-certified findings into P1 multi-step attack chains |
| **FIXER** | Bounty Closer | CVSS v3.1 scoring, reproducible `curl` + Python PoCs, war-room transcript & Markdown report |
