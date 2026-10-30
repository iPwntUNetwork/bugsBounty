# bugsBounty — Autonomous Single-Agent Offensive Security & Bug Bounty Framework

> **22 Self-Contained `.bin/` & Live Exploitation Tools · 78 Vulnerability Scanners · 20-Vendor WAF Evasion Mutex · 100% Deterministic Verification · Six-Stage Single Agent · ChatGPT-Style `#basement-ops` Console (CLI + Web UI) · xAI Grok / Groq Cloud / OpenAI / Local Ollama / Offline Mode**

`bugsBounty` (`v2.2.0`) is an end-to-end offensive security, bug bounty automation, red-team, and validation framework driven by **one agent** (`AGENT`) that runs a six-stage workflow — recon, hunt, escalate, verify, chains, report — over a **pre-bundled `.bin/` native binary arsenal**, **automated heavy-tool escalation**, **thread-safe polymorphic WAF evasion**, and an **adversarial zero-LLM verification stage** that actively tries to **disprove** every finding before a single bug enters your report.

---

## Documentation Index

| Document | What It Covers |
|---|---|
| **[`README.md`](./README.md)** *(this file)* | Architecture overview, full installation (`Linux x86_64`, `Kali/WSL2`, `macOS/ARM64`), `Grok` / `Groq` / `OpenAI` / `Ollama` setup, target scanning, the interactive agent console, 22-tool matrix, and repository map |
| **[`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)** | Deep-dive architecture: the single-agent six-stage pipeline, `SeparationOfDutiesError` invariant, the deterministic falsification rules, `PayloadMutexCoordinator`, all 20 WAF signatures & 24 tamper scripts, `BeefServer` C2 & `OOBManager` callbacks, and data schemas |
| **[`docs/CLI_AND_WARROOM_GUIDE.md`](./docs/CLI_AND_WARROOM_GUIDE.md)** | Complete operator reference: all global options, all 19 CLI commands, `#basement-ops` REPL slash commands, Web console HTTP API, `VulnCorp` Target Lab endpoints & false-positive traps, env vars, and troubleshooting |
| **[`docs/SCANNERS_AND_MODULES_REFERENCE.md`](./docs/SCANNERS_AND_MODULES_REFERENCE.md)** | Complete catalog of all **22 `.bin/` & built-in tools**, all **78 `scan/` modules**, Cloud / CI-CD / OSINT / Fuzzing / Post-Exploitation / Platform Report Templates, custom plugin authoring (`tools/plugins/`), Python SDK usage, and the live E2E suite |

---

## High-Level Architecture

```text
                       ┌───────────────────────────────────────────────────────────┐
                       │         Operator Control Surfaces (#basement-ops)         │
                       │  • CLI One-Shot:  bughunter autopilot / recon / scan ...  │
                       │  • Terminal REPL: bughunter warroom --lab  (/lab, /key)   │
                       │  • Browser UI:    bughunter ui --port 8787 --lab          │
                       └─────────────────────────────┬─────────────────────────────┘
                                                     │
                   ┌─────────────────────────────────▼─────────────────────────────────┐
                   │     AI Brain (Optional): xAI Grok · Groq · OpenAI · Local Ollama  │
                   │       (100% deterministic fallback when run with zero API keys)   │
                   └─────────────────────────────────┬─────────────────────────────────┘
                                                     │  AGENT (one agent, one transcript)
     ┌───────────────┬───────────────┬───────────────┼───────────────┬───────────────┐
     ▼               ▼               ▼               ▼               ▼               ▼
┌─────────┐    ┌──────────┐    ┌──────────┐    ┌───────────┐   ┌───────────┐   ┌────────────┐
│1. RECON │───▶│ 2. HUNT  │───▶│3.ESCALATE│───▶│ 4. VERIFY │──▶│ 5. CHAINS │──▶│ 6. REPORT  │──▶ ADVISORY
│ Surface │    │ Scanners │    │  Heavy   │    │Deterministic│ │ Correlate │   │ CVSS + PoCs│   + PoCs.md
│  map    │    │ + WAF    │    │  tools   │    │ falsifier │   │  chains   │   │ + advisory │
└────┬────┘    └────┬─────┘    └────┬─────┘    └─────┬─────┘   └─────┬─────┘   └────┬─────┘
     │              │               │                │               │              │
     ▼              ▼               ▼                ▼               ▼              ▼
• subfinder    • 78 Scanners   • SQLi -> sqlmap • ZERO LLM!    • Chains exposed • CVSS v3.1
• assetfinder  • PAYLOAD_MUTEX • XSS  -> dalfox • Rejects self-  secrets + 403  • curl + Python
• dnsx/httpx   • 20 WAF sigs     + BeEF hook.js   certification  bypasses + XSS   repro scripts
• wafw00f      • 24 Tampers    • SSRF -> OOB /  • Replays benign BeEF hooks     • H1 / Bugcrowd
• katana/arjun • UA burn/rot     Interactsh     controls &     • Elevates       / Intigriti /
• ffuf/gobuster• YAML Nuclei   • CMDi -> commix bins false       chained impact   Immunefi
• gau/wayback  • Nikto           + OOB canary     positives      to P1 Critical   templates
```

### Core Engineering Guarantees

1. **Self-Contained `.bin/` Offensive Arsenal (`22 / 22 READY`)**: Ships **19 pre-bundled security tools** inside `.bin/` plus **3 built-in exploitation & callback servers** (`BeefServer` XSS Hook C2, `OOBManager` HTTP + `interactsh-client` listener, and declarative YAML `Nuclei` engine), automatically prepended ahead of system `$PATH`.
2. **Thread-Safe WAF Evasion (`PAYLOAD_MUTEX`)**: Detects **20 commercial WAF vendors** (`Cloudflare`, `AWS WAF`, `Akamai`, `Imperva`, `ModSecurity`, `F5 BIG-IP`, `DataDome`, `PerimeterX`, `FortiWeb`, etc.), burns blocked `User-Agent` identities on `429`/`403`, and coordinates **24 polymorphic tamper scripts** across worker threads without re-sending burned payloads.
3. **Automated Heavy-Weapon Escalation (stage 3)**: Suspected leads never stop at regex matches — `SQLi` automatically hands off to `.bin/sqlmap` (with vendor-matched `--tamper`), `XSS` hands off to `.bin/dalfox` + stages a live **`BeefServer` (`hook.js`)** session, `SSRF` verifies real outbound callbacks against `OOBManager` / `.bin/interactsh-client`, `CMDi` escalates to `.bin/commix` + OOB beacons, and `401`/`403` gates trigger `bypass_403` + `.bin/arjun`.
4. **100% Deterministic Verification (stage 4)**: The verification stage makes **zero LLM calls**. It enforces `SeparationOfDutiesError` (a finding's detector is **architecturally forbidden** from certifying it, even though both run inside the same agent), then actively tries to break the claim using benign baseline controls, reflection-parity diffs, DBMS proof verification, live OOB callback logs, and algebra checks — so unproven claims are binned instead of shipped.

---

## Step-by-Step Installation

### 1. System Prerequisites

#### Ubuntu / Debian / Kali / Parrot / WSL2 (`x86_64`)
```bash
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip perl xz-utils
```
*(No Go compiler is required on `Linux x86_64` — pre-compiled native binaries unpack directly from `.bin/_gobins.txz.*`.)*

#### macOS (Apple Silicon / Intel) or ARM64 Linux
```bash
# macOS (Homebrew):
brew install git python@3.11 xz go

# ARM64 Ubuntu / Debian:
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip perl xz-utils golang-go
```
*(`install.sh` automatically detects non-`Linux/x86_64` hosts and compiles all 12 Go tools natively into `.cache/gobins/`.)*

### 2. Clone & Run `./install.sh`

```bash
git clone https://github.com/iPwntUNetwork/bugsBounty.git
cd bugsBounty
./install.sh
```

What `./install.sh` executes automatically:
1. Creates `.venv/` (`Python >= 3.10`) and installs all package dependencies plus three CLI entrypoints: `.venv/bin/bughunter`, `.venv/bin/bugsbounty`, and `.venv/bin/crew`.
2. Extracts bundled Python tools (`sqlmap`, `arjun`, `paramspider`, `wafw00f`) into `.cache/pytools/`.
3. Extracts pre-compiled Go binaries into `.cache/gobins/` *(or builds native Go binaries on macOS/ARM64)*.
4. Runs `./.venv/bin/bughunter tools` and confirms all **22 / 22** tools report **`READY`**.

---

## Connecting Your Groq API Key (`https://api.groq.com/openai/v1` · `qwen/qwen3.8-27b`) or Local `Ollama`

`bugsBounty` works **out of the box with zero API keys** in deterministic mode, and defaults to **Groq Cloud (`https://api.groq.com/openai/v1`)** with default model **`qwen/qwen3.8-27b`** (plus support for **Local Ollama**, **OpenAI**, and **xAI**):

| Provider | Key Prefix / Source | Default Endpoint | Default Model (`--model` override supported) |
|---|---|---|---|
| **Groq Cloud *(Default)*** | `gsk_...` (`console.groq.com`) | `https://api.groq.com/openai/v1` | **`qwen/qwen3.8-27b`** |
| **Local Ollama** | Free / Offline (`ollama.com`) | `http://localhost:11434` | `llama3.1:8b` *(or first installed local model)* |
| **OpenAI** | `sk-...` (`platform.openai.com`) | `https://api.openai.com/v1` | `gpt-4o-mini` |
| **xAI** | `xai-...` (`console.x.ai`) | `https://api.x.ai/v1` | `grok-3` |

### 4 Ways to Activate Your Groq API Key

```bash
# 1. Save ONCE permanently (~/.bugsBounty/config.json, chmod 0600 — outside Git) + live ping test:
./.venv/bin/bughunter auth YOUR_GROQ_API_KEY --test
# Uses endpoint https://api.groq.com/openai/v1 and default model qwen/qwen3.8-27b automatically!

# 2. Pass inline on any single command (-k / --api-key):
./.venv/bin/bughunter --api-key YOUR_GROQ_API_KEY warroom --lab
./.venv/bin/bughunter --api-key YOUR_GROQ_API_KEY autopilot https://authorized-target.tld

# 3. Export via environment variable or local .env file (gitignored):
export GROQ_API_KEY="gsk_..."
export GROQ_MODEL="qwen/qwen3.8-27b"   # already the built-in default!

# 4. Run 100% locally offline with Ollama:
ollama pull llama3.1:8b
./.venv/bin/bughunter --provider ollama --ollama-model llama3.1:8b warroom --lab
```
> You can also hot-swap keys mid-session inside `bughunter warroom` via `/key YOUR_GROQ_API_KEY` (automatically masked in transcripts) or inside `bughunter ui` via the **`API Key / LLM`** button in the top bar.

---

## Quickstart Workflows

### Workflow 1 — Safe Local End-to-End Demo (`VulnCorp Target Lab`)
Spin up the built-in vulnerable target application (`Cloudflare` WAF simulation + real SQLite SQLi, reflected XSS, SSRF, OS command injection, path traversal, SSTI, `/admin` 403 bypass, exposed `/.env`, **plus 6 false-positive traps** designed to test the verifier):

```bash
# Option A: Interactive Terminal War-Room + Auto-Started Lab
./.venv/bin/bughunter warroom --lab

# Option B: Interactive Browser Console (http://127.0.0.1:8787) + Auto-Started Lab
./.venv/bin/bughunter ui --port 8787 --lab

# Option C: Standalone Target Server + Full Autopilot CLI
./.venv/bin/bughunter lab --port 8080                  # Terminal 1
./.venv/bin/bughunter autopilot http://127.0.0.1:8080  # Terminal 2
```

### Workflow 2 — Scanning an Authorized Bug Bounty Target

```bash
# Full autonomous run -> writes verified Markdown report + curl/Python PoCs:
./.venv/bin/bughunter autopilot https://authorized-target.tld -o target_report.md

# Or execute each stage step-by-step with full control:
./.venv/bin/bughunter recon https://authorized-target.tld
./.venv/bin/bughunter hunt https://authorized-target.tld
./.venv/bin/bughunter escalate https://authorized-target.tld
./.venv/bin/bughunter critic https://authorized-target.tld
./.venv/bin/bughunter chains https://authorized-target.tld
./.venv/bin/bughunter poc https://authorized-target.tld
./.venv/bin/bughunter report https://authorized-target.tld -o target_report.md

# Run any of the 78 targeted scanners directly:
./.venv/bin/bughunter scan sqli "https://authorized-target.tld/product?id=1"
./.venv/bin/bughunter scan jwt_deep "https://authorized-target.tld/api/me"
./.venv/bin/bughunter scan graphql_deep "https://authorized-target.tld/graphql"
```

### Workflow 3 — Talking Directly to the Agent

```bash
# Terminal REPL (#basement-ops):
./.venv/bin/bughunter warroom --lab
# Inside the REPL:
#   /target site.com      -> set the target
#   /recon                -> stage 1: map everything about the target
#   /hunt                 -> stage 2: look for bugs
#   /auto                 -> recon + hunt, then chase down every bug it finds
#   /verify               -> deterministic verification, bins false positives
#   /chains               -> build kill chains
#   /report               -> write the final CVSS v3.1 advisory
#   /status               -> live engagement summary

# Single-shot command from shell scripts / CI pipelines:
./.venv/bin/bughunter agent --lab -m "Recon this box, then hunt and verify it"

# Browser Web Command Center (#basement-ops — default Basic Auth -> admin:bugsBounty):
./.venv/bin/bughunter ui --host 0.0.0.0 --port 8787 --lab
#   • Default login: Username `admin` / Password `bugsBounty` (`--auth-user` / `--auth-pass` / `--no-auth`)
#   • ChatGPT-style `#basement-ops` console: one conversation with the agent
#       - message thread (you right, agent left) with live stage/verdict narration & a typing indicator
#       - sidebar: target box, Recon / Hunt / Auto buttons, 6-stage tracker, live counters
#       - drawers: Live ops (.bin processes, PAYLOAD_MUTEX, event stream), Findings (verified bugs,
#         curl PoCs, disproved claims, kill chains), BeEF hook C2 + OOB, Arsenal status, API key, Help
```

---

## The Agent & Its Six Stages (`agents/agent.py`)

There is exactly **one agent**. It has a single identity (`AGENT`), a single transcript and a single
telemetry record; the six stages below are ordered *internal* steps of that agent, dispatched from
`agents/autopilot.py` or invoked individually from the CLI/REPL/Web console.

| # | Stage | Module | What the agent does | Primary tooling |
|---|---|---|---|---|
| 1 | **Recon** | `agents/recon_agent.py` | Attack-surface mapping | `subfinder`, `assetfinder`, `dnsx`, `httpx`, `wafw00f`, `katana`, `hakrawler`, `arjun`, `ffuf`, `gobuster`, `gau`, `waybackurls`, `paramspider` |
| 2 | **Hunt** | `agents/hunter.py` | Parallel vulnerability probing across parameterized URLs, locked gates, YAML rules and Nikto, coordinated through `PAYLOAD_MUTEX` + 24 WAF tamper scripts | `scan/*`, `.bin/nuclei`, `.bin/nikto` |
| 3 | **Escalate** | `agents/escalator.py` | Heavy-weapon confirmation: `SQLi → sqlmap`, `XSS → dalfox + BeefServer`, `SSRF → OOBManager / interactsh`, `CMDi → commix + OOB`, `401/403 → bypass_403` | `.bin/sqlmap`, `.bin/dalfox`, `.bin/commix`, BeEF, OOB |
| 4 | **Verify** | `agents/critic.py` | **100% deterministic** verification (zero LLM calls). Enforces detector provenance, replays benign baselines and impact proofs, bins false positives | control probes on `core/http.py` |
| 5 | **Chains** | `chains/builder.py` | Correlates verified findings into multi-step P1 chains (`.env Secrets -> Admin`, `403 Bypass -> Admin RCE`, `XSS -> BeEF Session Hijack`, `SQLi -> Credential Dump`) | `chains/builder.py` |
| 6 | **Report** | `agents/triage.py`, `poc_generator.py`, `reporter.py` | CVSS v3.1 scoring, standalone `curl` + Python PoCs, platform-ready advisories (`Markdown`, `HackerOne`, `Bugcrowd`, `Intigriti`, `Immunefi`) | CVSS + PoC + reporter |

### Modes

| Command | What happens |
|---|---|
| `/target <site.com>` | Sets the target for everything that follows (host or full URL). |
| `/recon` | Stage 1 only: subdomains, live hosts, WAF vendor, crawl, hidden params, dirbust, historical URLs. |
| `/hunt` | Stage 2 only: SQLi, XSS, SSRF, CMDi, SSTI, LFI, 403 bypasses and exposure templates. |
| `/auto` | **Agent-driven:** recon → hunt → *pursue each lead individually* (heavy tools) → verify → chains → report. |
| `/autopilot` | Batch version of the same six stages (escalate/verify in bulk rather than per lead). |
| `/verify` · `/chains` · `/report` · `/status` | Run or inspect a single stage at any time. |

`/auto` is the "let the agent drive" mode: leads are sorted by severity/confidence, each one is escalated
with its matching heavy tool (`sqlmap`, `dalfox` + BeEF, `commix`, `interactsh`/OOB, `bypass_403`),
immediately challenged with deterministic controls, and only the survivors go on to chains and the report.

Every stage writes into the same `AGENT_BUS` transcript (`agent_transcript.json` per engagement), so the
console chat, the live feed and the report all show one continuous voice instead of a simulated group chat.

## The 22 Arsenal Tools (`tools/registry.py` & `.bin/`)

| Tool | Category | Source | Role Access | Purpose |
|---|---|---|---|---|
| `subfinder` | `recon` | `.bin/subfinder` | `recon` | Passive subdomain enumeration |
| `assetfinder` | `recon` | `.bin/assetfinder` | `recon` | Certificate & OSINT subdomain discovery |
| `dnsx` | `recon` | `.bin/dnsx` | `recon` | Fast bulk DNS resolution (`A`/`AAAA`/`CNAME`) |
| `httpx` | `recon` | `.bin/httpx` | `recon`, `hunter` | Live HTTP prober (status, title, tech stack, CDN/WAF) |
| `wafw00f` | `waf` | `.bin/wafw00f` | `recon`, `hunter` | Active commercial WAF vendor fingerprinting |
| `katana` | `crawl` | `.bin/katana` | `recon`, `hunter` | Headless-capable JS-aware web crawler |
| `hakrawler` | `crawl` | `.bin/hakrawler` | `recon` | Fast form, link & script endpoint crawler |
| `gobuster` | `recon` | `.bin/gobuster` | `recon`, `hunter` | High-speed directory & hidden path brute-forcer |
| `ffuf` | `fuzz` | `.bin/ffuf` | `recon`, `hunter` | Calibrated content & parameter fuzzer (`-ac`) |
| `arjun` | `params` | `.bin/arjun` | `recon`, `hunter` | Hidden HTTP GET/POST parameter discovery |
| `waybackurls` | `params` | `.bin/waybackurls` | `recon` | Wayback Machine historical endpoint miner |
| `gau` | `params` | `.bin/gau` | `recon` | AlienVault OTX + CommonCrawl + Wayback URL fetcher |
| `paramspider` | `params` | `.bin/paramspider` | `recon` | Historical parameterized endpoint extractor |
| `nuclei` | `templates` | `.bin/nuclei` | `hunter`, `escalator` | Declarative YAML exposure & CVE template engine |
| `nikto` | `web` | `.bin/nikto` | `hunter` | Server misconfiguration & dangerous file scanner |
| `sqlmap` | `sqli` | `.bin/sqlmap` | `escalator` | Automated DBMS extraction & WAF-tamper SQLi engine |
| `dalfox` | `xss` | `.bin/dalfox` | `hunter`, `escalator` | DOM/reflected XSS parameter analyzer & verifier |
| `commix` | `exploit` | `.bin/commix` | `escalator` | Automated OS command injection exploitation engine |
| `interactsh` | `oob` | `.bin/interactsh-client` | `hunter`, `escalator` | Out-of-band DNS/HTTP blind interaction client + local listener |
| `beef_hook` | `xss` | Built-in (`tools/beef.py`) | `escalator` | Live BeEF-style XSS browser hook C2 server (`hook.js`) |
| `bypass_403` | `exploit` | Built-in (`scan/bypass_403.py`) | `hunter`, `escalator` | Edge ACL header (`X-Original-URL`, `X-Forwarded-For`), verb & path bypasser |
| `exploit_stagers` | `exploit` | Built-in (`exploit/stagers.py`) | `escalator`, `chainsaw` | Non-destructive PoC stagers (BeEF hook, SQLi proof, SSRF/CMDi OOB) |

---

## Repository Directory Map

```text
bugsBounty/
├── bughunter.py / bugsBounty.py  # Main Typer CLI entrypoints (`bughunter`, `bugsbounty`, `agent`)
├── install.sh / pyproject.toml   # Cross-platform 1-command installer & PEP 621 package spec
├── .bin/                         # 19 pre-bundled offensive tools & portable cross-platform shims
├── core/                         # Config, AI router (Grok/Groq/OpenAI/Ollama), HTTP, Mutex, Stealth, WAF Bypass, Scope, Auth, CVSS
├── tools/                        # Central ToolRegistry, 22 adapters, live BeefServer C2, OOBManager, Wordlists, Plugins
├── agents/                       # Single agent core (agent.py), six stage modules, Autopilot, WarRoomSession
├── chains/                       # Multi-step exploit chain builder (stage 5)
├── scan/                         # 78 modular vulnerability scanners (SQLi, XSS, SSRF, CMDi, JWT, GraphQL, HTTP/2, OAuth, SAML, AI/LLM...)
├── recon/                        # Subdomains, Host Probing, Crawling, Dirbusting, Wayback + Advanced DNS / Favicon / JS Analysis
├── templates/                    # Declarative YAML rule engine & common exposure rules (.env, Git, Actuator, Debug)
├── fuzz/                         # Differential anomaly fuzzer & LLM/polymorphic payload generator
├── exploit/                      # PoC stagers, reverse shell templates, webshell templates
├── cloud/ · cicd/ · osint/       # AWS S3/IAM deep scanner, GitHub Actions scanner, OSINT harvester
├── exfil/ · redteam/ · memory/   # OOB exfil PoC helpers, authorized phishing templates, cross-target pattern DB
├── report/                       # HackerOne, Bugcrowd, Intigriti & Immunefi submission templates
├── web/                          # ChatGPT-style #basement-ops console (HTTP server + single-page chat UI)
├── docs/                         # Deep-dive Architecture, CLI/Console & Scanners/SDK manuals
└── tests/                        # VulnCorp stateful WAF + trap target server & live E2E suite
```

---

## Running the Live Verification Suite

```bash
# Run the live end-to-end suite against a real local stateful WAF + SQLite/XSS/SSRF/CMDi/Trap server:
./.venv/bin/pytest -v tests/test_agent_e2e.py
```

---

## Legal & Authorization Notice

> **Authorized Testing Only**: Only run `bugsBounty` against targets you own (such as the built-in `bughunter lab` target) or systems for which you hold explicit written permission (e.g., an active bug bounty program scope or signed penetration testing engagement). Scope enforcement helpers are built directly into `core/scope.py`.
