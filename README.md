# bugsBounty — Autonomous 6-Agent Offensive Security & Bug Bounty Framework

`bugsBounty` wires **19 self-contained `.bin/` security binaries** + **3 built-in live exploitation/OOB engines** (`BeefServer` XSS Hook C2, `OOBManager` HTTP/Interactsh callback server, and declarative YAML `Nuclei` engine) into a strict **6-agent war-room workflow** supporting both **Groq** and **local Ollama** LLMs (plus 100% deterministic execution with zero API keys required).

---

## Architecture & Strict Separation of Duties

```
[GHOST: Recon] ──▶ [BLITZ: WAF-Evading Hunter] ──▶ [SWITCH: Heavy Tool Escalator]
                                                            │
                                                            ▼
[FIXER: CVSS/PoC/Report] ◀── [CHAINSAW: Attack Chains] ◀── [RAZOR: Deterministic Critic]
```

### The 20-Year War-Room Crew (`agents/crew.py`)
| Handle | Role | Responsibility |
|---|---|---|
| **GHOST** | Recon Cartographer | Subdomains, DNS, live tech probing, WAF fingerprinting, crawling, hidden params, dirbusting (`subfinder`, `assetfinder`, `dnsx`, `httpx`, `wafw00f`, `katana`, `hakrawler`, `arjun`, `ffuf`, `gobuster`, `gau`, `waybackurls`, `paramspider`) |
| **BLITZ** | Active Vuln Hunter | Multi-threaded scanning with `PAYLOAD_MUTEX`, 20-vendor WAF detection, 24 polymorphic tamper scripts & User-Agent rotation |
| **SWITCH** | Escalation Specialist | Automatic vulnerability handoffs: suspected SQLi → `.bin/sqlmap`; suspected XSS → `.bin/dalfox` + live **BeEF Hook C2** (`hook.js`); SSRF → `Interactsh`/OOB callback; CMDi → `.bin/commix` + OOB |
| **RAZOR** | **Deterministic Critic** | **Zero-LLM adversarial verifier**. Enforces `SeparationOfDutiesError` (detector may NEVER self-certify). Challenges every finding with benign controls, quote-pair SQL grammar probes, dual algebraic SSTI checks, HTML-encoding checks, and OOB receipts. Cheers valid exploits; dishes out Aussie brown-eye roasts on false positives! |
| **CHAINSAW** | Chain Architect | Stitches RAZOR-certified findings into P1 multi-step attack chains |
| **FIXER** | Bounty Closer | CVSS v3.1 scoring, reproducible `curl` + Python PoCs, war-room transcript & Markdown report |

---

## Bundled `.bin/` Arsenal (22 Ready Tools)

Every binary lives directly inside `/home/user/bugsBounty/.bin/` with `/home/user/bugsBounty/.bin` automatically prepended to `PATH`:

- **Recon & DNS**: `subfinder`, `assetfinder`, `dnsx`, `httpx`
- **Crawling & Hidden Params**: `katana`, `hakrawler`, `gau`, `waybackurls`, `paramspider`, `arjun`
- **Content & Server Fuzzing**: `ffuf`, `gobuster`, `nikto`, `wafw00f`, `nuclei`
- **Exploitation & Escalation**: `sqlmap`, `dalfox`, `commix`, `interactsh-client`
- **Built-in Live C2 & Bypass Engines**: `beef_hook` (`tools/beef.py`), `local_oob` (`tools/oob.py`), `bypass_403` (`scan/bypass_403.py`)

---

## Quick Start

```bash
# 1. Audit all 22 bundled .bin/ & internal tools
./.venv/bin/python bughunter.py tools

# 2. Meet the 6-agent crew
./.venv/bin/python bughunter.py crew

# 3. Full end-to-end autopilot with local Ollama model
./.venv/bin/python bughunter.py --provider ollama --ollama-model llama3.1:8b autopilot https://target.tld

# 4. Run full live E2E test suite (real WAF + SQLite + XSS/BeEF + SSRF OOB + CMDi + False-Positive Traps + Ollama mock)
./.venv/bin/pytest -v tests/test_crew_arsenal_e2e.py
```
