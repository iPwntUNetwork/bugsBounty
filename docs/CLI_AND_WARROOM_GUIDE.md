# Complete CLI & `#basement-ops` Interactive Agent Console Guide

This manual documents **every global CLI option**, **every `bughunter` subcommand**, **every interactive `#basement-ops` slash command**, **every Web console HTTP API endpoint**, **every `VulnCorp` Target Lab route**, and **common troubleshooting steps**.

---

## 1. Installed Entrypoints

Running `./install.sh` installs three equivalent CLI commands inside `.venv/bin/`:

| Command | Equivalent Invocation | Purpose |
|---|---|---|
| `./.venv/bin/bughunter` | `python3 bughunter.py` | Main full-featured CLI (all 19 subcommands) |
| `./.venv/bin/bugsbounty` | `python3 bugsBounty.py` | Alias for `bughunter` |
| `./.venv/bin/agent` | `./.venv/bin/bughunter warroom` | Direct shortcut straight into the interactive `#basement-ops` REPL |

> **Tip**: Activate the virtual environment once per shell (`source .venv/bin/activate`) if you want to type `bughunter ...` and `agent` directly without `./.venv/bin/`.

---

## 2. Global Options (`bughunter [GLOBAL OPTIONS] <COMMAND> ...`)

Global flags go **before** the subcommand name (for example: `bughunter --api-key xai-... --model grok-3 warroom --lab`):

| Flag | Short | Default | Description |
|---|---|---|---|
| `--provider <str>` | — | `groq` / `auto` | AI provider: `groq` (`https://api.groq.com/openai/v1`), `ollama`, `openai`, or `xai` |
| `--api-key <str>` | `-k` | env/config | API key for this run (`gsk_...` → Groq `https://api.groq.com/openai/v1`) |
| `--model <str>` | — | `qwen/qwen3.8-27b` | Override model (Groq default: `qwen/qwen3.8-27b`) |
| `--base-url <str>` | — | provider default | Custom OpenAI-compatible `/v1` API URL (vLLM, LM Studio, OpenRouter, Together, etc.) |
| `--ollama-model <str>` | — | `llama3.1:8b` | Local Ollama model tag |
| `--ollama-url <str>` | — | `http://localhost:11434` | Local or LAN Ollama daemon URL |
| `--rate <float>` | — | `25.0` | Maximum HTTP requests per second per target |
| `--proxy <str>` | — | none | Route HTTP scanner traffic through proxy (e.g. `http://127.0.0.1:8080` for Burp/Caido or `socks5://...`) |
| `--stealth / --no-stealth` | — | `--stealth` | Enable rotating browser TLS/header profiles & automatic `429`/`403` User-Agent burn recovery |
| `--stream / --no-stream` | — | `--stream` | Enable/disable live agent stage updates on stdout |

---

## 3. All 19 CLI Subcommands (With Copy-Paste Examples)

### 3.1 Setup, Auth & Diagnostics

```bash
# Save your xAI Grok (xai-...), Groq Cloud (gsk_...), or OpenAI (sk-...) key permanently (chmod 0600) & verify live:
bughunter auth YOUR_API_KEY --test
bughunter auth YOUR_API_KEY --model grok-3 --test
bughunter auth                    # Show current active provider, endpoint & masked key status

# Audit all 22 .bin/ & built-in offensive tools (table or JSON):
bughunter tools
bughunter tools --json

# Check local Ollama daemon reachability & installed models:
bughunter ollama
bughunter ollama --model qwen2.5-coder:7b
```

### 3.2 Interactive Agent & Local Target Lab

```bash
# Drop into the interactive #basement-ops terminal REPL (and auto-boot local vulnerable target):
bughunter warroom --lab
bughunter warroom https://authorized-target.tld

# Launch the live Browser War-Room UI on http://0.0.0.0:8787 (with auto-started target lab):
bughunter ui --port 8787 --lab
bughunter ui --host 127.0.0.1 --port 8787 --target https://authorized-target.tld

# Inspect the agent + its six stages, open REPL (-i), or send a single-shot message (-m):
bughunter agent
bughunter agent -i --lab
bughunter agent --lab -m "Map every hidden endpoint and fingerprint the WAF"
bughunter agent -t http://127.0.0.1:8080 -m "Audit every finding and bin any false positives"

# Start the standalone VulnCorp Vulnerable Target Server on port 8080:
bughunter lab --host 127.0.0.1 --port 8080 --waf
bughunter lab --port 8080 --no-waf
```

### 3.3 Full Pipeline & Individual Agent Phases

```bash
# Full single-agent pipeline (recon -> hunt -> escalate -> verify -> chains -> report):
bughunter autopilot https://authorized-target.tld --max-pages 50 -o bounty_report.md

# Stage 1 — Recon / attack-surface mapping:
bughunter recon https://authorized-target.tld --max-pages 35

# Stage 2 — Hunt (WAF-evading active scanning):
bughunter hunt https://authorized-target.tld

# Stage 3 — Escalate (sqlmap, dalfox + BeEF, Interactsh/OOB, commix):
bughunter escalate https://authorized-target.tld

# Stage 4 — 100% deterministic verification (critic / validate / verify are aliases):
bughunter verify https://authorized-target.tld
bughunter critic https://authorized-target.tld

# Stage 5 — Multi-step attack chain synthesis:
bughunter chains https://authorized-target.tld

# Stage 6 — CVSS v3.1 triage, PoC scripts & Markdown report generation:
bughunter triage https://authorized-target.tld
bughunter poc https://authorized-target.tld
bughunter report https://authorized-target.tld -o final_advisory.md
```

### 3.4 Direct Module Scanning & Live BeEF Browser Hook C2

```bash
# Run any of the 78 individual scanners inside scan/<module>.py directly:
bughunter scan sqli "http://127.0.0.1:8080/product?id=1"
bughunter scan xss "http://127.0.0.1:8080/search?q=test"
bughunter scan ssrf "http://127.0.0.1:8080/webhook?callback=http://example.com"
bughunter scan bypass_403 "http://127.0.0.1:8080/admin"
bughunter scan jwt_deep "https://authorized-target.tld/api/profile"
bughunter scan graphql_deep "https://authorized-target.tld/graphql"

# Stage a live BeEF browser hook C2 payload against a reflected/stored XSS parameter:
bughunter beef "http://127.0.0.1:8080/search?q=test" --param q
```

---

## 4. `#basement-ops` Interactive Slash Commands

Inside `bughunter warroom` (or the chat box of `bughunter ui`), you can mix **slash commands**, **inline URLs**, and **natural English** freely — all of it is handled by the one agent:

| Command / Syntax | Effect |
|---|---|
| `/lab` *(or `/lab nowaf`)* | Starts the built-in `VulnCorp Portal` target lab on a local port and binds it as active target |
| `/target <url>` *(or paste any `https://...` URL inline)* | Updates the active target URL for the agent immediately |
| `/key <API_KEY> [model]` | Hot-loads & saves your `Grok` (`xai-...`), `Groq` (`gsk_...`), or `OpenAI` (`sk-...`) key **with secret masking in the chat transcript** |
| `/provider <grok\|groq\|openai\|ollama> [model]` | Switches active AI provider/model live without restarting |
| `/autopilot` *(aliases: `/auto`, `/run`, `/pwn`)* | Runs all 6 stages end-to-end and saves a complete Markdown report |
| `/recon` | Runs stage 1 — surface discovery & WAF fingerprinting |
| `/hunt` *(alias: `/scan`)* | Runs stage 2 — multi-threaded WAF-evading vulnerability scan |
| `/escalate` | Runs stage 3 — heavy-tool confirmation (`sqlmap`, `dalfox`+`BeEF`, `Interactsh`/OOB, `commix`) |
| `/verify` *(aliases: `/audit`, `/critic`, `/validate`)* | Runs stage 4 — 100% deterministic verification & false-positive pruning |
| `/chains` | Runs stage 5 — multi-step exploit chain synthesis |
| `/report` *(aliases: `/poc`, `/triage`)* | Runs stage 6 — CVSS v3.1 scoring + PoC builder + Markdown advisory output |
| `/status` *(aliases: `/findings`)* | Displays live counts (Surface URLs, raw claims, verified bugs, disproved claims, chains, active LLM) |
| `/tools` | Shows how many `.bin/` & built-in tools are READY |
| `/help` | Prints the command list |
| `/quit` / `/exit` | Cleanly shuts down any running local lab server and exits REPL |
| `@agent <message>` | Optional prefix — everything already goes to the single `AGENT` |

---

## 5. Browser Console HTTP API Reference (`web/warroom_ui.py`)

When running `bughunter ui --host 0.0.0.0 --port 8787`, the server exposes clean JSON endpoints (all CORS-enabled and relative-path proxy safe):

| Method & Route | Request Body | Response Payload |
|---|---|---|
| `GET /` | — | Full single-page `#basement-ops` interactive web console HTML/CSS/JS |
| `GET /health` | — | `{"ok": true, "status": { ... }}` — live health check, target, counts & active LLM summary |
| `GET /api/state` | — | Complete session snapshot: `status`, single `agent` record, `stages` tracker, `verified` findings, `disproved` claims, `raw` findings, `chains`, `pocs`, and last 160 `transcript` messages |
| `GET /api/tools` | — | Live audit table of all **22 `.bin/` & built-in tools** (`name`, `category`, `source`, `status`, `version`) |
| `POST /api/chat` | `{"message": "/recon", "async": true}` | Executes the command under session lock (async on a worker thread); returns `{"new_messages": [...], "status": {...}}` |
| `POST /api/llm` | `{"provider": "grok", "api_key": "xai-...", "model": "grok-3"}` | Configures & persists provider/key (`0600`), masks key in response, returns `{"ok": true, "llm": {...}}` |

---

## 6. Built-In Safe Target Lab Reference (`VulnCorp Portal` — `tests/vuln_server.py`)

Running `bughunter lab` (or `--lab`) starts a realistic stateful web application protected by a **simulated Cloudflare WAF** (which blocks naive `<script>`, raw `UNION SELECT`, `;cat /etc/passwd`, and rate-spikes unless bypassed via `PAYLOAD_MUTEX` tampers & UA rotation!):

### 8 Genuine Exploitable Vulnerabilities (verifier certifies `VERIFIED`)
1. `GET /product?id=1` — Real **in-memory SQLite SQL Injection** (leaks `admin_users` hashes under boolean/UNION tamper bypass & `.bin/sqlmap`).
2. `GET /search?q=router` — **Reflected XSS** behind Cloudflare `<script>` filter (exploitable via polymorphic `<svg/onload=...>` / `<details/open/ontoggle=...>` + live BeEF `hook.js`).
3. `GET /webhook?callback=http://...` — **Live Out-of-Band SSRF** (server genuinely performs an outbound HTTP fetch to your `OOBManager` canary URL).
4. `GET /diag?host=127.0.0.1` — **OS Command Injection** (`$IFS` / `;` command execution verified with dynamic echo tokens & `.bin/commix`).
5. `GET /download?file=manual.txt` — **Path Traversal / LFI** (`....//` traversal leaks `/etc/passwd`).
6. `GET /render?tpl=welcome` — **Server-Side Template Injection (SSTI)** (evaluates `{{a*b}}` expressions server-side).
7. `GET /admin` — **403 Edge ACL Bypass** (`403 Forbidden` directly, unlocked to `200 OK` admin panel via `X-Original-URL` / `X-Forwarded-For: 127.0.0.1`).
8. `GET /.env` — **Exposed Production Secrets File** (leaks DB & cloud credentials).

### 6 Deliberate False-Positive Traps (the verifier disproves every single one!)
1. `GET /blog?post=sql-tuning` — Static article containing literal words `"SQL syntax error near MySQL"` on every request (**SQLi trap**).
2. `GET /safe-echo?msg=...` — Properly HTML-escapes `<` → `&lt;` and `>` → `&gt;` (**XSS trap**).
3. `GET /fake-webhook?url=...` — Prints `"Queued webhook to <url>"` in text **without ever making an outbound network request** (**SSRF trap**).
4. `GET /echo-cmd?cmd=...` — Echoes raw text back without executing shell commands (**CMDi trap**).
5. `GET /spa-fallback/...` — Returns HTTP `200 OK` generic HTML shell for *every* path (**Soft-200 LFI / `.env` trap**).
6. `GET /broken-500?x=...` — Always returns `500 Internal Server Error` regardless of benign vs malicious input (**500-diff trap**).

---

## 7. Environment Variables Reference

| Variable | Purpose | Default |
|---|---|---|
| `GROQ_API_KEY` | Groq Cloud API key (`gsk_...`) | — |
| `GROQ_BASE_URL` | Groq OpenAI-compatible base URL | `https://api.groq.com/openai/v1` |
| `GROQ_MODEL` / `BUGHUNTER_MODEL` | Groq default model (`FAST_MODEL` also defaults here) | `qwen/qwen3.8-27b` |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | OpenAI API key & model | `gpt-4o-mini` |
| `XAI_API_KEY` / `XAI_BASE_URL` | Optional xAI key (`xai-...`) & base URL | `https://api.x.ai/v1` |
| `OLLAMA_BASE_URL` / `OLLAMA_MODEL` | Local Ollama URL & model | `http://localhost:11434` / `llama3.1:8b` |
| `LLM_PROVIDER` / `BUGHUNTER_PROVIDER` | Force provider (`auto`, `grok`, `groq`, `openai`, `ollama`) | `auto` |
| `BUGHUNTER_HOME` | Data directory for config, findings & reports | `~/.bugsBounty` |
| `BUGHUNTER_PROXY` | Outbound HTTP/SOCKS proxy URL | — |
| `BUGHUNTER_MAX_RPS` | Global per-host request rate limit | `25` |

---

## 8. Troubleshooting

- **`python3 -m venv` fails on fresh Ubuntu/Debian**: Install the `venv` package with `sudo apt update && sudo apt install -y python3-venv perl xz-utils`, then re-run `./install.sh`.
- **Running on macOS (M1/M2/M3/M4) or Raspberry Pi (`arm64`)**: Install Go first (`brew install go` or `sudo apt install -y golang-go`) and re-run `./install.sh` — it automatically compiles all 12 Go binaries natively for your CPU architecture into `.cache/gobins/`.
- **API Key `401 Unauthorized`**: Run `./.venv/bin/bughunter auth YOUR_API_KEY --test` to inspect which provider/endpoint was detected (`groq` `https://api.groq.com/openai/v1` + `qwen/qwen3.8-27b`, `ollama`, `openai`, or `xai`) and verify live network reachability.
- **Web Command Center HTTP Basic Auth (`401 Unauthorized` in browser / curl)**: By default, `bughunter ui` protects `/` and `/api/*` with HTTP Basic Auth **`admin:bugsBounty`** (override via `--auth-user <u/> --auth-pass <p>`, env vars `BUGHUNTER_UI_USER` / `BUGHUNTER_UI_PASS`, or `--no-auth`). Victim hook endpoints (`/beef/hook.js`, `/beef/poll`, `/beef/beacon`, `/beef/result`, `/beef/loot`, `/beef/victim`, `/oob/*`) remain open so hooked browsers report home seamlessly.

