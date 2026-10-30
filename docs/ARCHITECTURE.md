# `bugsBounty` System Architecture & Security Engineering Deep-Dive

This document details the internal architecture, concurrency model, WAF evasion engine, escalation handoffs, **no-self-certification** guarantees, and the **100% deterministic verification logic** of the single `AGENT` inside `bugsBounty`.

---

## 1. Design Philosophy: Why Most Bug Bounty Scanners Fail

Conventional scanners fail in two opposite directions:
1. **Noisy regex scanners** flag every `500 Internal Server Error`, `SQL` word on a static marketing page, HTML-encoded reflection, or soft-200 SPA fallback as "Critical" — wasting hours of human triage and getting researchers banned for spam reports.
2. **Pure-LLM agents** suffer from **confirmation bias**: when the same LLM prompt generates a payload *and* judges whether its own payload worked, it hallucinates impact whenever a response looks vaguely unusual.

`bugsBounty` eliminates both failure modes with **one agent** whose work is split into **four strict architectural layers** (surfaced as six ordered stages):

```text
[ Layer 1: Attack Surface & WAF Intelligence ]  stage 1 recon   (recon/* + .bin/* + core/waf_bypass.py)
                     │
                     ▼
[ Layer 2: Mutex-Coordinated Active Hunting  ]  stage 2 hunt    (scan/* + core/mutex.py + core/stealth.py)
                     │
                     ▼
[ Layer 3: Heavy Weapon Exploitation Handoff ]  stage 3 escalate(agents/escalator.py + sqlmap/dalfox/BeEF/OOB/commix)
                     │
                     ▼
[ Layer 4: Zero-LLM Falsification Gate       ]  stage 4 verify  (agents/critic.py — SeparationOfDutiesError + Control Replay)
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
   [ VERIFIED HIT ]      [ DISPROVED / REJECTED ]
   -> stages 5 & 6       -> Logged separately with exact forensic disproof notes
```

---

## 2. Core Data Flow & Single-Agent Lifecycle (`agents/autopilot.py`)

When `run_autopilot(target, max_pages=35, report_out=...)` executes, one `AGENT` walks six ordered stages over shared structured state (`agents/agent.py :: STAGES`):

### Stage 1 — Recon (`agents/recon_agent.py :: run_recon`)
1. **Binary Attack-Surface Enumeration**:
   - Subdomains & DNS: `.bin/subfinder`, `.bin/assetfinder`, `.bin/dnsx`, plus Certificate Transparency (`crt.sh`) when given a domain.
   - Live HTTP Fingerprinting: `.bin/httpx` extracts status codes, page titles, server headers, CDN hints, and content lengths.
   - WAF Detection: `.bin/wafw00f` + passive/active signature probes (`core/waf_bypass.get_host_waf_profile`) identify the exact WAF vendor in front of the host and pre-seed `PAYLOAD_MUTEX` with stealth headers + vendor-specific tamper priorities.
   - Active Spidering & Hidden Parameter Mining: `.bin/katana`, `.bin/hakrawler`, and `.bin/arjun` map links, JS endpoints, HTML forms, and undocumented GET/POST query parameters.
   - Calibrated Path Discovery & Historical Mining: `.bin/ffuf` (auto-calibrated `-ac`), `.bin/gobuster`, `.bin/waybackurls`, `.bin/gau`, and `.bin/paramspider` discover hidden admin gates, `.env` / backup files, and legacy parameterized endpoints.
2. **Stage Output**: Emits a structured `surface` dictionary (`urls`, `param_urls`, `forms`, `locked_gates`, `waf`, `hosts`) into session state and the `AGENT_BUS` transcript for the hunting stage.

### Stage 2 — Hunt (`agents/hunter.py :: run_hunter`)
1. Runs targeted vulnerability scanners in parallel (`agents/swarm.py`) across every parameterized endpoint (`scan/sqli.py`, `scan/xss.py`, `scan/ssrf.py`, `scan/cmdi.py`, `scan/lfi.py`, `scan/ssti.py`, `scan/redirect.py`, `scan/cors.py`, `scan/headers.py`, etc.).
2. Runs declarative YAML exposure templates (`.bin/nuclei` -> `templates/engine.py`) and `.bin/nikto` server checks against base origins, plus `scan/bypass_403.py` against locked `401`/`403` gates.
3. Stamps every resulting `Finding` object with immutable detector provenance:
   - `detected_by = "hunter:<scanner>"` (specific scanner provenance, **never** `"critic:verify"`)
   - `verified = False` (untrusted claim until the verification stage proves it).

### Stage 3 — Escalate (`agents/escalator.py :: run_escalator`)
Automatically inspects every suspected finding from the hunt stage and hands it to a specialized heavy exploitation engine:

| Suspected Vulnerability Class | Automatic Escalation Pipeline | Proof Artifacts Recorded on `Finding` |
|---|---|---|
| **SQL Injection (`sqli`)** | Invokes `.bin/sqlmap --batch --level 2 --risk 2` with vendor-tuned `--tamper=...` from `sqlmap_tampers_for_wafs(waf_vendor)` | Confirmed DBMS banner/type (`SQLite`, `MySQL`, `PostgreSQL`, etc.), injectable parameter type, extracted table/column evidence |
| **Cross-Site Scripting (`xss`)** | Invokes `.bin/dalfox url ...` **AND** starts `BeefServer` (`tools/beef.py`), injecting live `<script src="http://.../hook.js"></script>` stagers (with polymorphic WAF bypass fallback `<svg onload=...>` / `<details ontoggle=...>`) | Reflected unencoded hook tag confirmation, live `hook_url`, ready-to-paste `beef_stagers`, active browser C2 session table |
| **Server-Side Request Forgery (`ssrf`)** | Starts `OOBManager` (`tools/oob.py` local HTTP listener + `.bin/interactsh-client`), generates unique canary URL `http://127.0.0.1:<port>/oob/<token>`, injects via `probe_with_mutex_bypass`, and polls real inbound hits | Verified inbound HTTP/DNS callback record (`client_ip`, `user_agent`, `path`, timestamp) proving the remote server made the outbound request |
| **OS Command Injection (`cmdi`)** | Invokes `.bin/commix --batch` **plus** deterministic command-output canary (`echo`) & OOB callback stager | Confirmed command execution output canary + `commix` session artifact |
| **Access Control / `401`/`403` Gate (`access_control` / `bypass_403`)** | Runs multi-vector header/verb/path bypass (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, `/%2e/admin`, `/admin/..;/admin`) + `.bin/arjun` parameter discovery on unlocked endpoints | Exact bypass curl header/path diff (`403 -> 200`), body length delta, unlocked admin content snippet |

### Stage 4 — Verify (`agents/critic.py :: run_critic`) — Zero-LLM Adversarial Verification
Every finding MUST pass through this stage. It **never** invokes an LLM (`0` API calls, `0` stochastic temperature drift).

#### Invariant A — No Self-Certification (`SeparationOfDutiesError`)
Before inspecting any HTTP traffic, `critique_finding(finding)` checks provenance:
1. If `finding.detected_by` is missing/empty → **raises `SeparationOfDutiesError`** (`"Provenance missing: every finding must record the detecting agent"`).
2. If `finding.detected_by` is the verifier itself (`critic:verify` / `critic` / `validator`) → **raises `SeparationOfDutiesError`**, because a claim that the verification stage generated can never be certified by the same stage.
3. The separation is enforced in code even though both stages run inside the same agent: the verification stage has no scanner code paths and the hunting stage cannot mark a finding verified.

#### Invariant B — Active Adversarial Disproof Per Vulnerability Class
The verification stage attempts to **disprove** every claim by sending benign baseline requests, comparing differential responses, and verifying concrete exploit artifacts:

| Vulnerability Class | How the Verifier Actively Attempts to Disprove It | Required Proof to Certify (`verified = True`) | Common False Positives Automatically Rejected |
|---|---|---|---|
| **`sqli`** | Replays clean alphanumeric baseline (`id=1`), non-existent record (`id=999999`), true boolean control (`1 AND 1=1`), and false boolean control (`1 AND 1=2`), plus checks `sqlmap` DBMS proof | True vs False boolean differential OR confirmed `sqlmap` DBMS banner OR real SQL engine parse diff absent from benign control | Static pages mentioning `"SQL syntax"` in blog text; identical 500 error pages returned for *any* non-integer input |
| **`xss`** | Injects unique canary with dangerous HTML characters (`<>"'`), inspects Content-Type (`text/html` vs `application/json` / `text/plain`), and checks whether `<` and `>` survived **unencoded** in an executable HTML context | Unencoded `<` / `>` reflection in `text/html` body + executable handler/hook tag (`<svg`, `<img`, `<details`, `hook.js`, or `dalfox` PoC) | HTML-entity encoded output (`&lt;script&gt;`); reflections inside `application/json` API responses |
| **`ssrf`** | Sends unique fresh OOB canary URL (`OOBManager.generate_canary()`) and checks actual listener hit log **or** verifies private metadata payload absent from baseline page | Real inbound socket callback recorded by `OOBManager` / `Interactsh` **or** verified cloud metadata token (`ami-id`, `instance-id`) absent on benign input | URL echoed back harmlessly in error message (`"Invalid webhook URL: http://..."`) without server fetch |
| **`cmdi`** | Computes a fresh random arithmetic/token echo marker and verifies the **evaluated result** (not the raw command string!) appears only when injected | Evaluated command output (`uid=`, fresh echo token without surrounding `echo ...` literal) or verified OOB beacon | Target simply reflecting the query parameter back in HTML (`Ping host: 127.0.0.1;id`) |
| **`lfi` / `traversal`** | Compares benign filename against traversal payload and inspects structure | Canonical multi-colon `/etc/passwd` structure (`root:x:0:0:`) or `win.ini` (`[extensions]`) absent on benign request | Custom 404/soft-200 SPA shell returning HTTP `200 OK` for `../../../../etc/passwd` |
| **`ssti`** | Injects unique random multiplication expression (e.g., `{{7919*13}}`) and checks for evaluated product `102947` while ensuring baseline does not contain it | Evaluated mathematical product `102947` present in response | Template string echoed literally as `{{7*7}}` without server-side evaluation |
| **`access_control` / `403`** | Sends direct unauthenticated request (`expect 401/403`), then replays exact bypass header/verb/path and compares response structure against soft-404 baseline | Direct request returns `401`/`403` AND bypass request returns `200` with genuine privileged content distinct from home/404 page | Edge server returning blank `200 OK` (`Content-Length: 0`) on `OPTIONS` or `HEAD` |
| **Sensitive Exposures (`.env`, `.git`)** | Fetches random non-existent sibling path (`/.nonexistent_<rand>`) to detect catch-all `200 OK` SPAs | HTTP `200` with authentic `KEY=VALUE` secrets (`DB_PASSWORD=`, `AWS_SECRET_ACCESS_KEY=`, `[core]`) AND sibling random path does NOT return matching body | Single-Page Apps returning `index.html` (`200 OK`) for every path including `/.env` |

### Stage 5 — Chains (`chains/builder.py :: build_chains`)
Operates strictly on verified findings to construct multi-step kill chains with boosted P1 impact ratings, including:
- **Exposed Secrets (`/.env`) → Administrative Takeover**
- **403 Edge ACL Bypass (`/admin`) + Command Injection / Admin Action → Full Server Compromise**
- **WAF-Bypassed Reflected/DOM XSS + Live BeEF Hook (`hook.js`) → Authenticated Session Takeover**
- **SQL Injection (`sqlmap` Confirmed) → Credential Extraction & Account Takeover**
- **SSRF Callback Verified → Internal Cloud Metadata / Microservice Pivot**

### Stage 6 — Report (`agents/triage.py`, `agents/poc_generator.py`, `agents/reporter.py`)
1. Computes standardized **CVSS v3.1** base scores (`core/cvss.py`) and bug bounty priority tiers (`P1`–`P4`).
2. Generates standalone reproducible **PoC bundles** (`curl` command with exact headers/tampers, standalone Python `requests` reproduction script, and BeEF/OOB stagers).
3. Writes comprehensive **Markdown + JSON advisories** including:
   - Executive Summary & WAF Evasion Telemetry (`PAYLOAD_MUTEX` stats)
   - Verified Vulnerability Advisories + CVSS v3.1 + Full PoCs
   - Multi-Step Attack Chains
   - **Transparency Appendix: False Positives Disproved & Rejected**
   - Full agent activity log (`AgentBus`).

---

## 3. Sophisticated WAF Detection, Stealth & `PAYLOAD_MUTEX` Engine

### 20 Fingerprinted WAF Vendors (`core/waf_bypass.py :: WAF_SIGNATURES`)
`cloudflare`, `aws_waf`, `cloudfront`, `akamai`, `modsecurity`, `imperva`, `f5_bigip`, `sucuri`, `barracuda`, `fortiweb`, `azure_waf`, `fastly_sigsci`, `wordfence`, `datadome`, `perimeterx`, `wallarm`, `radware`, `citrix_netscaler`, `safeline`, `custom_app_waf`.

### 24 Composable Polymorphic Tamper Scripts (`core/waf_bypass.py :: TAMPER_SCRIPTS`)
| Category | Tamper Script Names |
|---|---|
| **SQLi Comment & Keyword Splitting** | `comment_inline_keywords` (`/*!50000UNION*/`), `mysql_versioned_comment`, `space2comment` (`/**/`), `space2mysqlblank` (`%09`/`%0b`/`%0c`), `space2mssqlhash`, `scientific_notation` (`1e0UNION`) |
| **XSS Tag & Event Polymorphism** | `xss_tag_polymorph` (`<script>` → `<svg/onload=...>`, `<img src=x onerror=...>`), `xss_details_ontoggle` (`<details/open/ontoggle=...>`), `html_hex_entities`, `js_octal_escape` |
| **OS Command & Path Evasion** | `cmdi_ifs_bypass` (`$IFS` / `${IFS}`), `cmdi_brace_bypass`, `lfi_double_dot_slash` (`....//`), `ssrf_decimal_localhost` (`2130706433` / `0x7f000001` / `[::ffff:127.0.0.1]`) |
| **Encoding, Case & Unicode Normalization** | `url_encode`, `double_url_encode`, `charencode`, `randomcase`, `space2tab`, `space2newline`, `space2plus`, `unicode_homoglyph`, `fullwidth_unicode`, `null_byte_prefix` |

### Thread-Safe Coordination (`core/mutex.py :: PayloadMutexCoordinator`)
When multiple scanner threads test the same host simultaneously:
1. Before transmitting a `(host, endpoint, vuln_type, tamper_name)` combination, the worker checks `PAYLOAD_MUTEX.is_burned(...)`. If another thread already got blocked (`403`/`406`/`429`/`503` WAF block page) using that exact tamper, **no other thread wastes requests repeating it**.
2. On a WAF block:
   - `PAYLOAD_MUTEX.record_failure(...)` marks that tamper burned on that endpoint.
   - `core/stealth.burn_ua(ua)` retires the blocked browser User-Agent profile and rotates to a fresh browser header suite (`Sec-Ch-Ua`, `Accept-Language`, `Upgrade-Insecure-Requests`).
3. On a successful bypass (`200 OK` non-block response):
   - `PAYLOAD_MUTEX.record_bypass_win(host, tamper_name)` promotes that tamper to **top priority across ALL worker threads** targeting that host!

---

## 4. Persistent State & Secret Security (`~/.bugsBounty/`)

All local artifacts live under `~/.bugsBounty/` (customizable via `BUGHUNTER_HOME`):
```text
~/.bugsBounty/
├── config.json      # Saved LLM provider & API keys (chmod 0600 — user read/write ONLY)
├── reports/         # Generated Markdown & JSON vulnerability advisories
├── findings/        # Per-target FindingStore JSONL/JSON records with full provenance
├── recon/           # Saved attack-surface maps per target
├── scans/           # Raw tool output logs (sqlmap, dalfox, commix, nuclei)
├── memory/          # Cross-target PatternDB & LeadBoard state
├── beef/            # BeEF browser hook session logs
└── oob/             # Out-of-Band HTTP/DNS canary hit logs
```
