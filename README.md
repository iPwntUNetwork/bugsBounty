# AI Bug Bounty Toolkit (Groq)

Autonomous, AI-driven bug bounty hunting toolkit. Uses **Groq** for reasoning/planning/critic, plus deterministic HTTP scanners and a critic to eliminate false positives.

## Quick start

```bash
git clone <this> && cd bugsBounty
./install_all.sh   # interactive: installs everything + asks for Groq key
# or minimal: ./install.sh
export GROQ_API_KEY="gsk_..."   # get from https://console.groq.com
bugsBounty setup
bugsBounty autopilot target.com
```

AI provider: Groq. Set `GROQ_API_KEY`. Deterministic scanning works without any key.

## Commands

- `bugsBounty recon <target>` — subdomain enum, live hosts, crawl
- `bugsBounty hunt <target>` — run all scanners
- `bugsBounty autopilot <target>` — full autonomous loop (recon→hunt→validate→report)
- `bugsBounty validate` — 7-Question Gate on last findings
- `bugsBounty report` — write submission-ready report
- `bugsBounty surface <target>` — ranked attack surface
- `bugsBounty graphql-audit <url>`, `param-discover`, `bypass-403`, `secrets-hunt`, `takeover`, `cloud-recon`, `scan-cves`, `web3-audit`, `chat`

## Architecture

- `core/llm.py` — Groq client (OpenAI-compatible)
- `core/http.py` — rate-limited HTTP client
- `recon/` — subdomains (crt.sh + brute), live hosts, crawler
- `scan/` — deterministic scanners: XSS, SQLi, SSTI, SSRF, traversal, redirect, cmdi, CORS, headers, files, takeover, JWT, GraphQL
- `agents/validator.py` — deterministic checks + LLM critic + 7-Question Gate
- `agents/autopilot.py` — autonomous loop (parallel swarm)
- `chains/builder.py` — exploit chain builder (A→B→C)
- `fuzz/engine.py` — zero-day fuzzing + differential analysis
- `scan/ai_llm.py` — AI/LLM app security (prompt injection, jailbreak)
- `scan/waf.py` — WAF detection + tamper bypass
- `scan/ssti_advanced.py` — SSTI engine fingerprint + RCE
- `scan/hijack.py` — session/cookie hijacking, fixation
- `scan/upload.py`, `scan/oauth.py`, `scan/websocket.py` — upload/OAuth/WS
- `scan/mitb.py` — Man-in-the-Browser / BeEF-style hooks
- `scan/xss_advanced.py` — DOM/mutation/polyglot/CSP bypass
- `scan/injection_advanced.py` — LDAP/XPath/HQL/EL/JNDI/Log4j
- `scan/ssrf_advanced.py` — protocol smuggling, DNS rebinding
- `scan/client_side.py` — postMessage, tabnabbing, DOM clobbering
- `scan/file_polyglot.py` — PHP in images, SVG XSS, polyglot uploads
- `scan/img_metadata.py` — EXIF metadata injection, ImageTragick, FFmpeg HLS
- `scan/archive_attacks.py` — zip slip
- `scan/xml_attacks.py` — XXE (OOB), SVG XXE, billion laughs
- `scan/soap.py`, `scan/grpc.py` — SOAP/XML, gRPC
- `scan/mfa_bypass.py`, `scan/oauth_advanced.py`, `scan/password_spray.py`, `scan/kerberos.py`
- `scan/port_scan.py`, `scan/http3.py`, `scan/service_worker.py`, `scan/webrtc.py`
- `scan/rfi.py`, `scan/lfi_advanced.py`, `scan/cmdi_advanced.py`, `scan/nosql_advanced.py`
- `scan/prototype_pollution_advanced.py`, `scan/dom_clobbering_advanced.py`, `scan/postmessage_advanced.py`
- `scan/cors_advanced.py`, `scan/csp_bypass_advanced.py`
- `scan/http2.py`, `scan/cswsh.py`, `scan/graphql_deep.py` — HTTP/2, CSWSH, GraphQL deep
- `scan/email_injection.py`, `scan/db_exposure.py`, `scan/container.py` — email, DB, container/K8s
- `scan/tls_audit.py`, `scan/business_logic.py`, `scan/api_discovery.py`, `scan/saml_xsw.py`
- `scan/csrf.py`, `scan/cache_deception.py`, `scan/default_creds.py`, `scan/ratelimit.py`, `scan/saml.py`
- `recon/wayback.py`, `recon/dirbust.py` — archived URLs + directory brute
- `memory/pattern_db.py` — cross-target learning
- `core/cvss.py` — CVSS 3.1 scoring in reports
- `core/auth.py` — authenticated scanning (login flows, sessions, tokens) via --username/--password
- `core/scope.py` — scope verification
- `core/stealth.py` — stealth mode (UA rotation, delays, proxies)
- `agents/duplicate_checker.py` — duplicate detection (local + Hacktivity)
- `agents/poc_generator.py` — working PoC generation for EVERY finding (saved to pocs/)
- `agents/triage.py` — triage preparation + never-submit list
- `report/templates.py` — H1/Bugcrowd/Intigriti/Immunefi templates
- `agents/deterministic/stub.py` — deterministic fallback (no LLM required)
- `recon/advanced/` — JS analysis, DNS recon, favicon hash
- `exploit/` — reverse shell & webshell generators
- `redteam/` — phishing templates
- `osint/` — employee/email/breach/GitHub recon
- `cloud/` — AWS deep (S3 takeover, metadata)
- `cicd/` — GitHub Actions security
- `exfil/` — data exfiltration helpers
- `templates/` — Nuclei-style template engine
- `agents/reporter.py` — report generation

## Safety

Only scan targets you own or have written authorization to test. Unauthorized scanning is illegal.
