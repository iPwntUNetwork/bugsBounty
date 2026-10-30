# Complete Scanners, Modules, Plugins & Python SDK Reference

This reference catalogs **all 78 vulnerability scanners in `scan/`**, **all auxiliary offensive & recon modules across the repository**, **platform report renderers**, **how to write custom plugins & YAML templates**, **Python SDK usage**, and **the 27-test live verification suite**.

---

## 1. All 78 Vulnerability Scanners (`scan/*.py`)

Every scanner module inside `scan/` can be invoked directly via CLI:
```bash
./.venv/bin/bughunter scan <scanner_name> <target_url>
```
or imported directly in Python (`from scan import sqli; hits = sqli.scan_url(url)`).

### 1.1 Injection & Server-Side Code Execution (15 Scanners)
| Module Name | File | What It Tests |
|---|---|---|
| `sqli` | `scan/sqli.py` | Error-based, Boolean differential & UNION SQLi with `probe_with_mutex_bypass` (`scan_url`, `scan_form`) |
| `nosqli` | `scan/nosqli.py` | MongoDB/NoSQL operator injection (`$ne`, `$gt`, `$regex`) |
| `nosql_advanced` | `scan/nosql_advanced.py` | Aggregation pipeline, `$where` JS execution & timing NoSQL attacks |
| `cmdi` | `scan/cmdi.py` | OS command injection with `$IFS` / quote / subshell WAF mutex tampers |
| `cmdi_advanced` | `scan/cmdi_advanced.py` | Blind time-delay & out-of-band beacon command injection |
| `ssti` | `scan/ssti.py` | Server-Side Template Injection (`Jinja2`, `Twig`, `Freemarker`, `ERB`, `Velocity`) with clean baseline diff |
| `ssti_advanced` | `scan/ssti_advanced.py` | Template engine fingerprinting & sandbox escape chains |
| `injection_advanced` | `scan/injection_advanced.py` | LDAP, XPath, HQL, Expression Language (`EL`/`SpEL`/`OGNL`) & `JNDI`/`Log4Shell` |
| `xxe` | `scan/xxe.py` | Classic external entity file disclosure & SSRF via XML endpoints |
| `xml_attacks` | `scan/xml_attacks.py` | SVG/DOCX/XML entity expansion, XInclude & parameter entity attacks |
| `soap` | `scan/soap.py` | WSDL enumeration, SOAPAction spoofing & XML injection |
| `deser` | `scan/deser.py` | Insecure deserialization signatures (`Java`, `PHP`, `.NET`, `Python pickle`, `Node`) |
| `crlf` | `scan/crlf.py` | HTTP response splitting & header injection (`%0d%0aSet-Cookie:...`) |
| `email_injection` | `scan/email_injection.py` | SMTP/header `Bcc:`/`Cc:` injection & password reset routing manipulation |
| `ai_llm` | `scan/ai_llm.py` | AI/LLM endpoints: prompt injection, system-prompt leakage & tool-use hijacking |

### 1.2 Cross-Site Scripting, Browser & Client-Side Attacks (11 Scanners)
| Module Name | File | What It Tests |
|---|---|---|
| `xss` | `scan/xss.py` | Reflected & HTML form XSS with 24 polymorphic WAF bypass variants |
| `xss_advanced` | `scan/xss_advanced.py` | DOM XSS sinks/sources, mXSS mutation payloads, polyglots & dangling markup |
| `csp_bypass_advanced` | `scan/csp_bypass_advanced.py` | Content-Security-Policy weaknesses (`unsafe-inline`, JSONP gadgets, wildcard CDNs) |
| `dom_clobbering_advanced` | `scan/dom_clobbering_advanced.py` | Named HTML element global variable clobbering |
| `client_side` | `scan/client_side.py` | Clickjacking, reverse tabnabbing & unsafe client sinks |
| `postmessage_advanced` | `scan/postmessage_advanced.py` | `window.addEventListener('message')` missing origin validation |
| `proto_pollution` | `scan/proto_pollution.py` | Query/JSON `__proto__` & `constructor.prototype` pollution |
| `prototype_pollution_advanced` | `scan/prototype_pollution_advanced.py` | Client & Node gadget chains escalating prototype pollution to XSS/RCE |
| `mitb` | `scan/mitb.py` | Man-in-the-Browser / live BeEF hook susceptibility & form-grabbing vectors |
| `cswsh` | `scan/cswsh.py` | Cross-Site WebSocket Hijacking (missing `Origin` handshake enforcement) |
| `service_worker` | `scan/service_worker.py` | Overly broad Service Worker scope & script injection persistence |

### 1.3 SSRF, File Inclusion, Upload & Archive Attacks (9 Scanners)
| Module Name | File | What It Tests |
|---|---|---|
| `ssrf` | `scan/ssrf.py` | Server-Side Request Forgery with decimal/hex IP tampers + live `OOBManager` canary callbacks |
| `ssrf_advanced` | `scan/ssrf_advanced.py` | Cloud metadata (`169.254.169.254` IMDSv1/GCP/Azure), `gopher://`, `dict://`, DNS rebinding |
| `lfi` | `scan/lfi.py` | Local File Inclusion & WAF-evading path traversal (`....//`) |
| `traversal` | `scan/traversal.py` | Directory traversal across query parameters & path segments |
| `lfi_advanced` | `scan/lfi_advanced.py` | `php://filter` base64 source disclosure, `zip://`/`phar://` wrappers & log poisoning |
| `rfi` | `scan/rfi.py` | Remote File Inclusion via external callback URLs |
| `upload` | `scan/upload.py` | Unrestricted file upload extension/MIME bypass checks |
| `file_polyglot` | `scan/file_polyglot.py` | Valid GIF/PNG/PDF header polyglots carrying active script/server payloads |
| `archive_attacks` | `scan/archive_attacks.py` | `Zip Slip` (`../../`) symlink & tar extraction path traversal probes |

### 1.4 Authentication, Session, Access Control & Identity Protocols (14 Scanners)
| Module Name | File | What It Tests |
|---|---|---|
| `bypass_403` | `scan/bypass_403.py` | Edge proxy header (`X-Original-URL`, `X-Forwarded-For`), HTTP verb & path normalization ACL bypasses |
| `idor` | `scan/idor.py` | Broken Object Level Authorization (BOLA / sequential & UUID swap differentials) |
| `mass_assign` | `scan/mass_assign.py` | Hidden privilege fields (`role`, `isAdmin`, `plan`, `balance`) binding |
| `jwt` | `scan/jwt.py` | Passive & active JWT inspection (`alg: none`, missing expiry, sensitive claims) |
| `jwt_deep` | `scan/jwt_deep.py` | RS256→HS256 key confusion, weak HMAC secret brute-forcing, `kid` SQLi/path traversal & `jku` spoofing |
| `oauth` | `scan/oauth.py` | `redirect_uri` open bypass & missing `state` parameter checks |
| `oauth_advanced` | `scan/oauth_advanced.py` | PKCE downgrade, token leakage via `Referer`, implicit flow & scope escalation |
| `saml` | `scan/saml.py` | SAML endpoint discovery, assertion replay & recipient validation |
| `saml_xsw` | `scan/saml_xsw.py` | XML Signature Wrapping (`XSW1`–`XSW8`) comment truncation attacks |
| `mfa_bypass` | `scan/mfa_bypass.py` | Response manipulation, direct step-skipping, rate-limit absence & backup code weaknesses |
| `hijack` | `scan/hijack.py` | Session fixation, predictable tokens, insecure cookie flags & broken logout |
| `csrf` | `scan/csrf.py` | Missing anti-CSRF tokens & `SameSite` cookie protections on state-changing forms |
| `default_creds` | `scan/default_creds.py` | Non-destructive default credential fingerprints on exposed admin/dev panels |
| `password_spray` | `scan/password_spray.py` | Lockout-aware low-velocity authentication testing |

### 1.5 API, Protocol, Caching, Concurrency & Infrastructure Scanners (29 Scanners)
| Module Name | File | What It Tests |
|---|---|---|
| `api_discovery` | `scan/api_discovery.py` | OpenAPI / Swagger / `v1`–`v4` shadow API endpoint enumeration |
| `graphql` | `scan/graphql.py` | GraphQL endpoint discovery & full introspection schema extraction |
| `graphql_deep` | `scan/graphql_deep.py` | Query batching brute-force, deep nesting/alias DoS & field suggestion leakage |
| `grpc` | `scan/grpc.py` | gRPC-Web & server reflection discovery |
| `websocket` | `scan/websocket.py` | Unauthenticated WebSocket message fuzzing & origin checks |
| `webrtc` | `scan/webrtc.py` | STUN/TURN internal IP leak & signaling inspection |
| `cors` / `cors_advanced` | `scan/cors*.py` | Reflected arbitrary Origin + `Access-Control-Allow-Credentials: true`, `null` origin & regex prefix/suffix bypasses |
| `cache_poison` | `scan/cache_poison.py` | Unkeyed header (`X-Forwarded-Host`, `X-Forwarded-Scheme`) web cache poisoning |
| `cache_deception` | `scan/cache_deception.py` | Path-confusion (`/.css`, `/.js` suffix on authenticated endpoints) cache deception |
| `smuggling` | `scan/smuggling.py` | Non-destructive `CL.TE` / `TE.CL` differential timing probes |
| `http2` / `http3` | `scan/http2.py`, `http3.py` | HTTP/2 request pseudo-header smuggling indicators & HTTP/3 `Alt-Svc` QUIC audit |
| `host_header` | `scan/host_header.py` | Password-reset link poisoning & virtual-host routing bypass |
| `redirect` | `scan/redirect.py` | Open redirect (`//evil`, `https:evil`, `@` authority tricks) |
| `business_logic` | `scan/business_logic.py` | Negative quantity/price, rounding overflow & workflow step-skip probes |
| `race` | `scan/race.py` | Synchronized multi-thread single-packet-style race condition testing |
| `ratelimit` | `scan/ratelimit.py` | IP header rotation (`X-Forwarded-For`, `True-Client-IP`) rate-limit bypass |
| `files` | `scan/files.py` | Sensitive exposed files (`.env`, `.git/config`, `.DS_Store`, `phpinfo`, backups) |
| `db_exposure` | `scan/db_exposure.py` | Unauthenticated Redis, Elasticsearch, MongoDB, CouchDB, Prometheus & Adminer exposure |
| `container` | `scan/container.py` | Exposed Docker daemon API, Kubernetes kubelet/API, etcd & Helm metadata |
| `takeover` | `scan/takeover.py` | Dangling CNAME subdomain takeover fingerprints (GitHub Pages, S3, Heroku, Fastly, Azure, Vercel) |
| `img_metadata` | `scan/img_metadata.py` | EXIF/XMP metadata XSS/SSTI/GPS leakage checks |
| `headers` | `scan/headers.py` | HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options` & server version disclosure |
| `tls_audit` | `scan/tls_audit.py` | Expired/self-signed certs, SAN mismatch & weak TLS protocol versions |
| `port_scan` | `scan/port_scan.py` | Fast concurrent TCP port & banner discovery |
| `kerberos` | `scan/kerberos.py` | Internal/AD Kerberos service & SPN exposure checks |
| `waf` | `scan/waf.py` | Standalone multi-layer WAF vendor detector & bypass verifier |
| `payloads` | `scan/payloads.py` | Shared curated payload corpus across scanner modules |

---

## 2. Auxiliary Offensive Packages Across the Repo

| Package & File | Key Functions | Purpose |
|---|---|---|
| **`cloud/aws_deep.py`** | `scan_base(domain_or_url)` | Enumerates candidate AWS S3 buckets (`public-read`/`public-write` ACLs, bucket takeover) & leaked AWS key patterns |
| **`cicd/github_actions.py`** | `scan_repo(repo_path_or_url)` | Detects `${{ github.event... }}` expression command injection, `pull_request_target` pwn requests, and unpinned runner actions |
| **`osint/employees.py`** | `harvest_emails()`, `github_recon()`, `breach_check()` | Public email pattern discovery, GitHub org secret surface recon & passive OSINT |
| **`fuzz/engine.py` & `fuzz/llm_payloads.py`** | `fuzz_url()`, `differential_scan()`, `generate_payloads()` | Zero-day anomaly/differential status/length/timing fuzzer + LLM/polymorphic payload synthesis |
| **`exploit/stagers.py`, `reverse_shell.py`, `webshell.py`** | `generate_stagers()`, `generate()`, `list_shells()` | Safe verification PoC stagers (BeEF hook, SQLi proof, OOB canary) plus authorized red-team shell templates |
| **`exfil/dns_exfil.py`** | `dns_exfil()`, `http_exfil()` | Authorized red-team data-egress proof helpers over DNS labels & chunked HTTP |
| **`redteam/phishing.py`** | `generate()` | Authorized red-team awareness & pretext template builder |
| **`memory/pattern_db.py` & `core/memory.py`** | `record()`, `query()`, `top_patterns()`, `LeadBoard` | Learns which WAF tampers & bug classes succeeded across past targets to prioritize future scans |
| **`report/templates.py`** | `render(platform, finding, poc)` | Formats verified findings specifically for **HackerOne**, **Bugcrowd**, **Intigriti**, and **Immunefi** submission forms |
| **`agents/duplicate_checker.py`** | `check_hacktivity()`, `check_local()` | Checks local finding stores & public HackerOne Hacktivity to avoid submitting known duplicates |

---

## 3. Extending `bugsBounty`

### 3.1 Drop-In Custom Tool Plugins (`tools/plugins/*.py`)
Any `.py` file placed inside `tools/plugins/` is auto-discovered by `ToolRegistry.load_plugins()` and immediately available to both deterministic pipelines and LLM agent tool loops:

```python
# tools/plugins/custom_header_probe.py
from tools.registry import register_tool
from core import http

def probe_security_txt(url: str) -> dict:
    r = http.get(url.rstrip("/") + "/.well-known/security.txt")
    return {"status": r.status_code, "found": r.status_code == 200 and "Contact:" in r.text, "body": r.text[:400]}

register_tool(
    name="security_txt",
    category="recon",
    description="Check /.well-known/security.txt disclosure policy",
    fn=probe_security_txt,
    roles=["recon", "hunter"],
)
```

### 3.2 Adding Declarative YAML Templates (`templates/rules/*.yaml`)
Add any YAML rule file into `templates/rules/` — `.bin/nuclei` (`templates/engine.py`) loads it automatically:

```yaml
id: exposed-graphql-playground
info:
  name: Exposed GraphQL Playground IDE
  severity: low
requests:
  - method: GET
    path:
      - "/playground"
      - "/graphiql"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["GraphQL Playground", "GraphiQL"]
```

---

## 4. Using `bugsBounty` as a Python Library (SDK)

```python
from core.config import configure_api_key
from agents.autopilot import run_autopilot
from tests.vuln_server import VulnLabServer

# Optional: configure Grok (xai-...) or Groq (gsk_...) or Ollama programmatically
configure_api_key(api_key="xai-YOUR_KEY", model="grok-3", persist=False)

# Spin up a safe local target server (or pass any authorized URL)
lab = VulnLabServer(enable_waf=True)
target_url = lab.start()

try:
    result = run_autopilot(target_url, max_pages=25, report_out="demo_report.md")
    print("Verified findings:", [f.vuln_type for f in result["verified"]])
    print("Disproved false positives:", [f.vuln_type for f in result["disproved"]])
    print("Attack chains:", len(result["chains"]))
    print("Saved advisory:", result["report_path"])
finally:
    lab.stop()
```

---

## 5. The Live Verification Suite (`tests/test_agent_e2e.py`)

Every major guarantee in the framework is tested live (zero mocked HTTP servers!) against `VulnLabServer`:

- **Tests 01–08**: Verifies all 19 `.bin/` executables exist, all 22 `ToolRegistry` tools report `READY`, and live executions of `.bin/httpx`, `.bin/katana`, `.bin/hakrawler`, `.bin/arjun`, `.bin/ffuf`, `.bin/gobuster`, `.bin/nuclei`, and `.bin/nikto` succeed against a real target.
- **Tests 09–12**: Verifies `Cloudflare` WAF detection, `429` `User-Agent` burn & rotation, 24 polymorphic tamper scripts, and multi-threaded `PayloadMutexCoordinator` tamper promotion across worker threads.
- **Tests 13–17**: Verifies live automatic escalations (`SQLi -> .bin/sqlmap` real SQLite extraction, `XSS -> .bin/dalfox + BeefServer hook.js`, `SSRF -> real inbound OOB socket callback`, `CMDi -> .bin/commix + OOB`, and `/admin 403 -> 200 ACL bypass`).
- **Tests 18–21**: Verifies `SeparationOfDutiesError` blocks self-certification & missing provenance, verifies the deterministic verifier certifies real exploits while **disproving 6 distinct false-positive traps**, and verifies the single-agent transcript records every verdict.
- **Tests 22–29**: Verifies live Ollama tool-calling, CLI commands, attack chains + PoCs, the full single-agent `run_autopilot()`, interactive `WarRoomSession` + web console HTTP API, `Grok`/`Groq`/`OpenAI` key prefix auto-routing & secret masking, and delta-polling/socket-reset resilience.
