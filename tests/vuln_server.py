"""Realistic Vulnerable + Stateful WAF + False-Positive Trap HTTP Server for Live E2E Verification.

Includes:
  1. Stateful Cloudflare-like WAF:
     - Blocks default scanner UAs (`sqlmap`, `nikto`, `python-requests`) with HTTP 403 + `cf-ray` header.
     - Blocks raw SQL/XSS/CMDi strings (`' UNION `, `<script>alert`, `;id`) UNLESS polymorphic WAF tamper
       (SQL inline comment `/**/`, case/whitespace mutation, `<svg/onload=...>` / tag break, `${IFS}` / newline) is applied!
     - Rate-throttles single burned UA if explicitly requested (`/ratelimit-ua`) returning HTTP 429 until UA rotates.
  2. Genuine Exploitable Vulnerabilities:
     - `/product?id=1`         : Real in-memory `sqlite3` SQL injection (boolean + UNION + syntax error).
     - `/search?q=hello`       : Reflected HTML XSS (WAF blocks `<script>`, allows `<svg/onload=...>`).
     - `/webhook?callback=...` : Real server-side `urllib.request.urlopen()` SSRF!
     - `/diag?host=127.0.0.1`  : Real command execution simulation / subprocess (`id` + `curl <oob_url>`).
     - `/download?file=doc.txt`: Path traversal exposing real `/etc/passwd` structure.
     - `/render?tpl=hello`     : Real algebraic template evaluation (`{{7*7}}` -> `49`, `{{6*7}}` -> `42`).
     - `/admin`                : Returns HTTP 403 unless `X-Original-URL: /admin` or `X-Forwarded-For: 127.0.0.1` header set!
     - `/.env`                 : Exposed environment secrets (`AWS_SECRET_ACCESS_KEY=...`, `DB_PASSWORD=...`).
  3. Adversarial False-Positive Traps (designed to fool naive scanners & test `RAZOR` deterministic falsification!):
     - `/trap/static-sql?id=1` : Always prints `SQL syntax MySQL error` banner regardless of input (even plain alpha!).
     - `/trap/encoded-xss?q=hi`: Reflects input properly escaped via `html.escape()`.
     - `/trap/json-xss?q=hi`   : Reflects raw string inside `Content-Type: application/json` (non-executable in browser!).
     - `/trap/fake-ssrf?u=x`   : Echoes query string back without ever making an outbound HTTP request.
     - `/trap/static-ssti?t=x` : Hardcodes `Result: 49` on benign input or fails `{{6*7}} -> 42` dual algebraic test!
     - `/trap/fake-cmdi?h=x`   : Never executes anything, just prints parameter string.
"""
import html
import json
import re
import sqlite3
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BAD_SCANNER_UAS = ("python-requests", "nikto", "curl/", "go-http-client")


def _make_sqlite_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
    conn.executemany(
        "INSERT INTO products (id, name, secret) VALUES (?, ?, ?)",
        [
            (1, "Quantum Router", "pub-sku-101"),
            (2, "ZeroDay Appliance", "FLAG{sqlite_union_extracted_secret_991}"),
            (3, "Stealth Tap", "internal-only"),
        ],
    )
    conn.commit()
    return conn


class VulnLabServer:
    def __init__(self, enable_waf: bool = True):
        self.enable_waf = enable_waf
        self.db = _make_sqlite_db()
        self.db_lock = threading.Lock()
        self.ua_counts: dict[str, int] = {}
        self.lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _waf_blocks(self, path_and_query: str, headers) -> tuple[int, str] | None:
        if not self.enable_waf:
            return None
        ua = (headers.get("User-Agent") or "").lower()
        with self.lock:
            self.ua_counts[ua] = self.ua_counts.get(ua, 0) + 1
            count_for_ua = self.ua_counts[ua]

        if path_and_query.startswith("/ratelimit-ua") and count_for_ua > 2:
            return 429, "Rate limit exceeded for current User-Agent fingerprint"

        # Allow sqlmap if it sets custom browser UA (which our adapter always does via PAYLOAD_MUTEX!)
        if any(bad in ua for bad in BAD_SCANNER_UAS):
            return 403, "Attention Required! Cloudflare Ray ID: 88ab12cd99ef"

        decoded = urllib.parse.unquote_plus(path_and_query)
        # Naive WAF rules that block ONLY naive non-tampered signatures:
        # 1. Blocks exact `' UNION SELECT ` with plain spaces (bypassed by `/**/`, `%09`, `%0a`, mixed comments, OR boolean payloads!)
        if re.search(r"'\s+UNION\s+SELECT\s+", decoded):
            return 403, "Cloudflare WAF Block: Naive SQLi signature"
        # 2. Blocks literal `<script` tag (bypassed by `<svg/onload=...>`, `<img src=x onerror=...>`, attribute breakout!)
        if "<script" in decoded.lower():
            return 403, "Cloudflare WAF Block: Naive <script> tag"
        # 3. Blocks literal `;id` or `|id` with bare space `; id` unless `${IFS}`, newline `%0a`, `&&`, or `$(id)` or subshell used — allow `;curl` or `${IFS}` or `%0aid` or `|id` after tamper
        if decoded.endswith(";id") or decoded.endswith("|id"):
            return 403, "Cloudflare WAF Block: Naive `;id` signature"
        return None

    def start(self) -> str:
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8", extra_headers: dict | None = None):
                data = body.encode("utf-8", errors="ignore")
                self.send_response(code)
                self.send_header("Server", "cloudflare")
                self.send_header("CF-RAY", "89b77c12a001-SYD")
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                for k, v in (extra_headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

                # Reverse-proxy header ACL bypass check BEFORE route dispatch (`X-Original-URL`)
                orig_url = self.headers.get("X-Original-URL") or self.headers.get("X-Rewrite-URL")
                xff = self.headers.get("X-Forwarded-For", "")

                blocked = lab._waf_blocks(self.path, self.headers)
                if blocked:
                    self._send(blocked[0], f"<html><title>Attention Required! | Cloudflare</title>{blocked[1]}</html>")
                    return

                if path == "/" or path == "/index.html":
                    if orig_url == "/admin":
                        self._send(200, "<html><h1>INTERNAL ADMIN CONSOLE</h1><p>Admin panel unlocked via X-Original-URL!</p><a href='/admin/panel?debug=1'>Debug</a></html>")
                        return
                    self._send(
                        200,
                        "<html><head><title>VulnCorp Portal</title><script src='/app.js'></script></head><body>"
                        "<a href='/product?id=1'>Products</a>"
                        "<a href='/search?q=router'>Search</a>"
                        "<a href='/webhook?callback=https://status.example'>Webhook</a>"
                        "<a href='/diag?host=127.0.0.1'>Diagnostics</a>"
                        "<a href='/download?file=readme.txt'>Docs</a>"
                        "<a href='/render?tpl=welcome'>Banner</a>"
                        "<a href='/hidden_api'>API</a>"
                        "</body></html>",
                    )
                    return

                if path == "/app.js":
                    self._send(
                        200,
                        "const endpoints = ['/product?id=1', '/admin', '/trap/static-sql?id=1'];",
                        ctype="application/javascript",
                    )
                    return

                if path == "/ratelimit-ua":
                    self._send(200, f"OK UA={self.headers.get('User-Agent', '')}")
                    return

                if path == "/.env":
                    self._send(200, "APP_ENV=production\nDB_PASSWORD=super_secret_pg_9921\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", ctype="text/plain")
                    return

                if path == "/admin" or path.rstrip("/") == "/admin":
                    if xff == "127.0.0.1" or orig_url == "/admin":
                        self._send(200, "<html><h1>INTERNAL ADMIN CONSOLE</h1><p>Role: superadmin | cluster-token=adm_99812</p></html>")
                    else:
                        self._send(403, "403 Forbidden: Edge ACL denied external IP")
                    return

                # Hidden parameter endpoint discoverable by `.bin/arjun` (`debug` or `id`)
                if path == "/hidden_api":
                    if "debug" in qs:
                        self._send(200, f'{{"status":"debug_mode_enabled","debug":{json.dumps(qs["debug"][0])},"internal_host":"10.20.0.5"}}', ctype="application/json")
                    else:
                        self._send(200, '{"status":"ok"}', ctype="application/json")
                    return

                # 1. Genuine SQLite SQLi
                if path == "/product":
                    raw_id = qs.get("id", ["1"])[0]
                    # Strip SQL inline comments `/**/` into space so sqlite3 executes standard tamper scripts realistically
                    normalized_sql = raw_id.replace("/**/", " ")
                    try:
                        with lab.db_lock:
                            rows = lab.db.execute(f"SELECT id, name, secret FROM products WHERE id = '{normalized_sql}'").fetchall()
                        html_rows = "".join(f"<li>{r[0]} - {r[1]} ({r[2]})</li>" for r in rows)
                        self._send(200, f"<html><body><h2>Products</h2><ul>{html_rows}</ul></body></html>")
                    except Exception as exc:
                        self._send(500, f"<html><body>Database error: sqlite3.OperationalError: {html.escape(str(exc))}</body></html>")
                    return

                # 2. Genuine Reflected XSS
                if path == "/search":
                    q = qs.get("q", [""])[0]
                    self._send(200, f"<html><body><h2>Search results for: {q}</h2></body></html>")
                    return

                # 3. Genuine Server-Side Request Forgery (real outbound HTTP request!)
                if path == "/webhook":
                    cb = qs.get("callback", [""])[0]
                    if cb.startswith(("http://127.0.0.1:", "http://localhost:")):
                        try:
                            with urllib.request.urlopen(cb, timeout=3) as resp:
                                body = resp.read(300).decode("utf-8", errors="ignore")
                            self._send(200, f"<html><body>Webhook response: {html.escape(body)}</body></html>")
                            return
                        except Exception as exc:
                            self._send(502, f"Webhook error: {html.escape(str(exc))}")
                            return
                    self._send(200, "<html><body>Webhook queued</body></html>")
                    return

                # 4. Genuine OS Command Injection (safe deterministic execution + real OOB curl beacon support!)
                if path == "/diag":
                    host_arg = qs.get("host", ["127.0.0.1"])[0]
                    clean_cmd = host_arg.replace("${IFS}", " ")
                    # Support OOB callback (`curl -s http://127.0.0.1:...`)
                    m_curl = re.search(r"curl\s+(?:-s\s+)?(http://127\.0\.0\.1:\d+/\S+)", clean_cmd)
                    if m_curl:
                        try:
                            urllib.request.urlopen(m_curl.group(1), timeout=2).read()
                        except Exception:
                            pass
                    if re.search(r"(?:;|\||&&|\n|`|\$\()\s*(?:/usr/bin/)?id\b", clean_cmd):
                        self._send(200, f"PING 127.0.0.1: 56 data bytes\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n")
                        return
                    # Also handle commix echo-based calculation probes (`echo ...`)
                    m_echo = re.search(r"echo\s+([A-Za-z0-9_]+)", clean_cmd)
                    if m_echo and any(sep in clean_cmd for sep in (";", "|", "&&", "\n", "$(")):
                        self._send(200, f"PING ok\n{m_echo.group(1)}\n")
                        return
                    self._send(200, f"PING {html.escape(host_arg)}: 56 data bytes\n64 bytes from 127.0.0.1: time=0.04 ms\n")
                    return

                # 5. Genuine Path Traversal / LFI
                if path == "/download":
                    fn = urllib.parse.unquote(qs.get("file", ["readme.txt"])[0])
                    if "etc/passwd" in fn:
                        self._send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", ctype="text/plain")
                        return
                    self._send(200, "VulnCorp Public Documentation v2.1\n", ctype="text/plain")
                    return

                # 6. Genuine SSTI (evaluates arithmetic expressions inside `{{...}}`)
                if path == "/render":
                    tpl = qs.get("tpl", ["welcome"])[0]
                    m_expr = re.search(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", tpl)
                    if m_expr:
                        val = int(m_expr.group(1)) * int(m_expr.group(2))
                        out = tpl[:m_expr.start()] + str(val) + tpl[m_expr.end():]
                        self._send(200, f"<html><body>Banner: {html.escape(out)}</body></html>")
                        return
                    self._send(200, f"<html><body>Banner: {html.escape(tpl)}</body></html>")
                    return

                # ==================== FALSE-POSITIVE TRAPS FOR RAZOR ====================
                if path == "/trap/static-sql":
                    self._send(500, "<html><body>Warning: SQL syntax MySQL error near line 1 (cached maintenance banner)</body></html>")
                    return
                if path == "/trap/encoded-xss":
                    q = html.escape(qs.get("q", [""])[0], quote=True)
                    self._send(200, f"<html><body>Safe search: {q}</body></html>")
                    return
                if path == "/trap/json-xss":
                    q = qs.get("q", [""])[0]
                    self._send(200, json.dumps({"query": q}), ctype="application/json")
                    return
                if path == "/trap/fake-ssrf":
                    u = qs.get("u", [""])[0]
                    self._send(200, f"<html><body>Requested URL string was: {html.escape(u)}</body></html>")
                    return
                if path == "/trap/static-ssti":
                    self._send(200, "<html><body>Page count: 49 items in catalog</body></html>")
                    return
                if path == "/trap/fake-cmdi":
                    h = qs.get("h", [""])[0]
                    self._send(200, f"<html><body>Host check queued for {html.escape(h)}</body></html>")
                    return

                self._send(404, "<html><body>404 Not Found</body></html>")

            def do_POST(self):
                self.do_GET()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
