"""Out-of-Band (OOB) interaction engine combining compiled `.bin/interactsh-client` + local callback server."""
import http.server
import json
import re
import socketserver
import subprocess
import threading
import time
import urllib.parse
import uuid
from core.config import OOB_HOST, OOB_PORT
from tools.registry import resolve_binary

_OOB_LOCK = threading.RLock()
_GLOBAL_OOB = None


class OOBManager:
    def __init__(self, host: str = OOB_HOST, port: int = OOB_PORT):
        self.host = host
        self.port = port
        self._httpd = None
        self._thread = None
        self._interactsh_proc = None
        self._interactsh_domain = None
        self.hits: dict[str, list[dict]] = {}
        self._lock = threading.RLock()

    def start(self):
        with self._lock:
            if self._httpd is None:
                mgr = self

                class H(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *a):
                        pass

                    def _record(self, method: str):
                        parsed = urllib.parse.urlparse(self.path)
                        m = re.search(r"/oob/([A-Za-z0-9_-]+)", parsed.path)
                        token = m.group(1) if m else parsed.path.strip("/")
                        length = int(self.headers.get("Content-Length", "0") or 0)
                        body = self.rfile.read(min(length, 8192)).decode(errors="ignore") if length else ""
                        hit = {
                            "token": token,
                            "method": method,
                            "path": self.path,
                            "remote": self.client_address[0],
                            "headers": dict(self.headers),
                            "body": body[:500],
                            "ts": time.time(),
                            "channel": "local_http_oob",
                        }
                        with mgr._lock:
                            mgr.hits.setdefault(token, []).append(hit)
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(f"oob-ack:{token}".encode())

                    def do_GET(self):
                        self._record("GET")

                    def do_POST(self):
                        self._record("POST")

                    def do_HEAD(self):
                        self._record("HEAD")

                try:
                    socketserver.ThreadingTCPServer.allow_reuse_address = True
                    httpd = socketserver.ThreadingTCPServer((self.host, self.port), H)
                except OSError:
                    httpd = socketserver.ThreadingTCPServer((self.host, 0), H)
                    self.port = httpd.server_address[1]
                self._httpd = httpd
                self._thread = threading.Thread(target=httpd.serve_forever, daemon=True, name="LocalOOBServer")
                self._thread.start()

            if self._interactsh_proc is None and self._interactsh_domain is None:
                exe = resolve_binary("interactsh-client")
                if exe:
                    try:
                        proc = subprocess.Popen(
                            [exe, "-json", "-nc"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                        self._interactsh_proc = proc
                        deadline = time.time() + 1.0

                        def _watch():
                            for line in iter(proc.stderr.readline, ""):
                                dm = re.search(r"([a-z0-9]{16,}\.[a-z0-9.-]+\.[a-z]{2,})", line, re.I)
                                if dm:
                                    with self._lock:
                                        self._interactsh_domain = dm.group(1)
                            for jline in iter(proc.stdout.readline, ""):
                                try:
                                    ev = json.loads(jline)
                                    tok = ev.get("full-id", "").split(".")[0]
                                    with self._lock:
                                        self.hits.setdefault(tok, []).append({**ev, "channel": "interactsh"})
                                except Exception:
                                    pass

                        threading.Thread(target=_watch, daemon=True, name="InteractshWatcher").start()
                        while time.time() < deadline and self._interactsh_domain is None and proc.poll() is None:
                            time.sleep(0.1)
                    except Exception:
                        self._interactsh_domain = ""

    def generate_canary(self, label: str = "probe") -> dict:
        self.start()
        token = f"{re.sub(r'[^a-z0-9]', '', label.lower())[:8]}{uuid.uuid4().hex[:10]}"
        http_callback = f"http://{self.host}:{self.port}/oob/{token}"
        oast_url = f"http://{token}.{self._interactsh_domain}" if self._interactsh_domain else None
        return {
            "token": token,
            "http_url": http_callback,
            "interactsh_url": oast_url,
            "interactsh_binary": resolve_binary("interactsh-client"),
        }

    def poll(self, token: str, wait_s: float = 0.6) -> list[dict]:
        deadline = time.time() + max(0.0, wait_s)
        while time.time() < deadline:
            with self._lock:
                if self.hits.get(token):
                    return list(self.hits[token])
            time.sleep(0.1)
        with self._lock:
            return list(self.hits.get(token, []))


def get_oob_manager() -> OOBManager:
    global _GLOBAL_OOB
    with _OOB_LOCK:
        if _GLOBAL_OOB is None:
            _GLOBAL_OOB = OOBManager()
        _GLOBAL_OOB.start()
        return _GLOBAL_OOB
