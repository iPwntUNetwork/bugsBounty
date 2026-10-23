"""HTTP client with rate limiting, browser UA rotation, 429 burn recovery, and raw request capture."""
import threading
import time
import urllib.parse
import requests
from core.config import CFG, MAX_RPS, REQUEST_TIMEOUT, STEALTH_MODE
from core.stealth import select_browser_profile, burn_ua, get_proxy

_lock = threading.Lock()
_last = [0.0]


class _CIDict(dict):
    """Case-insensitive header mapping supporting both lowercase and canonical lookups."""

    def __init__(self, data=None):
        super().__init__()
        for k, v in (data or {}).items():
            self[k] = v

    def __setitem__(self, key, value):
        super().__setitem__(str(key).lower(), value)

    def __getitem__(self, key):
        return super().__getitem__(str(key).lower())

    def __contains__(self, key):
        return super().__contains__(str(key).lower())

    def get(self, key, default=None):
        return super().get(str(key).lower(), default)


def _throttle():
    with _lock:
        rps = float(CFG.get("rate_limit") or MAX_RPS or 25.0)
        now = time.time()
        min_gap = 1.0 / max(rps, 0.1)
        wait = _last[0] + min_gap - now
        if wait > 0:
            time.sleep(wait)
        _last[0] = time.time()


class Response:
    def __init__(self, r, url, method="GET", payload=None, req_headers=None):
        self.url = url
        self.method = method
        self.payload = payload
        self.status = r.status_code if r is not None else 0
        raw = dict(r.headers) if r is not None else {}
        self.headers = _CIDict(raw)
        self.text = r.text if r is not None else ""
        self.content = r.content if r is not None else b""
        self.elapsed = r.elapsed.total_seconds() if r is not None else 0
        self.ok = r is not None and r.status_code < 400
        self.error = None
        parsed = urllib.parse.urlparse(url)
        pq = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        hdr_block = "\n".join(f"{k}: {v}" for k, v in (req_headers or {}).items())
        self.raw_request = f"{method.upper()} {pq} HTTP/1.1\nHost: {parsed.netloc}\n{hdr_block}".strip()

    def json(self):
        import json
        return json.loads(self.text or "{}")

    def snippet(self, n=400):
        t = self.text or ""
        return t[:n].replace("\n", " ")


def request(method, url, **kw):
    _throttle()
    kw.setdefault("timeout", CFG.get("timeout", REQUEST_TIMEOUT))
    hdrs = dict(kw.get("headers") or {})
    host = urllib.parse.urlparse(url).netloc or "global"
    if CFG.get("stealth", STEALTH_MODE):
        prof = select_browser_profile(host)
        for hk, hv in prof.get("headers", {}).items():
            hdrs.setdefault(hk, hv)
        hdrs.setdefault("User-Agent", prof["ua"])
    kw["headers"] = hdrs
    kw.setdefault("allow_redirects", False)
    proxy = CFG.get("proxy") or get_proxy()
    if proxy and "proxies" not in kw:
        kw["proxies"] = {"http": proxy, "https": proxy}

    try:
        from core.auth import get_current
        sess = get_current()
        if sess is not None and sess.logged_in:
            for k, v in (sess.headers or {}).items():
                kw["headers"].setdefault(k, v)
            if sess.cookies:
                kw.setdefault("cookies", {})
                for k, v in sess.cookies.items():
                    kw["cookies"].setdefault(k, v)
    except Exception:
        pass

    payload = kw.get("data") or kw.get("json") or kw.get("params")
    try:
        r = requests.request(method, url, **kw)
        if r.status_code == 429:
            burn_ua(host, kw["headers"].get("User-Agent", ""))
            rot = select_browser_profile(host, force_rotate=True)
            kw["headers"]["User-Agent"] = rot["ua"]
            r = requests.request(method, url, **kw)
        return Response(r, url, method, payload, req_headers=kw["headers"])
    except Exception as e:
        resp = Response(None, url, method, payload, req_headers=kw["headers"])
        resp.error = str(e)
        resp.status = 0
        return resp


def get(url, **kw):
    return request("GET", url, **kw)


def post(url, **kw):
    return request("POST", url, **kw)


def follow(url, **kw):
    kw["allow_redirects"] = True
    return request("GET", url, **kw)
