"""HTTP client with rate limiting, retries, and evidence capture."""
import time
import threading
import requests
from core.config import MAX_RPS, REQUEST_TIMEOUT, USER_AGENT

_lock = threading.Lock()
_last = [0.0]


def _throttle():
    with _lock:
        now = time.time()
        min_gap = 1.0 / max(MAX_RPS, 0.1)
        wait = _last[0] + min_gap - now
        if wait > 0:
            time.sleep(wait)
        _last[0] = time.time()


class Response:
    def __init__(self, r, url, method="GET", payload=None):
        self.url = url
        self.method = method
        self.payload = payload
        self.status = r.status_code if r is not None else 0
        raw = dict(r.headers) if r is not None else {}
        self.headers = {k.lower(): v for k, v in raw.items()}
        self.text = r.text if r is not None else ""
        self.content = r.content if r is not None else b""
        self.elapsed = r.elapsed.total_seconds() if r is not None else 0
        self.ok = r is not None and r.status_code < 400
        self.error = None

    def snippet(self, n=400):
        t = self.text or ""
        return t[:n].replace("\n", " ")


def request(method, url, **kw):
    _throttle()
    kw.setdefault("timeout", REQUEST_TIMEOUT)
    kw.setdefault("headers", {})
    kw["headers"].setdefault("User-Agent", USER_AGENT)
    kw.setdefault("allow_redirects", False)
    # merge authenticated session if present
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
        return Response(r, url, method, payload)
    except Exception as e:
        resp = Response(None, url, method, payload)
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
