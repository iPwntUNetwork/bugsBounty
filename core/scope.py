"""Engagement scope control — nothing outside the target's own domain is ever touched.

The policy is derived from the active target:

  * the target host itself,
  * its registrable domain (`app.example.com` -> `example.com`) and therefore its
    sibling subdomains, unless strict mode is on,
  * anything the operator explicitly allowed (`/scope allow ...`),
  * loopback + our own tooling endpoints (local lab, OOB listener, BeEF C2, LLM APIs).

Everything else — third-party sites, CDNs, ad networks, unrelated domains that a
crawler or a passive source stumbled onto — is **blocked before any packet is sent**.

Enforcement points:
  * `core/http.py` refuses out-of-scope HTTP requests (returns a synthetic 0-status response),
  * `tools/registry.exec_binary()` refuses to launch any `.bin/` tool pointed at a
    foreign host (sqlmap, dalfox, httpx, katana, ffuf, ...),
  * recon/hunt/escalate filter discovered assets before they reach a scanner.
"""
import json
import re
import threading
import time
import urllib.parse
from collections import deque

from core.config import HOME

SCOPE_FILE = HOME / "scope.json"

# Public suffixes that need three labels for the registrable domain (example.co.uk).
_MULTI_LABEL_SUFFIXES = {
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "or.jp",
    "co.kr", "or.kr",
    "com.br", "com.cn", "com.mx", "com.sg", "com.tr", "com.hk", "com.tw",
    "co.za", "co.in", "co.il", "com.ar", "com.pl", "com.ua",
}

# Infrastructure we own or legitimately query *about* the target. Never scanned.
INFRA_HOSTS = {
    "localhost",
    "crt.sh",
    "web.archive.org",
    "archive.org",
    "api.hackerone.com",
    "api.groq.com",
    "api.x.ai",
    "api.openai.com",
    "interactsh.app",
    "oast.pro", "oast.fun", "oast.me", "oast.live", "oast.site", "oast.online",
}

# Big public sites that are never a legitimate scan target by accident.
DEFAULT_DENY = ("google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com")

_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\-]{1,63}(?:\.(?!-)[A-Za-z0-9\-]{1,63})+\.?$")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def host_of(value) -> str:
    """Extract a lowercase host from a URL, `host:port`, or bare hostname."""
    if not value:
        return ""
    raw = str(value).strip()
    if raw.startswith("//"):
        raw = "http:" + raw
    if _URL_RE.match(raw):
        parsed = urllib.parse.urlparse(raw)
    else:
        parsed = urllib.parse.urlparse("//" + raw.split("/", 1)[0])
    host = (parsed.hostname or "").strip().strip("[]").lower().rstrip(".")
    if not host:
        # bare hostname fallback (e.g. "example.com/path")
        host = raw.split("/", 1)[0].split("@")[-1].split(":")[0].strip("[]").lower().rstrip(".")
    return host


def is_ip(host: str) -> bool:
    return bool(_IP_RE.match(host or "")) or ":" in (host or "") and all(c in "0123456789abcdef:" for c in host)


def is_loopback(host: str) -> bool:
    h = (host or "").lower()
    return h in ("localhost", "::1", "0.0.0.0") or h.startswith("127.")


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without a full public-suffix list."""
    h = (host or "").lower().strip(".")
    if not h or is_ip(h):
        return h
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    if ".".join(parts[-2:]) in _MULTI_LABEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _norm_pattern(pattern: str) -> str:
    p = (pattern or "").strip().lower()
    if "://" in p:
        p = host_of(p)
    return p.strip(".").strip("*.")


def _matches(host: str, patterns) -> str:
    """Return the matching pattern (or '') — exact host or subdomain of a pattern."""
    for raw in patterns:
        pat = _norm_pattern(raw)
        if not pat:
            continue
        if host == pat or host.endswith("." + pat):
            return raw
    return ""


class ScopePolicy:
    """Allow/deny decision engine bound to one engagement target."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.target_url = ""
        self.target_host = ""
        self.target_registrable = ""
        self.subdomains = True
        self.allow: set[str] = set()
        self.deny: set[str] = set(DEFAULT_DENY)
        self.blocked: deque = deque(maxlen=60)
        self.allowed_count = 0
        self.blocked_count = 0
        self.last_block_at = 0.0
        self._load_persisted()

    # -- persistence -----------------------------------------------------
    def _load_persisted(self) -> None:
        data = {}
        try:
            if SCOPE_FILE.exists():
                data = json.loads(SCOPE_FILE.read_text() or "{}")
        except Exception:
            data = {}
        for item in data.get("in_scope") or []:
            pat = _norm_pattern(str(item))
            if pat and not is_loopback(pat):
                self.allow.add(pat)
        for item in data.get("out_of_scope") or []:
            pat = _norm_pattern(str(item))
            if pat:
                self.deny.add(pat)

    def _persist(self) -> None:
        try:
            SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
            SCOPE_FILE.write_text(json.dumps({
                "in_scope": sorted(self.allow),
                "out_of_scope": sorted(self.deny),
            }, indent=2))
        except Exception:
            pass

    # -- target ----------------------------------------------------------
    def set_target(self, url_or_host: str) -> dict:
        raw = (url_or_host or "").strip()
        if raw and "://" not in raw and not raw.startswith("//"):
            raw = f"http://{raw}"
        host = host_of(raw)
        with self._lock:
            self.target_url = raw
            self.target_host = host
            self.target_registrable = registrable_domain(host)
            self.blocked.clear()
            self.blocked_count = 0
            self.allowed_count = 0
        return self.snapshot()

    def clear(self) -> None:
        with self._lock:
            self.target_url = ""
            self.target_host = ""
            self.target_registrable = ""
            self.blocked.clear()
            self.blocked_count = 0
            self.allowed_count = 0

    def ensure_target(self, url_or_host: str) -> dict:
        """Adopt a target only when none is set (CLI entry points)."""
        if not self.enforced:
            return self.set_target(url_or_host)
        return self.snapshot()

    @property
    def enforced(self) -> bool:
        return bool(self.target_host)

    # -- rules -----------------------------------------------------------
    def add_allow(self, pattern: str, persist: bool = True) -> str:
        pat = _norm_pattern(pattern)
        if not pat:
            return ""
        with self._lock:
            self.allow.add(pat)
            self.deny.discard(pat)
        if persist:
            self._persist()
        return pat

    def add_deny(self, pattern: str, persist: bool = True) -> str:
        pat = _norm_pattern(pattern)
        if not pat:
            return ""
        with self._lock:
            self.deny.add(pat)
        if persist:
            self._persist()
        return pat

    def remove_allow(self, pattern: str, persist: bool = True) -> bool:
        pat = _norm_pattern(pattern)
        with self._lock:
            existed = pat in self.allow
            self.allow.discard(pat)
        if persist:
            self._persist()
        return existed

    def remove_deny(self, pattern: str, persist: bool = True) -> bool:
        pat = _norm_pattern(pattern)
        with self._lock:
            existed = pat in self.deny
            self.deny.discard(pat)
        if persist:
            self._persist()
        return existed

    def set_subdomains(self, enabled: bool) -> None:
        with self._lock:
            self.subdomains = bool(enabled)

    # -- decision --------------------------------------------------------
    def explain(self, value, record: bool = True, source: str = "") -> tuple[bool, str]:
        """(allowed, human reason) for a URL or host."""
        host = host_of(value)
        if not host:
            return True, "unparseable target — not enforced"

        if is_loopback(host):
            with self._lock:
                self.allowed_count += 1
            return True, "loopback / local lab"

        infra = _matches(host, INFRA_HOSTS)
        if infra:
            with self._lock:
                self.allowed_count += 1
            return True, f"tooling endpoint ({infra})"

        if not self.enforced:
            return True, "no target set — scope not enforced"

        denied = _matches(host, self.deny)
        if denied:
            return self._block(host, f"explicitly out of scope ({denied})", source, value, record)

        allowed = _matches(host, self.allow)
        if allowed:
            with self._lock:
                self.allowed_count += 1
            return True, f"explicitly allowed ({allowed})"

        if host == self.target_host:
            with self._lock:
                self.allowed_count += 1
            return True, "target host"

        if self.subdomains and self.target_registrable and not is_ip(host):
            if registrable_domain(host) == self.target_registrable:
                with self._lock:
                    self.allowed_count += 1
                return True, f"same domain as target ({self.target_registrable})"

        return self._block(host, f"not part of {self.target_registrable or self.target_host}", source, value, record)

    def _block(self, host: str, reason: str, source: str, value, record: bool) -> tuple[bool, str]:
        with self._lock:
            self.blocked_count += 1
            self.last_block_at = time.time()
            if record:
                self.blocked.append({
                    "host": host,
                    "value": str(value)[:300],
                    "reason": reason,
                    "source": source or "unknown",
                    "ts": round(time.time(), 3),
                })
        return False, reason

    def is_in_scope(self, value, record: bool = True, source: str = "") -> bool:
        return self.explain(value, record=record, source=source)[0]

    def allows_host(self, host: str, source: str = "", record: bool = True) -> bool:
        return self.is_in_scope(host, record=record, source=source)

    def filter_urls(self, urls, source: str = "filter") -> list:
        """Keep only in-scope entries, recording what was dropped."""
        out = []
        for u in urls or []:
            if self.is_in_scope(u, source=source):
                out.append(u)
        return out

    def screen_command(self, binary: str, args=None, stdin_text: str | None = None) -> dict | None:
        """Refuse to launch a tool pointed at a foreign host. Returns the violation, if any."""
        if not self.enforced:
            return None
        tokens = []
        for a in args or []:
            tok = str(a).strip()
            if not tok or tok.startswith("-"):
                continue
            if _URL_RE.match(tok):
                tokens.append(tok)
            elif _HOST_RE.match(tok):
                tokens.append(tok)
        for line in (stdin_text or "").splitlines():
            tok = line.strip()
            if tok and (_URL_RE.match(tok) or _HOST_RE.match(tok)):
                tokens.append(tok)
        for tok in tokens:
            ok, reason = self.explain(tok, source=f"tool:{binary}")
            if not ok:
                return {"token": tok, "host": host_of(tok), "reason": reason}
        return None

    # -- reporting -------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "target": self.target_url,
                "host": self.target_host,
                "registrable": self.target_registrable,
                "subdomains": self.subdomains,
                "enforced": self.enforced,
                "allow": sorted(self.allow),
                "deny": sorted(self.deny),
                "allowed_count": self.allowed_count,
                "blocked_count": self.blocked_count,
                "blocked": list(reversed(self.blocked))[:20],
            }

    def summary(self) -> str:
        s = self.snapshot()
        if not s["enforced"]:
            return "scope: no target set (unrestricted)"
        patterns = s["host"]
        if s["subdomains"] and s["registrable"] and not is_ip(s["host"]):
            patterns = f"{s['registrable']} (+ subdomains)"
        extra = f" +{len(s['allow'])} allowed" if s["allow"] else ""
        blocked = f" · {s['blocked_count']} blocked" if s["blocked_count"] else ""
        return f"scope: {patterns}{extra}{blocked}"


SCOPE = ScopePolicy()


# ---- backwards-compatible helpers (older modules import these) -----------
def in_scope(asset) -> bool:
    return SCOPE.is_in_scope(asset)


def is_allowed(asset) -> bool:
    return SCOPE.is_in_scope(asset)


def check_asset(asset):
    ok, reason = SCOPE.explain(asset)
    return ok, (f"Out of scope — {reason}" if not ok else f"In scope — {reason}")


def load_scope() -> dict:
    return {"in_scope": sorted(SCOPE.allow), "out_of_scope": sorted(SCOPE.deny)}


def check_hackerone(program, asset):
    """Ask HackerOne whether an asset belongs to a program (never scans anything)."""
    from core.http import get

    err = "unknown"
    try:
        r = get(f"https://api.hackerone.com/v1/hackers/programs/{program}", timeout=20, scope_exempt=True)
        if r.status == 200:
            data = r.json() if hasattr(r, "json") else {}
            scopes = []
            if "relationships" in data:
                for s in data["relationships"].get("structured_scopes", {}).get("data", []):
                    scopes.append(s.get("attributes", {}).get("asset_identifier", ""))
            for s in scopes:
                if asset in s or s in asset:
                    return True, f"In scope: {s}"
            return False, f"Not in scope. Known: {scopes[:5]}"
    except Exception as e:
        err = str(e)
    return None, f"Could not verify (manual check required): {err}"


def verify(target, program=None):
    if program:
        return check_hackerone(program, target)
    return check_asset(target)
