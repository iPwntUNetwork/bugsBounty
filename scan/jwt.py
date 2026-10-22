"""JWT weakness scanner (passive + active)."""
import base64, json, urllib.parse
from core.http import get
from core.findings import Finding
from core.memory import log_event

def _b64d(s):
    s += "=" * (-len(s) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return None

def scan_text(text, url):
    findings = []
    import re
    for m in re.finditer(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", text or ""):
        tok = m.group(0)
        parts = tok.split(".")
        if len(parts) < 2:
            continue
        header = _b64d(parts[0])
        payload = _b64d(parts[1])
        if not header:
            continue
        alg = header.get("alg", "")
        if alg.lower() == "none":
            findings.append(Finding(
                id=f"jwt-none-{hash(tok) & 0xffff:x}",
                target=urllib.parse.urlparse(url).netloc,
                type="JWT alg=none",
                severity="critical",
                url=url,
                parameter="token",
                payload=tok[:60],
                evidence="JWT uses alg=none",
                response_snippet=str(header),
                confidence=0.95,
            ))
        if alg.upper().startswith("HS") and "kid" in header:
            findings.append(Finding(
                id=f"jwt-kid-{hash(tok) & 0xffff:x}",
                target=urllib.parse.urlparse(url).netloc,
                type="JWT kid injection candidate",
                severity="medium",
                url=url,
                parameter="token",
                payload=tok[:60],
                evidence=f"alg={alg}, kid={header.get('kid')}",
                response_snippet=str(header),
                confidence=0.5,
            ))
        # weak secret hint: if exp missing
        if payload and "exp" not in payload:
            findings.append(Finding(
                id=f"jwt-noexp-{hash(tok) & 0xffff:x}",
                target=urllib.parse.urlparse(url).netloc,
                type="JWT missing exp",
                severity="low",
                url=url,
                parameter="token",
                payload=tok[:60],
                evidence="No expiration claim",
                response_snippet=str(payload)[:200],
                confidence=0.9,
            ))
    log_event(urllib.parse.urlparse(url).netloc, "jwt_scan", {"url": url, "findings": len(findings)})
    return findings


def scan_url(url):
    r = get(url)
    if r.status == 0:
        return []
    return scan_text(r.text + " " + str(r.headers), url)
