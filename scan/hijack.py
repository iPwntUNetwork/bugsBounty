"""Session/cookie hijacking, fixation, host takeover."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status == 0:
        return findings
    cookies = r.headers.get("set-cookie", "")
    # insecure cookie flags
    if cookies:
        low = cookies.lower()
        if "secure" not in low:
            findings.append(Finding(
                id=f"cookie-nosecure-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="Cookie Missing Secure Flag",
                severity="low",
                url=url,
                parameter="cookie",
                payload=cookies[:80],
                evidence="Set-Cookie lacks Secure",
                response_snippet=cookies[:200],
                confidence=0.9,
            ))
        if "httponly" not in low:
            findings.append(Finding(
                id=f"cookie-nohttponly-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="Cookie Missing HttpOnly Flag",
                severity="low",
                url=url,
                parameter="cookie",
                payload=cookies[:80],
                evidence="Set-Cookie lacks HttpOnly (XSS can steal)",
                response_snippet=cookies[:200],
                confidence=0.9,
            ))
        if "samesite" not in low:
            findings.append(Finding(
                id=f"cookie-nosamesite-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="Cookie Missing SameSite Flag",
                severity="low",
                url=url,
                parameter="cookie",
                payload=cookies[:80],
                evidence="Set-Cookie lacks SameSite (CSRF risk)",
                response_snippet=cookies[:200],
                confidence=0.9,
            ))
    # session fixation: accept session id from URL param
    for param in ["session", "sid", "sessionid", "PHPSESSID", "JSESSIONID"]:
        r2 = get(url, params={param: "FIXEDSESSION123"})
        if r2.status == 200:
            sc = r2.headers.get("set-cookie", "")
            if "FIXEDSESSION123" in sc:
                findings.append(Finding(
                    id=f"session-fixation-{param}-{hash(url) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Session Fixation",
                    severity="medium",
                    url=url,
                    parameter=param,
                    payload="FIXEDSESSION123",
                    evidence="Server accepted attacker-supplied session id",
                    response_snippet=sc[:200],
                    confidence=0.7,
                ))
    log_event(parsed.netloc, "hijack_scan", {"url": url, "findings": len(findings)})
    return findings
