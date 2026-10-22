"""CSRF scanner."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse, re

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status == 0:
        return findings
    body = r.text or ""
    # forms without CSRF token
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(body, "lxml")
    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        if method != "POST":
            continue
        inputs = [i.get("name", "") for i in form.find_all("input")]
        token_fields = [n for n in inputs if "csrf" in n.lower() or "token" in n.lower() or "_token" in n.lower()]
        if not token_fields:
            action = urllib.parse.urljoin(url, form.get("action", ""))
            findings.append(Finding(
                id=f"csrf-{hash(action) & 0xffff:x}",
                target=parsed.netloc,
                type="Missing CSRF Token",
                severity="medium",
                url=action,
                parameter="form",
                payload="",
                evidence=f"POST form at {action} has no CSRF token",
                response_snippet=str(form)[:200],
                confidence=0.7,
            ))
    # SameSite cookie
    cookies = r.headers.get("set-cookie", "")
    if cookies and "samesite" not in cookies.lower():
        findings.append(Finding(
            id=f"csrf-cookie-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="CSRF (SameSite missing)",
            severity="low",
            url=url,
            parameter="cookie",
            payload="",
            evidence="Session cookie lacks SameSite",
            response_snippet=cookies[:200],
            confidence=0.8,
        ))
    log_event(parsed.netloc, "csrf_scan", {"url": url, "findings": len(findings)})
    return findings
