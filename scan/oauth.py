"""OAuth misconfiguration scanner."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # open redirect in redirect_uri
    for payload in ["https://evil.example.com", "https://evil.example.com/callback"]:
        r = get(url, params={"redirect_uri": payload, "client_id": "test", "response_type": "code"})
        if r.status in (301, 302, 303, 307, 308):
            loc = r.headers.get("location", "")
            if "evil.example.com" in loc:
                findings.append(Finding(
                    id=f"oauth-redirect-{hash(url) & 0xffff:x}",
                    target=parsed.netloc,
                    type="OAuth Open Redirect (redirect_uri)",
                    severity="medium",
                    url=url,
                    parameter="redirect_uri",
                    payload=payload,
                    evidence=f"Location: {loc}",
                    response_snippet=f"HTTP {r.status} Location: {loc}",
                    confidence=0.8,
                ))
                break
    # state missing
    r = get(url, params={"client_id": "test", "response_type": "code", "redirect_uri": "https://example.com/cb"})
    if r.status == 200 and "state" not in (r.text or "").lower():
        findings.append(Finding(
            id=f"oauth-nostate-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="OAuth Missing State (CSRF)",
            severity="medium",
            url=url,
            parameter="state",
            payload="",
            evidence="Authorization endpoint does not require state",
            response_snippet=r.snippet(200),
            confidence=0.5,
        ))
    log_event(parsed.netloc, "oauth_scan", {"url": url, "findings": len(findings)})
    return findings
