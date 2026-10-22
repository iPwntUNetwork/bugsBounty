"""Host header injection / password reset poisoning scanner."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    canary = "evil.example.com"
    # Host header override
    r = get(url, headers={"Host": canary})
    if r.status != 0 and canary in (r.text or ""):
        findings.append(Finding(
            id=f"hosthdr-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="Host Header Injection",
            severity="medium",
            url=url,
            parameter="Host",
            payload=canary,
            evidence="Canary reflected in response",
            response_snippet=r.snippet(200),
            confidence=0.6,
        ))
    # X-Forwarded-Host
    r = get(url, headers={"X-Forwarded-Host": canary})
    if r.status != 0 and canary in (r.text or ""):
        findings.append(Finding(
            id=f"xfh-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="Host Header Injection (X-Forwarded-Host)",
            severity="medium",
            url=url,
            parameter="X-Forwarded-Host",
            payload=canary,
            evidence="Canary reflected",
            response_snippet=r.snippet(200),
            confidence=0.6,
        ))
    log_event(parsed.netloc, "host_header_scan", {"url": url, "findings": len(findings)})
    return findings
