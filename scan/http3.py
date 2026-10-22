"""HTTP/3 / QUIC detection."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status != 0:
        alt_svc = r.headers.get("alt-svc", "")
        if "h3" in alt_svc.lower() or "quic" in alt_svc.lower():
            findings.append(Finding(
                id="http3-{}".format(hash(url) & 0xffff),
                target=parsed.netloc,
                type="HTTP/3 (QUIC) Supported",
                severity="info",
                url=url,
                parameter="alt-svc",
                payload=alt_svc[:120],
                evidence="Server advertises HTTP/3",
                response_snippet=alt_svc[:200],
                confidence=0.9,
            ))
    log_event(parsed.netloc, "http3_scan", {"url": url, "findings": len(findings)})
    return findings
