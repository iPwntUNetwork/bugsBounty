"""Prototype pollution scanner (client-side via query params)."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

PAYLOADS = [
    "__proto__[polluted]=1",
    "constructor[prototype][polluted]=1",
    "__proto__.polluted=1",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    base = parsed._replace(query="").geturl()
    for payload in PAYLOADS:
        test_url = base + "?" + payload
        r = get(test_url)
        if r.status == 0:
            continue
        # heuristic: if response contains polluted or script evaluates
        if "polluted" in (r.text or "").lower():
            findings.append(Finding(
                id=f"proto-{hash(test_url) & 0xffff:x}",
                target=parsed.netloc,
                type="Prototype Pollution (potential)",
                severity="medium",
                url=test_url,
                parameter="__proto__",
                payload=payload,
                evidence="Polluted marker reflected",
                response_snippet=r.snippet(200),
                confidence=0.4,
            ))
            break
    log_event(parsed.netloc, "proto_pollution_scan", {"url": url, "findings": len(findings)})
    return findings
