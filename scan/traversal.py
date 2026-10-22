"""Path traversal / LFI scanner."""
import urllib.parse
from core.http import get
from scan.payloads import TRAVERSAL
from core.findings import Finding
from core.memory import log_event

MARKERS = ["root:x:0:0", "daemon:x:", "[extensions]", "for 16-bit app support", "bin/bash", "nobody:x:"]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        for payload in TRAVERSAL:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            text = r.text or ""
            if any(m in text for m in MARKERS):
                findings.append(Finding(
                    id=f"lfi-{hash(new_url+payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Path Traversal / LFI",
                    severity="high",
                    url=new_url,
                    parameter=param,
                    payload=payload,
                    evidence="File content markers in response",
                    response_snippet=r.snippet(300),
                    confidence=0.85,
                ))
                break
    log_event(parsed.netloc, "traversal_scan", {"url": url, "findings": len(findings)})
    return findings
