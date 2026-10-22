"""Command injection scanner."""
import urllib.parse, time
from core.http import get
from scan.payloads import CMDI
from core.findings import Finding
from core.memory import log_event

MARKERS = ["uid=", "gid=", "root", "www-data", "nt authority", "volume serial"]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        for payload in CMDI:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            start = time.time()
            r = get(new_url)
            elapsed = time.time() - start
            if r.status == 0:
                continue
            text = r.text or ""
            if any(m in text for m in MARKERS):
                findings.append(Finding(
                    id=f"cmdi-{hash(new_url+payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Command Injection",
                    severity="critical",
                    url=new_url,
                    parameter=param,
                    payload=payload,
                    evidence="Command output markers in response",
                    response_snippet=r.snippet(300),
                    confidence=0.85,
                ))
                break
            # time-based
            if "sleep" in payload or "delay" in payload.lower():
                pass
    log_event(parsed.netloc, "cmdi_scan", {"url": url, "findings": len(findings)})
    return findings
