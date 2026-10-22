"""CRLF injection scanner."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        for payload in ["%0d%0aX-CRLF: injected", "%0d%0a%0d%0a<html>", "%0aSet-Cookie: crlf=injected"]:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            # check if injected header present
            if "x-crlf" in {k.lower() for k in r.headers} or "crlf=injected" in r.headers.get("set-cookie", ""):
                findings.append(Finding(
                    id=f"crlf-{hash(new_url+payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="CRLF Injection",
                    severity="medium",
                    url=new_url,
                    parameter=param,
                    payload=payload,
                    evidence="Injected header/cookie present",
                    response_snippet=r.snippet(200),
                    confidence=0.85,
                ))
                break
            # check body reflection of CRLF
            if "%0d%0a" not in payload and "injected" in (r.text or ""):
                pass
    log_event(parsed.netloc, "crlf_scan", {"url": url, "findings": len(findings)})
    return findings
