"""HTTP/2 attacks: rapid reset, smuggling, HPACK bomb."""
from core.http import get, request
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # HTTP/2 rapid reset (CVE-2023-44487) - check if server supports H2
    try:
        import httpx
        # probe H2
        r = get(url)
        if "h2" in (r.headers.get("alt-svc", "") or "").lower() or r.headers.get("http2", ""):
            findings.append(Finding(
                id="http2-supported-{}".format(hash(url) & 0xffff),
                target=parsed.netloc,
                type="HTTP/2 Supported (rapid reset candidate)",
                severity="info",
                url=url,
                parameter="protocol",
                payload="HTTP/2",
                evidence="Server supports HTTP/2; test rapid reset (CVE-2023-44487)",
                response_snippet="",
                confidence=0.5,
            ))
    except Exception:
        pass
    # HTTP/2 smuggling via CRLF in headers
    r = get(url, headers={"Foo": "bar\r\nTransfer-Encoding: chunked"})
    if r.status != 0 and r.status not in (400,):
        findings.append(Finding(
            id="http2-smuggle-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="HTTP/2 Header Injection (potential)",
            severity="medium",
            url=url,
            parameter="header",
            payload="CRLF in header",
            evidence="Server accepted CRLF in header",
            response_snippet=r.snippet(200),
            confidence=0.4,
        ))
    # HPACK bomb (large header)
    big = "A" * 8000
    r = get(url, headers={"X-Big": big})
    if r.status == 0 or r.status >= 500:
        findings.append(Finding(
            id="hpack-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="HPACK Bomb (potential DoS)",
            severity="low",
            url=url,
            parameter="header",
            payload="8000-byte header",
            evidence="Server errored on large header",
            response_snippet=r.snippet(100) if r.status != 0 else "timeout/error",
            confidence=0.4,
        ))
    log_event(parsed.netloc, "http2_scan", {"url": url, "findings": len(findings)})
    return findings
