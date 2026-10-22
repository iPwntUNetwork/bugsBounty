"""Security headers audit."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

REQUIRED = [
    ("content-security-policy", "Missing Content-Security-Policy", "low"),
    ("strict-transport-security", "Missing HSTS", "low"),
    ("x-frame-options", "Missing X-Frame-Options (clickjacking)", "low"),
    ("x-content-type-options", "Missing X-Content-Type-Options", "low"),
    ("referrer-policy", "Missing Referrer-Policy", "info"),
    ("permissions-policy", "Missing Permissions-Policy", "info"),
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status == 0:
        return findings
    h = {k.lower(): v for k, v in r.headers.items()}
    for hdr, title, sev in REQUIRED:
        if hdr not in h:
            findings.append(Finding(
                id=f"hdr-{hdr}-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type=title,
                severity=sev,
                url=url,
                parameter="header",
                payload="",
                evidence=f"Header '{hdr}' not present",
                response_snippet=r.snippet(120),
                confidence=0.95,
            ))
    # info disclosure
    for hdr in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
        if hdr in h:
            findings.append(Finding(
                id=f"info-{hdr}-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="Information Disclosure (version)",
                severity="info",
                url=url,
                parameter="header",
                payload="",
                evidence=f"{hdr}: {h[hdr]}",
                response_snippet=f"{hdr}: {h[hdr]}",
                confidence=0.99,
            ))
    log_event(parsed.netloc, "headers_scan", {"url": url, "findings": len(findings)})
    return findings
