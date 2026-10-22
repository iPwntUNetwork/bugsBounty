"""Rate limit bypass scanner."""
from core.http import get, request
from core.findings import Finding
from core.memory import log_event
import urllib.parse, time

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # baseline: hit endpoint many times
    statuses = []
    for _ in range(5):
        r = get(url)
        statuses.append(r.status)
    if 429 not in statuses:
        # no rate limit observed; try bypass headers anyway
        pass
    for h in BYPASS_HEADERS:
        r = get(url, headers=h)
        if r.status != 0 and r.status != 429:
            # if original was 429, bypass succeeded
            orig = get(url)
            if orig.status == 429 and r.status == 200:
                findings.append(Finding(
                    id=f"ratelimit-bypass-{hash(str(h)) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Rate Limit Bypass",
                    severity="medium",
                    url=url,
                    parameter="header",
                    payload=str(h),
                    evidence=f"Header bypassed 429 (-> {r.status})",
                    response_snippet=r.snippet(200),
                    confidence=0.7,
                ))
    log_event(parsed.netloc, "ratelimit_scan", {"url": url, "findings": len(findings)})
    return findings
