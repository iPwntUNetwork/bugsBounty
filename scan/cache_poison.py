"""Web cache poisoning scanner."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse, uuid

UNKEYED_HEADERS = ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Port"]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # baseline
    base_r = get(url)
    if base_r.status == 0:
        return findings
    canary = "cp" + uuid.uuid4().hex[:8]
    for h in UNKEYED_HEADERS:
        r = get(url, headers={h: canary + ".evil.example.com"})
        if r.status == 0:
            continue
        # if canary reflected in response or cache headers present
        if canary in (r.text or ""):
            # check cache indicators
            cache_hdr = r.headers.get("age") or r.headers.get("x-cache") or r.headers.get("cf-cache-status")
            sev = "high" if cache_hdr else "medium"
            findings.append(Finding(
                id=f"cachepoison-{h}-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="Web Cache Poisoning (unkeyed header)",
                severity=sev,
                url=url,
                parameter=h,
                payload=f"{h}: {canary}.evil.example.com",
                evidence=f"Canary reflected; cache header: {cache_hdr}",
                response_snippet=r.snippet(200),
                confidence=0.6 if cache_hdr else 0.4,
            ))
    # param cloaking / cache key
    log_event(parsed.netloc, "cache_poison_scan", {"url": url, "findings": len(findings)})
    return findings
