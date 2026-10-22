"""Web cache deception scanner."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # append static extension to dynamic URL
    for ext in [".css", ".js", ".png", ".jpg", ".ico", ".svg"]:
        test_url = url.rstrip("/") + ext
        r = get(test_url)
        if r.status == 0:
            continue
        base = get(url)
        if r.status == 200 and base.status == 200 and r.text == base.text:
            # cache headers?
            cache_hdr = r.headers.get("cache-control", "") + r.headers.get("age", "") + r.headers.get("x-cache", "")
            if "max-age" in cache_hdr or "public" in cache_hdr or r.headers.get("age"):
                findings.append(Finding(
                    id=f"cachedeception-{ext}-{hash(url) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Web Cache Deception",
                    severity="medium",
                    url=test_url,
                    parameter="path",
                    payload=ext,
                    evidence=f"Dynamic content cached with static extension (cache: {cache_hdr[:80]})",
                    response_snippet=r.snippet(200),
                    confidence=0.6,
                ))
                break
    log_event(parsed.netloc, "cache_deception_scan", {"url": url, "findings": len(findings)})
    return findings
