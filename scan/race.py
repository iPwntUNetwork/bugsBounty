"""Race condition scanner (concurrent duplicate requests)."""
import concurrent.futures, time
from core.http import post, get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # send N concurrent identical requests
    N = 8
    results = []
    def worker():
        return get(url)
    with concurrent.futures.ThreadPoolExecutor(max_workers=N) as ex:
        futs = [ex.submit(worker) for _ in range(N)]
        for f in futs:
            try:
                results.append(f.result())
            except Exception:
                pass
    statuses = [r.status for r in results]
    bodies = [r.text for r in results]
    # if responses differ significantly under concurrency -> potential race
    if len(set(bodies)) > 1 and len(set(statuses)) > 1:
        findings.append(Finding(
            id=f"race-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="Race Condition (potential)",
            severity="medium",
            url=url,
            parameter="concurrency",
            payload=f"{N} parallel requests",
            evidence=f"Statuses: {set(statuses)}, body variants: {len(set(bodies))}",
            response_snippet=results[0].snippet(200) if results else "",
            confidence=0.4,
        ))
    log_event(parsed.netloc, "race_scan", {"url": url, "findings": len(findings)})
    return findings
