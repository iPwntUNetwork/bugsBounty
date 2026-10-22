"""Service worker abuse detection."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    for path in ["/sw.js", "/service-worker.js", "/serviceworker.js", "/worker.js"]:
        r = get("{}://{}{}".format(parsed.scheme, parsed.netloc, path))
        if r.status == 200:
            findings.append(Finding(
                id="sw-{}-{}".format(path, hash(url) & 0xffff),
                target=parsed.netloc,
                type="Service Worker Exposed",
                severity="low",
                url="{}://{}{}".format(parsed.scheme, parsed.netloc, path),
                parameter="path",
                payload=path,
                evidence="Service worker script accessible",
                response_snippet=r.snippet(200),
                confidence=0.8,
            ))
    log_event(parsed.netloc, "service_worker_scan", {"url": url, "findings": len(findings)})
    return findings
