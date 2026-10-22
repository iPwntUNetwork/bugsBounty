"""Advanced DOM clobbering."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status == 0:
        return findings
    body = r.text or ""
    # DOM clobbering via named properties
    if "document." in body and ("getElementById" not in body or "querySelector" not in body):
        findings.append(Finding(
            id="domclobber-adv-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="DOM Clobbering (advanced)",
            severity="medium",
            url=url,
            parameter="html",
            payload="id/name attributes",
            evidence="Direct property access without getElementById",
            response_snippet=body[:200],
            confidence=0.4,
        ))
    # clobbering to XSS
    if "<form" in body.lower() and "name=" in body.lower():
        findings.append(Finding(
            id="domclobber-form-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="DOM Clobbering via Form (potential)",
            severity="medium",
            url=url,
            parameter="html",
            payload="<form name=x>",
            evidence="Form with name attribute can clobber window.x",
            response_snippet=body[:200],
            confidence=0.4,
        ))
    log_event(parsed.netloc, "dom_clobbering_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
