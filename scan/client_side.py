"""Client-side security: postMessage, DOM clobbering, clickjacking, tabnabbing."""
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
    # postMessage without origin check
    if "addEventListener('message'" in body or 'addEventListener("message"' in body:
        if "origin" not in body.lower():
            findings.append(Finding(
                id=f"postmessage-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="postMessage Missing Origin Check",
                severity="medium",
                url=url,
                parameter="js",
                payload="postMessage",
                evidence="message event listener without origin validation",
                response_snippet=body[:200],
                confidence=0.6,
            ))
    # DOM clobbering: named properties
    if "document." in body and "getElementById" not in body:
        pass
    # clickjacking: X-Frame-Options missing (already headers) + frame ancestors
    # tabnabbing: target=_blank without rel=noopener
    if 'target="_blank"' in body or "target='_blank'" in body:
        if "noopener" not in body.lower() and "noreferrer" not in body.lower():
            findings.append(Finding(
                id=f"tabnabbing-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="Reverse Tabnabbing",
                severity="low",
                url=url,
                parameter="html",
                payload='target="_blank"',
                evidence="target=_blank without rel=noopener",
                response_snippet=body[:200],
                confidence=0.8,
            ))
    # DOM clobbering via id/name
    if "document." in body and ".src" in body:
        findings.append(Finding(
            id=f"domclobber-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="DOM Clobbering (potential)",
            severity="low",
            url=url,
            parameter="html",
            payload="id/name attributes",
            evidence="DOM property access via id/name possible",
            response_snippet=body[:200],
            confidence=0.3,
        ))
    log_event(parsed.netloc, "client_side_scan", {"url": url, "findings": len(findings)})
    return findings
