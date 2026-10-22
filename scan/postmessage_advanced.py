"""Advanced postMessage: origin bypass, data injection."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse, re

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status == 0:
        return findings
    body = r.text or ""
    # find postMessage listeners
    if "addEventListener" in body and "message" in body:
        # check for origin validation
        if "origin" not in body.lower() and "source" not in body.lower():
            findings.append(Finding(
                id="postmsg-noorigin-{}".format(hash(url) & 0xffff),
                target=parsed.netloc,
                type="postMessage No Origin Validation",
                severity="high",
                url=url,
                parameter="js",
                payload="postMessage",
                evidence="message listener without origin/source check",
                response_snippet=body[:300],
                confidence=0.7,
            ))
        # check for eval/innerHTML in handler
        if "eval(" in body or "innerHTML" in body or "document.write" in body:
            findings.append(Finding(
                id="postmsg-sink-{}".format(hash(url) & 0xffff),
                target=parsed.netloc,
                type="postMessage Dangerous Sink",
                severity="high",
                url=url,
                parameter="js",
                payload="eval/innerHTML",
                evidence="postMessage handler uses dangerous sink",
                response_snippet=body[:300],
                confidence=0.6,
            ))
    # postMessage to parent
    if "parent.postMessage" in body or "top.postMessage" in body:
        findings.append(Finding(
            id="postmsg-out-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="postMessage Outbound (potential leak)",
            severity="low",
            url=url,
            parameter="js",
            payload="parent.postMessage",
            evidence="Page sends postMessage to parent",
            response_snippet=body[:200],
            confidence=0.5,
        ))
    log_event(parsed.netloc, "postmessage_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
