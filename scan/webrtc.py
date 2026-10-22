"""WebRTC leak detection."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status != 0 and "RTCPeerConnection" in (r.text or ""):
        findings.append(Finding(
            id="webrtc-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="WebRTC Usage (IP leak potential)",
            severity="low",
            url=url,
            parameter="js",
            payload="RTCPeerConnection",
            evidence="Page uses WebRTC; may leak local IP",
            response_snippet=r.snippet(200),
            confidence=0.7,
        ))
    log_event(parsed.netloc, "webrtc_scan", {"url": url, "findings": len(findings)})
    return findings
