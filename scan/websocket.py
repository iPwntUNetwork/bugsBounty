"""WebSocket security scanner."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # check for ws endpoints
    ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
    # check origin validation
    r = get(url, headers={"Origin": "https://evil.example.com", "Upgrade": "websocket", "Connection": "Upgrade"})
    if r.status not in (403, 400, 0) and r.status < 500:
        findings.append(Finding(
            id=f"ws-origin-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="WebSocket Origin Validation Missing",
            severity="medium",
            url=url,
            parameter="Origin",
            payload="https://evil.example.com",
            evidence=f"WebSocket handshake accepted foreign origin (status {r.status})",
            response_snippet=r.snippet(200),
            confidence=0.5,
        ))
    log_event(parsed.netloc, "websocket_scan", {"url": url, "findings": len(findings)})
    return findings
