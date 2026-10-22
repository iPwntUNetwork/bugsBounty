"""Cross-Site WebSocket Hijacking (CSWSH)."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # find websocket endpoints
    ws_candidates = ["/ws", "/websocket", "/socket", "/socket.io", "/sockjs", "/cable", "/live"]
    root = "{}://{}".format(parsed.scheme, parsed.netloc)
    for c in ws_candidates:
        wurl = root + c
        r = get(wurl, headers={"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version": "13", "Origin": "https://evil.example.com"})
        if r.status in (101, 200):
            findings.append(Finding(
                id="cswsh-{}-{}".format(c, hash(url) & 0xffff),
                target=parsed.netloc,
                type="Cross-Site WebSocket Hijacking",
                severity="high",
                url=wurl,
                parameter="Origin",
                payload="Origin: https://evil.example.com",
                evidence="WebSocket handshake accepted foreign origin (status {})".format(r.status),
                response_snippet=r.snippet(200),
                confidence=0.7,
            ))
    log_event(parsed.netloc, "cswsh_scan", {"url": url, "findings": len(findings)})
    return findings
