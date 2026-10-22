"""HTTP request smuggling scanner (CL.TE / TE.CL detection)."""
from core.http import request
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    # CL.TE probe
    headers_te = {
        "Transfer-Encoding": "chunked",
        "Content-Length": "4",
    }
    body = "1\r\nZ\r\nQ\r\n\r\n"
    try:
        r = request("POST", base + "/", headers=headers_te, data=body, timeout=10)
        if r.status == 0:
            return findings
        # heuristic: if server accepts both TE and CL ambiguously -> potential
        if r.status in (200, 400) and "chunked" not in r.headers.get("transfer-encoding", "").lower():
            pass
    except Exception:
        pass
    # Time-based TE.CL: send TE with delay
    import time
    headers = {"Transfer-Encoding": "chunked", "Content-Length": "1"}
    payload = "0\r\n\r\n"  # terminate chunked
    start = time.time()
    r = request("POST", base + "/", headers=headers, data=payload, timeout=10)
    elapsed = time.time() - start
    # If server waits for more data (timeout) -> potential smuggling
    if elapsed >= 4:
        findings.append(Finding(
            id=f"smuggle-{hash(base) & 0xffff:x}",
            target=parsed.netloc,
            type="HTTP Request Smuggling (potential)",
            severity="high",
            url=base,
            parameter="headers",
            payload="Transfer-Encoding: chunked + Content-Length",
            evidence=f"Server delayed {elapsed:.2f}s (possible TE/CL desync)",
            response_snippet=r.snippet(200) if r else "",
            confidence=0.45,
        ))
    log_event(parsed.netloc, "smuggle_scan", {"url": url, "findings": len(findings)})
    return findings
