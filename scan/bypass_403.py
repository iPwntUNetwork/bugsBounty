"""401/403 Access-Control & Edge Proxy Bypass Scanner (`X-Original-URL`, `X-Forwarded-For`, verb/path mutations)."""
import urllib.parse
from core.findings import Finding
from core.memory import log_event
from tools.adapters import run_bypass_403


def scan_url(url: str) -> list[Finding]:
    parsed = urllib.parse.urlparse(url)
    res = run_bypass_403(url)
    findings = []
    for bp in res.get("bypasses", []):
        effective_url = bp.get("url", url)
        findings.append(Finding(
            id=f"403bypass-{hash(url + bp['technique']) & 0xffff:x}",
            target=parsed.netloc,
            type="403 Access-Control Bypass",
            severity="high",
            url=effective_url,
            parameter="header/path",
            payload=bp["technique"],
            evidence=f"Locked endpoint returned HTTP 200 ({bp['length']}B vs baseline HTTP {res['baseline_status']}) via {bp['technique']}",
            confidence=0.88,
            detected_by="hunter:bypass_403",
        ))
    log_event(parsed.netloc, "bypass_403_scan", {"url": url, "findings": len(findings)})
    return findings
