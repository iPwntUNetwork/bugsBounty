"""Advanced CSP bypass techniques."""
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
    csp = r.headers.get("content-security-policy", "")
    if not csp:
        return findings
    # check for bypass opportunities
    bypasses = []
    if "unsafe-inline" in csp:
        bypasses.append("unsafe-inline allows inline scripts")
    if "unsafe-eval" in csp:
        bypasses.append("unsafe-eval allows eval()")
    if "*" in csp.split("script-src")[-1].split(";")[0] if "script-src" in csp else False:
        bypasses.append("wildcard in script-src")
    if "data:" in csp:
        bypasses.append("data: URI allowed")
    if "blob:" in csp:
        bypasses.append("blob: URI allowed")
    # JSONP endpoints
    if "callback" in csp or "jsonp" in csp.lower():
        bypasses.append("JSONP callback possible")
    # base-uri missing
    if "base-uri" not in csp:
        bypasses.append("missing base-uri (base tag injection)")
    # object-src missing
    if "object-src" not in csp:
        bypasses.append("missing object-src")
    for b in bypasses:
        findings.append(Finding(
            id="csp-bypass-{}-{}".format(b.split()[0], hash(url) & 0xffff),
            target=parsed.netloc,
            type="CSP Bypass: {}".format(b),
            severity="medium",
            url=url,
            parameter="CSP",
            payload=csp[:120],
            evidence=b,
            response_snippet=csp[:200],
            confidence=0.7,
        ))
    log_event(parsed.netloc, "csp_bypass_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
