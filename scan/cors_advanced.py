"""Advanced CORS: null origin, wildcard with credentials, reflection."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # null origin
    r = get(url, headers={"Origin": "null"})
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "")
    if acao == "null" and acac.lower() == "true":
        findings.append(Finding(
            id="cors-null-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="CORS Null Origin with Credentials",
            severity="high",
            url=url,
            parameter="Origin",
            payload="null",
            evidence="ACAO: null, ACAC: true",
            response_snippet="ACAO=null; ACAC=true",
            confidence=0.9,
        ))
    # origin reflection
    for origin in ["https://evil.example.com", "https://attacker.com"]:
        r = get(url, headers={"Origin": origin})
        acao = r.headers.get("access-control-allow-origin", "")
        if acao == origin:
            sev = "high" if r.headers.get("access-control-allow-credentials", "").lower() == "true" else "medium"
            findings.append(Finding(
                id="cors-reflect-{}-{}".format(origin.split("//")[1].split(".")[0], hash(url) & 0xffff),
                target=parsed.netloc,
                type="CORS Origin Reflection",
                severity=sev,
                url=url,
                parameter="Origin",
                payload=origin,
                evidence="ACAO reflects arbitrary origin",
                response_snippet="ACAO={}".format(acao),
                confidence=0.8,
            ))
            break
    # wildcard with credentials (invalid but check)
    r = get(url, headers={"Origin": "https://evil.example.com"})
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append(Finding(
            id="cors-wildcard-creds-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="CORS Wildcard with Credentials",
            severity="high",
            url=url,
            parameter="Origin",
            payload="*",
            evidence="ACAO: *, ACAC: true (invalid but dangerous)",
            response_snippet="ACAO=*; ACAC=true",
            confidence=0.9,
        ))
    log_event(parsed.netloc, "cors_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
