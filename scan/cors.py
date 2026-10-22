"""CORS misconfiguration scanner."""
from core.http import get, request
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # test reflected origin
    for origin in ["https://evil.example.com", "null", "https://attacker.com"]:
        r = get(url, headers={"Origin": origin})
        if r.status == 0:
            continue
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao == origin or acao == "*":
            sev = "high" if (acac.lower() == "true" and acao != "*") else "medium"
            if acao == "*" and acac.lower() == "true":
                sev = "high"
            findings.append(Finding(
                id=f"cors-{hash(url+origin) & 0xffff:x}",
                target=parsed.netloc,
                type="CORS Misconfiguration",
                severity=sev,
                url=url,
                parameter="Origin",
                payload=origin,
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                response_snippet=f"ACAO={acao}; ACAC={acac}",
                confidence=0.75 if acao == origin else 0.5,
            ))
            break
    log_event(parsed.netloc, "cors_scan", {"url": url, "findings": len(findings)})
    return findings
