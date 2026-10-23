"""Kerberos attacks: AS-REP roasting, Kerberoasting."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_base(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    # detect Kerberos endpoints
    for path in ["/krb", "/kerberos", "/kdc", "/auth/kerberos", "/gssapi"]:
        url = "{}://{}{}".format(parsed.scheme, parsed.netloc, path)
        r = get(url)
        if r.status != 0 and r.status != 404:
            findings.append(Finding(
                id="kerberos-{}-{}".format(path.strip("/"), hash(url) & 0xffff),
                target=parsed.netloc,
                type="Kerberos Endpoint (potential)",
                severity="info",
                url=url,
                parameter="path",
                payload=path,
                evidence="Non-404 (status {})".format(r.status),
                response_snippet=r.snippet(200),
                confidence=0.4,
            ))
    log_event(parsed.netloc, "kerberos_scan", {"base": base_url, "findings": len(findings)})
    return findings

scan_url = scan_base
