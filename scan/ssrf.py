"""SSRF scanner."""
import urllib.parse
from core.http import get
from scan.payloads import SSRF
from core.findings import Finding
from core.memory import log_event

SSRF_PARAMS = ["url", "uri", "path", "dest", "redirect", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir", "show", "navigation", "open", "file", "document", "folder", "pg", "php_path", "style", "doc", "img", "filename"]

INDICATORS = ["ami-id", "instance-id", "computeMetadata", "root:x:", "metadata", "iam/security-credentials"]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    # only test params present in URL or known ssrf params if URL has no params? skip brute to reduce FP
    if not test_params:
        return findings
    for param in test_params:
        for payload in SSRF[:5]:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            text = r.text or ""
            # avoid counting payload reflection
            text_nopayload = text.replace(payload, "")
            if any(ind in text_nopayload for ind in INDICATORS):
                findings.append(Finding(
                    id=f"ssrf-{hash(new_url+payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Server-Side Request Forgery",
                    severity="high",
                    url=new_url,
                    parameter=param,
                    payload=payload,
                    evidence="Response contains internal/metadata indicators",
                    response_snippet=r.snippet(300),
                    confidence=0.75,
                ))
                break
    log_event(parsed.netloc, "ssrf_scan", {"url": url, "findings": len(findings)})
    return findings
