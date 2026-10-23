"""Server-Side Template Injection scanner with mutex WAF bypass & clean baseline check."""
import urllib.parse
from core.http import get
from core.waf_bypass import probe_with_mutex_bypass
from scan.payloads import SSTI
from core.findings import Finding
from core.memory import log_event


def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings

    base_r = get(url)
    if "49" in (base_r.text or ""):
        return findings

    for param in test_params:
        for payload in SSTI:
            r, used_payload, bypass_tag = probe_with_mutex_bypass(
                url, param, payload, vuln_class="generic", baseline_status=base_r.status or 200
            )
            if r.status == 0:
                continue
            if "49" in (r.text or "") and payload in ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "${{7*7}}") and payload not in (r.text or ""):
                findings.append(Finding(
                    id=f"ssti-{hash(url + param + used_payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Server-Side Template Injection",
                    severity="high",
                    url=url,
                    parameter=param,
                    payload=used_payload,
                    evidence="Template arithmetic expression evaluated server-side (7*7 -> 49)",
                    request=r.raw_request,
                    response_snippet=r.snippet(300),
                    confidence=0.88,
                    detected_by="hunter:ssti",
                    waf_bypass_used=bypass_tag,
                ))
                break
    log_event(parsed.netloc, "ssti_scan", {"url": url, "findings": len(findings)})
    return findings
