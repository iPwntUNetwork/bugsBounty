"""SSRF scanner with WAF mutex tamper evasion + local OOB callback probe."""
import urllib.parse
from core.http import get
from core.waf_bypass import probe_with_mutex_bypass
from scan.payloads import SSRF
from core.findings import Finding
from core.memory import log_event
from tools.oob import get_oob_manager

INDICATORS = ["ami-id", "instance-id", "computemetadata", "root:x:", "iam/security-credentials", "oob-ack:"]


def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings

    base_r = get(url)
    oob = get_oob_manager()

    for param in test_params:
        canary = oob.generate_canary("ssrf")
        r_oob, used_oob, oob_bypass = probe_with_mutex_bypass(
            url, param, canary["http_url"], vuln_class="ssrf", baseline_status=base_r.status or 200
        )
        hits = oob.poll(canary["token"], wait_s=0.35)
        if hits:
            findings.append(Finding(
                id=f"ssrf-oob-{hash(url + param) & 0xffff:x}",
                target=parsed.netloc,
                type="Server-Side Request Forgery (SSRF)",
                severity="critical",
                url=url,
                parameter=param,
                payload=used_oob,
                evidence=f"Target server fetched out-of-band callback `{canary['http_url']}` (token={canary['token']})",
                request=r_oob.raw_request,
                response_snippet=r_oob.snippet(300),
                confidence=0.98,
                detected_by="hunter:ssrf",
                waf_bypass_used=oob_bypass,
                oob_interactions=hits,
            ))
            continue

        for payload in SSRF[:6]:
            r, used_payload, bypass_tag = probe_with_mutex_bypass(
                url, param, payload, vuln_class="ssrf", baseline_status=base_r.status or 200
            )
            if r.status == 0:
                continue
            text_clean = (r.text or "").replace(used_payload, "").lower()
            if any(ind in text_clean for ind in INDICATORS):
                findings.append(Finding(
                    id=f"ssrf-{hash(url + param + used_payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Server-Side Request Forgery (SSRF)",
                    severity="high",
                    url=url,
                    parameter=param,
                    payload=used_payload,
                    evidence="Response contains cloud metadata / internal resource indicators",
                    request=r.raw_request,
                    response_snippet=r.snippet(300),
                    confidence=0.82,
                    detected_by="hunter:ssrf",
                    waf_bypass_used=bypass_tag,
                ))
                break

    log_event(parsed.netloc, "ssrf_scan", {"url": url, "findings": len(findings)})
    return findings
