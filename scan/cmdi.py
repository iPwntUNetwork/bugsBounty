"""OS Command Injection scanner with WAF mutex tamper evasion (`probe_with_mutex_bypass`)."""
import re
import urllib.parse
from core.http import get
from core.waf_bypass import probe_with_mutex_bypass
from scan.payloads import CMDI
from core.findings import Finding
from core.memory import log_event

MARKERS_RE = re.compile(r"(uid=\d+\([^)]+\)|gid=\d+\(|nt authority\\system|volume serial number)", re.I)


def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings

    base_r = get(url)
    base_text = base_r.text or ""

    for param in test_params:
        for payload in CMDI:
            r, used_payload, bypass_tag = probe_with_mutex_bypass(
                url, param, payload, vuln_class="cmdi", baseline_status=base_r.status or 200
            )
            if r.status == 0:
                continue
            text = r.text or ""
            m = MARKERS_RE.search(text)
            if m and not MARKERS_RE.search(base_text):
                findings.append(Finding(
                    id=f"cmdi-{hash(url + param + used_payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Command Injection",
                    severity="critical",
                    url=url,
                    parameter=param,
                    payload=used_payload,
                    evidence=f"OS command execution output confirmed (`{m.group(1)}`)" + (f" via {bypass_tag}" if bypass_tag else ""),
                    request=r.raw_request,
                    response_snippet=r.snippet(300),
                    confidence=0.92,
                    detected_by="hunter:cmdi",
                    waf_bypass_used=bypass_tag,
                ))
                break
    log_event(parsed.netloc, "cmdi_scan", {"url": url, "findings": len(findings)})
    return findings
