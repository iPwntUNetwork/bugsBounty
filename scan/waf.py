"""WAF detection and multi-layer bypass scanner."""
import urllib.parse
from core.http import get
from core.findings import Finding
from core.memory import log_event
from core.mutex import PAYLOAD_MUTEX
from core.stealth import select_browser_profile, ORIGIN_SPOOF_HEADERS
from core.waf_bypass import TAMPER_SCRIPTS, get_host_waf_profile, is_waf_block, apply_tamper


def detect_waf(url: str, run_external: bool = True) -> dict:
    prof = get_host_waf_profile(url, run_external_wafw00f=run_external)
    wafs = prof.get("wafs", [])
    return {
        "detected": bool(wafs),
        "waf": wafs[0] if wafs else None,
        "wafs": wafs,
        "blocking": prof.get("blocking", False),
        "sqlmap_tampers": prof.get("sqlmap_tampers", ""),
    }


def scan_url(url: str):
    findings = []
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    prof_data = get_host_waf_profile(url, run_external_wafw00f=True)
    wafs = prof_data.get("wafs", [])
    clean_status = prof_data.get("clean_status", 200)
    if clean_status == 0:
        return findings

    if wafs:
        findings.append(Finding(
            id=f"waf-{hash(url) & 0xffff:x}",
            target=host,
            type="WAF Detected",
            severity="info",
            url=url,
            parameter="waf",
            payload=",".join(wafs),
            evidence=f"Detected WAF/CDN protection: {', '.join(wafs)} (SQLMap tamper profile: {prof_data.get('sqlmap_tampers')})",
            confidence=0.85,
            detected_by="hunter:waf",
        ))

    sep = "&" if "?" in url else "?"
    canary_attack = "<script>alert(1)</script>' UNION SELECT 1,2--"
    orig = get(f"{url}{sep}q={urllib.parse.quote(canary_attack)}")
    if not is_waf_block(orig, clean_status):
        log_event(host, "waf_scan", {"url": url, "findings": len(findings), "wafs": wafs})
        return findings

    PAYLOAD_MUTEX.record_failure(host, "waf_probe", canary_attack, "raw", status=orig.status, reason="waf_block")

    for idx, name in enumerate(TAMPER_SCRIPTS):
        try:
            tampered = apply_tamper(name, canary_attack)
        except Exception:
            continue
        ua_prof = select_browser_profile(host, force_rotate=True)
        hdrs = dict(ua_prof.get("headers", {}))
        hdrs["User-Agent"] = ua_prof["ua"]
        hdrs.update(ORIGIN_SPOOF_HEADERS[idx % len(ORIGIN_SPOOF_HEADERS)])
        test_q = tampered if name in ("url_encode", "double_url_encode", "charencode", "space2mysqlblank", "space2mssqlhash", "null_byte_prefix") else urllib.parse.quote(tampered)
        test_url = f"{url}{sep}q={test_q}"
        r = get(test_url, headers=hdrs)
        if r.status == 0:
            continue
        if not is_waf_block(r, clean_status) and r.status == 200:
            PAYLOAD_MUTEX.record_bypass_win(host, name, profile=ua_prof)
            findings.append(Finding(
                id=f"waf-bypass-{name}-{hash(url) & 0xffff:x}",
                target=host,
                type="WAF Bypass",
                severity="medium",
                url=test_url,
                parameter="q",
                payload=tampered,
                evidence=f"Tamper '{name}' + UA '{ua_prof['name']}' bypassed WAF ({orig.status} blocked -> {r.status} allowed)",
                request=r.raw_request,
                response_snippet=r.snippet(250),
                confidence=0.8,
                detected_by="hunter:waf",
                waf_bypass_used=f"tamper:{name}+ua:{ua_prof['name']}",
            ))
            break
        PAYLOAD_MUTEX.record_failure(host, "waf_probe", canary_attack, name, status=r.status, ua=ua_prof["ua"])

    log_event(host, "waf_scan", {"url": url, "findings": len(findings), "wafs": wafs})
    return findings


detect = scan_url
