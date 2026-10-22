"""WAF detection and bypass tamper engine."""
from core.http import get, request
from core.findings import Finding
from core.memory import log_event
import urllib.parse

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "aws_waf": ["x-amzn-requestid", "awselb", "x-amz-cf-id"],
    "akamai": ["akamai", "akamaighost", "x-akamai"],
    "modsecurity": ["mod_security", "modsecurity", "NOYB"],
    "imperva": ["incapsula", "visid_incap", "incap_ses"],
    "f5_bigip": ["bigip", "f5", "ts=", "x-waf"],
    "sucuri": ["sucuri", "x-sucuri"],
    "barracuda": ["barracuda", "barra_counter_session"],
    "fortinet": ["fortigate", "fortiweb"],
    "azure": ["x-azure-ref", "arr-affinity"],
}

TAMPER_SCRIPTS = {
    "space2comment": lambda p: p.replace(" ", "/**/"),
    "randomcase": lambda p: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
    "url_encode": lambda p: urllib.parse.quote(p),
    "double_url_encode": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
    "unicode": lambda p: p.replace("a", "\u0430"),
    "comment_between": lambda p: p.replace("SELECT", "SEL/**/ECT").replace("UNION", "UNI/**/ON"),
    "charencode": lambda p: "".join(f"%{ord(c):02x}" for c in p),
}

def detect_waf(url):
    r = get(url)
    if r.status == 0:
        return None
    h = {k.lower(): v for k, v in r.headers.items()}
    body = (r.text or "").lower()
    detected = []
    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig in h or sig in body or sig in str(h):
                detected.append(waf)
                break
    probe = get(url + "?q=<script>alert(1)</script>' OR 1=1--")
    if probe.status in (403, 406, 429, 503, 999) or "blocked" in (probe.text or "").lower() or "waf" in (probe.text or "").lower():
        if not detected:
            detected.append("unknown_waf")
    return detected

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    wafs = detect_waf(url)
    if wafs:
        findings.append(Finding(
            id=f"waf-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="WAF Detected",
            severity="info",
            url=url,
            parameter="waf",
            payload=",".join(wafs),
            evidence=f"WAF: {', '.join(wafs)}",
            response_snippet="",
            confidence=0.8,
        ))
    base_payload = "<script>alert(1)</script>"
    for name, fn in TAMPER_SCRIPTS.items():
        try:
            tampered = fn(base_payload)
        except Exception:
            continue
        test_url = url + "?q=" + urllib.parse.quote(tampered)
        r = get(test_url)
        if r.status == 0:
            continue
        orig = get(url + "?q=" + urllib.parse.quote(base_payload))
        if orig.status in (403, 406, 429, 503) and r.status == 200:
            findings.append(Finding(
                id=f"waf-bypass-{name}-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="WAF Bypass",
                severity="medium",
                url=test_url,
                parameter="q",
                payload=tampered,
                evidence=f"Tamper '{name}' bypassed WAF (orig {orig.status} -> {r.status})",
                response_snippet=r.snippet(200),
                confidence=0.7,
            ))
    log_event(parsed.netloc, "waf_scan", {"url": url, "findings": len(findings), "wafs": wafs})
    return findings
