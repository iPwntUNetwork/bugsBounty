"""Reflected XSS scanner."""
import urllib.parse
from core.http import get
from scan.payloads import XSS
from core.findings import Finding
from core.memory import log_event

REFLECTION_MARKERS = ["<script>alert(1)</script>", "onerror=alert(1)", "onload=alert(1)"]


def scan_url(url, params=None):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else (params or [])
    if not test_params:
        return findings
    base = parsed._replace(query="").geturl()
    for param in test_params:
        for payload in XSS:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            # check reflection
            reflected = payload in r.text or any(m in r.text for m in REFLECTION_MARKERS)
            # check if payload appears unencoded
            if reflected:
                # verify unencoded reflection (not HTML-encoded)
                encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                if encoded not in r.text or payload in r.text:
                    f = Finding(
                        id=f"xss-{hash(new_url+payload) & 0xffff:x}",
                        target=parsed.netloc,
                        type="Reflected XSS",
                        severity="medium",
                        url=new_url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Payload reflected unencoded in response (status {r.status})",
                        response_snippet=r.snippet(300),
                        confidence=0.7,
                    )
                    findings.append(f)
                    break
    log_event(parsed.netloc, "xss_scan", {"url": url, "findings": len(findings)})
    return findings


def scan_forms(forms, base_url):
    findings = []
    from core.http import post, get
    for form in forms:
        action = form["action"]
        method = form["method"]
        for inp in form["inputs"]:
            for payload in XSS[:4]:
                data = {i["name"]: (payload if i["name"] == inp["name"] else (i.get("value") or "test")) for i in form["inputs"]}
                if method == "POST":
                    r = post(action, data=data)
                else:
                    r = get(action, params=data)
                if r.status == 0:
                    continue
                if payload in r.text and payload.replace("<", "&lt;") not in r.text:
                    findings.append(Finding(
                        id=f"xssform-{hash(action+inp['name']+payload) & 0xffff:x}",
                        target=urllib.parse.urlparse(base_url).netloc,
                        type="Reflected XSS (form)",
                        severity="medium",
                        url=action,
                        parameter=inp["name"],
                        payload=payload,
                        evidence=f"Form input reflected unencoded",
                        response_snippet=r.snippet(300),
                        confidence=0.65,
                    ))
                    break
    return findings
