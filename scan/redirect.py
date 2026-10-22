"""Open redirect scanner."""
import urllib.parse
from core.http import get
from scan.payloads import REDIRECT, OPEN_REDIRECT_PARAMS
from core.findings import Finding
from core.memory import log_event

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    # params from url + common
    test_params = list(qs.keys()) + [p for p in OPEN_REDIRECT_PARAMS if p not in qs]
    test_params = list(dict.fromkeys(test_params))[:20]
    for param in test_params:
        for payload in REDIRECT[:4]:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status in (301, 302, 303, 307, 308):
                loc = r.headers.get("location", "")
                if "evil.example.com" in loc or loc.startswith("//evil"):
                    findings.append(Finding(
                        id=f"redirect-{hash(new_url+payload) & 0xffff:x}",
                        target=parsed.netloc,
                        type="Open Redirect",
                        severity="medium",
                        url=new_url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Redirect Location: {loc}",
                        response_snippet=f"HTTP {r.status} Location: {loc}",
                        confidence=0.9,
                    ))
                    break
            # also check meta refresh / js
            if r.status == 200 and ("evil.example.com" in r.text):
                if "window.location" in r.text or "meta" in r.text.lower():
                    findings.append(Finding(
                        id=f"redirect-js-{hash(new_url) & 0xffff:x}",
                        target=parsed.netloc,
                        type="Open Redirect (JS/meta)",
                        severity="medium",
                        url=new_url,
                        parameter=param,
                        payload=payload,
                        evidence="Redirect target reflected in JS/meta",
                        response_snippet=r.snippet(200),
                        confidence=0.6,
                    ))
                    break
    log_event(parsed.netloc, "redirect_scan", {"url": url, "findings": len(findings)})
    return findings
