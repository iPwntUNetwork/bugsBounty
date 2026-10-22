"""Server-Side Template Injection scanner."""
import urllib.parse
from core.http import get
from scan.payloads import SSTI
from core.findings import Finding
from core.memory import log_event

MARKERS = ["49", "4949", "7777777"]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        for payload in SSTI:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            if "49" in r.text and payload in ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "${{7*7}}"):
                # ensure 49 not already present? check baseline
                base_r = get(parsed._replace(query=urllib.parse.urlencode({k: v for k, v in qs.items()}, doseq=True)).geturl() if qs else parsed.geturl())
                if "49" not in (base_r.text or ""):
                    findings.append(Finding(
                        id=f"ssti-{hash(new_url+payload) & 0xffff:x}",
                        target=parsed.netloc,
                        type="Server-Side Template Injection",
                        severity="high",
                        url=new_url,
                        parameter=param,
                        payload=payload,
                        evidence="Template expression evaluated (7*7=49)",
                        response_snippet=r.snippet(300),
                        confidence=0.8,
                    ))
                    break
    log_event(parsed.netloc, "ssti_scan", {"url": url, "findings": len(findings)})
    return findings
