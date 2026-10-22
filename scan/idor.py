"""IDOR / BOLA heuristic scanner."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse, re

ID_PARAMS = ["id", "user_id", "userId", "uid", "account", "account_id", "profile", "order", "order_id", "doc", "document_id", "file", "item", "item_id", "post", "post_id"]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    for param in list(qs.keys()):
        if param.lower() not in [p.lower() for p in ID_PARAMS]:
            continue
        val = qs[param][0]
        # try increment/decrement
        if val.isdigit():
            for newval in (str(int(val)+1), str(int(val)-1), "1", "2"):
                if newval == val:
                    continue
                q = dict(qs)
                q[param] = [newval]
                new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
                r = get(new_url)
                if r.status == 200 and r.text and r.text != get(url).text:
                    # ensure not error page
                    if "not found" not in (r.text or "").lower() and "error" not in (r.text or "").lower():
                        findings.append(Finding(
                            id=f"idor-{param}-{hash(url) & 0xffff:x}",
                            target=parsed.netloc,
                            type="IDOR / BOLA (potential)",
                            severity="high",
                            url=new_url,
                            parameter=param,
                            payload=f"{param}={newval}",
                            evidence=f"Accessed another object (status {r.status})",
                            response_snippet=r.snippet(200),
                            confidence=0.5,
                        ))
                        break
    log_event(parsed.netloc, "idor_scan", {"url": url, "findings": len(findings)})
    return findings
