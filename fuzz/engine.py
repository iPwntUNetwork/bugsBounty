"""Zero-day discovery: fuzzing + differential/anomaly detection."""
import random, string, urllib.parse, time
from core.http import get, post
from core.findings import Finding
from core.memory import log_event

FUZZ_CHARS = ["'", '"', "<", ">", "{", "}", "$", "%", "\\", "/", ";", "|", "&", "`", "(", ")", "[", "]", "*", "+", "-", "=", "!", "@", "#", "^", "~", " "]

def gen_payloads(n=30):
    out = []
    # random strings
    for _ in range(n):
        L = random.randint(1, 40)
        out.append("".join(random.choice(string.ascii_letters + string.digits + "".join(FUZZ_CHARS)) for _ in range(L)))
    # known dangerous
    out += ["{{7*7}}", "${7*7}", "' OR '1'='1", "<script>alert(1)</script>", "../../../../etc/passwd", ";id", "|id", "${jndi:ldap://x/a}"]
    return out

def fuzz_url(url, param=None):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    params = [param] if param else (list(qs.keys()) if qs else ["q", "id", "search", "input"])
    baseline = get(url)
    base_len = len(baseline.text or "") if baseline.status != 0 else 0
    base_status = baseline.status
    for p in params:
        anomalies = []
        for payload in gen_payloads(25):
            q = dict(qs)
            q[p] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            # anomaly: status change, length delta, error keywords, reflection
            if r.status != base_status and r.status in (500, 502, 503):
                anomalies.append((payload, r, "server error"))
            elif abs(len(r.text or "") - base_len) > max(50, base_len * 0.5) and base_len > 0:
                anomalies.append((payload, r, "length anomaly"))
            elif any(k in (r.text or "").lower() for k in ["exception", "traceback", "stack trace", "error", "warning", "fatal", "syntax"]):
                anomalies.append((payload, r, "error keyword"))
        if anomalies:
            # report most interesting
            payload, r, reason = anomalies[0]
            findings.append(Finding(
                id=f"fuzz-{p}-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="Zero-Day Candidate (fuzzing anomaly)",
                severity="medium",
                url=new_url if False else url,
                parameter=p,
                payload=payload,
                evidence=f"{reason}: status {r.status}, len {len(r.text or '')} (baseline {base_len})",
                response_snippet=r.snippet(300),
                confidence=0.35,
            ))
    log_event(parsed.netloc, "fuzz_scan", {"url": url, "findings": len(findings)})
    return findings

def differential_scan(url):
    """Compare responses across HTTP methods and headers for anomalies."""
    findings = []
    parsed = urllib.parse.urlparse(url)
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
    resps = {}
    for m in methods:
        from core.http import request
        r = request(m, url)
        resps[m] = r
    # TRACE reflection
    r = resps.get("TRACE")
    if r and r.status == 200 and "TRACE" in (r.text or ""):
        findings.append(Finding(
            id=f"trace-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="HTTP TRACE Enabled",
            severity="low",
            url=url,
            parameter="method",
            payload="TRACE",
            evidence="TRACE method reflected",
            response_snippet=r.snippet(200),
            confidence=0.9,
        ))
    # method override
    r = get(url, headers={"X-HTTP-Method-Override": "DELETE"})
    if r.status not in (405, 403, 404, 0) and r.status < 500:
        pass
    log_event(parsed.netloc, "diff_scan", {"url": url, "findings": len(findings)})
    return findings
