"""SQL injection scanner (error + boolean + time-based)."""
import time, urllib.parse, re
from core.http import get
from scan.payloads import SQLI
from core.findings import Finding
from core.memory import log_event

SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "mysql_num_rows", "pg_query", "pg_exec",
    "sqlite3", "ora-01756", "unclosed quotation", "quoted string not properly terminated",
    "microsoft ole db", "odbc sql", "jdbc", "sqlstate", "syntax error",
    "warning: mysql", "valid mysql result", "mysqlclient", "postgresql",
    "you have an error in your sql", "supplied argument is not a valid",
]

def _has_sql_error(text):
    t = (text or "").lower()
    return any(e in t for e in SQL_ERRORS)


def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    base = parsed._replace(query="").geturl()
    for param in test_params:
        # error-based
        for payload in ["'", "\"", "' OR '1'='1", "1'"]:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            if _has_sql_error(r.text):
                findings.append(Finding(
                    id=f"sqli-err-{hash(new_url+payload) & 0xffff:x}",
                    target=parsed.netloc,
                    type="SQL Injection (error-based)",
                    severity="high",
                    url=new_url,
                    parameter=param,
                    payload=payload,
                    evidence="SQL error message in response",
                    response_snippet=r.snippet(300),
                    confidence=0.8,
                ))
                break
        # boolean-based
        try:
            q1 = dict(qs); q1[param] = ["1' AND '1'='1"]
            q2 = dict(qs); q2[param] = ["1' AND '1'='2"]
            r1 = get(parsed._replace(query=urllib.parse.urlencode(q1, doseq=True)).geturl())
            r2 = get(parsed._replace(query=urllib.parse.urlencode(q2, doseq=True)).geturl())
            if r1.status == 200 and r2.status == 200 and r1.text != r2.text and len(r1.text) != len(r2.text):
                # ensure not just param echo
                if abs(len(r1.text)-len(r2.text)) > 20:
                    findings.append(Finding(
                        id=f"sqli-bool-{hash(url+param) & 0xffff:x}",
                        target=parsed.netloc,
                        type="SQL Injection (boolean-based)",
                        severity="high",
                        url=url,
                        parameter=param,
                        payload="1' AND '1'='1 vs 1' AND '1'='2",
                        evidence=f"Response length differs: true={len(r1.text)} false={len(r2.text)}",
                        response_snippet=r1.snippet(200),
                        confidence=0.6,
                    ))
        except Exception:
            pass
        # time-based
        try:
            q = dict(qs); q[param] = ["' AND SLEEP(3)--"]
            start = time.time()
            r = get(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl())
            elapsed = time.time() - start
            if elapsed >= 2.5 and r.status != 0:
                findings.append(Finding(
                    id=f"sqli-time-{hash(url+param) & 0xffff:x}",
                    target=parsed.netloc,
                    type="SQL Injection (time-based)",
                    severity="high",
                    url=url,
                    parameter=param,
                    payload="' AND SLEEP(3)--",
                    evidence=f"Response delayed {elapsed:.2f}s",
                    response_snippet=r.snippet(200),
                    confidence=0.75,
                ))
        except Exception:
            pass
    log_event(parsed.netloc, "sqli_scan", {"url": url, "findings": len(findings)})
    return findings
