"""Business logic: price manipulation, coupon abuse, workflow bypass."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    # price/amount manipulation
    for param in ["price", "amount", "total", "cost", "value", "qty", "quantity", "discount"]:
        if param in qs:
            for val in ["0", "-1", "0.01", "999999"]:
                q = dict(qs)
                q[param] = [val]
                new_url = parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
                r = get(new_url)
                if r.status == 200 and "error" not in (r.text or "").lower() and "invalid" not in (r.text or "").lower():
                    findings.append(Finding(
                        id="bizlogic-{}-{}".format(param, hash(url) & 0xffff),
                        target=parsed.netloc,
                        type="Business Logic (price/amount manipulation)",
                        severity="high",
                        url=new_url,
                        parameter=param,
                        payload=val,
                        evidence="Server accepted manipulated {}={}".format(param, val),
                        response_snippet=r.snippet(200),
                        confidence=0.5,
                    ))
                    break
    # coupon/discount code brute
    for code in ["SAVE10", "DISCOUNT", "PROMO", "FREESHIP", "WELCOME", "ADMIN", "TEST"]:
        r = get(url, params={"coupon": code, "promo": code, "discount": code})
        if r.status == 200 and code.lower() in (r.text or "").lower():
            findings.append(Finding(
                id="coupon-{}-{}".format(code, hash(url) & 0xffff),
                target=parsed.netloc,
                type="Coupon/Promo Code Accepted",
                severity="low",
                url=url,
                parameter="coupon",
                payload=code,
                evidence="Coupon code accepted/reflected",
                response_snippet=r.snippet(200),
                confidence=0.4,
            ))
    log_event(parsed.netloc, "business_logic_scan", {"url": url, "findings": len(findings)})
    return findings
