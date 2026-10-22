"""Advanced OAuth 2.0: PKCE bypass, state confusion, implicit flow."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # PKCE downgrade: omit code_challenge
    r = get(url, params={"response_type": "code", "client_id": "test", "redirect_uri": "https://example.com/cb"})
    if r.status == 200 and "code_challenge" not in (r.text or "").lower():
        findings.append(Finding(
            id="oauth-pkce-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="OAuth PKCE Not Enforced",
            severity="medium",
            url=url,
            parameter="code_challenge",
            payload="",
            evidence="Authorization endpoint accepts request without PKCE",
            response_snippet=r.snippet(200),
            confidence=0.6,
        ))
    # implicit flow (token in fragment)
    r = get(url, params={"response_type": "token", "client_id": "test", "redirect_uri": "https://example.com/cb"})
    if r.status in (301, 302, 303, 307, 308):
        loc = r.headers.get("location", "")
        if "access_token" in loc or "token=" in loc:
            findings.append(Finding(
                id="oauth-implicit-{}".format(hash(url) & 0xffff),
                target=parsed.netloc,
                type="OAuth Implicit Flow (token leakage)",
                severity="medium",
                url=url,
                parameter="response_type",
                payload="token",
                evidence="Access token returned in redirect fragment",
                response_snippet=loc[:200],
                confidence=0.7,
            ))
    # state confusion: reuse state
    r1 = get(url, params={"client_id": "test", "response_type": "code", "redirect_uri": "https://example.com/cb", "state": "FIXEDSTATE"})
    r2 = get(url, params={"client_id": "test", "response_type": "code", "redirect_uri": "https://example.com/cb", "state": "FIXEDSTATE"})
    if r1.status == r2.status and r1.status in (200, 302):
        findings.append(Finding(
            id="oauth-state-reuse-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="OAuth State Reuse (CSRF)",
            severity="medium",
            url=url,
            parameter="state",
            payload="FIXEDSTATE",
            evidence="Same state accepted twice",
            response_snippet=r1.snippet(200),
            confidence=0.5,
        ))
    log_event(parsed.netloc, "oauth_advanced_scan", {"url": url, "findings": len(findings)})
    return findings
