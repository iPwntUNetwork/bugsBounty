"""Deep JWT attack scanner: alg confusion, weak secret brute, kid injection."""
import base64, json, hmac, hashlib, urllib.parse
from core.http import get
from core.findings import Finding
from core.memory import log_event

COMMON_SECRETS = ["secret", "password", "123456", "admin", "key", "jwt", "changeme", "letmein", "qwerty", ""]

def _b64d(s):
    s += "=" * (-len(s) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return None

def _b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def scan_token(token, url):
    findings = []
    parts = token.split(".")
    if len(parts) != 3:
        return findings
    header = _b64d(parts[0])
    payload = _b64d(parts[1])
    if not header:
        return findings
    alg = header.get("alg", "")
    # alg none
    if alg.lower() != "none":
        # craft alg=none token
        new_header = dict(header); new_header["alg"] = "none"
        none_token = _b64e(json.dumps(new_header).encode()) + "." + parts[1] + "."
        findings.append(Finding(
            id=f"jwt-none-craft-{hash(token) & 0xffff:x}",
            target=urllib.parse.urlparse(url).netloc,
            type="JWT alg=none (craftable)",
            severity="critical",
            url=url,
            parameter="token",
            payload=none_token[:80],
            evidence=f"Original alg={alg}; none variant craftable",
            response_snippet=str(header),
            confidence=0.9,
        ))
    # weak secret brute (HS256)
    if alg.upper().startswith("HS"):
        msg = (parts[0] + "." + parts[1]).encode()
        sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        for secret in COMMON_SECRETS:
            for h in (hashlib.sha256,):
                try:
                    calc = hmac.new(secret.encode(), msg, h).digest()
                    if hmac.compare_digest(calc, sig):
                        findings.append(Finding(
                            id=f"jwt-weak-{hash(token) & 0xffff:x}",
                            target=urllib.parse.urlparse(url).netloc,
                            type="JWT Weak Secret",
                            severity="critical",
                            url=url,
                            parameter="token",
                            payload=f"secret={secret}",
                            evidence=f"HMAC secret recovered: {secret!r}",
                            response_snippet=str(header),
                            confidence=0.99,
                        ))
                except Exception:
                    pass
    # kid injection
    if "kid" in header:
        findings.append(Finding(
            id=f"jwt-kid-{hash(token) & 0xffff:x}",
            target=urllib.parse.urlparse(url).netloc,
            type="JWT kid Injection Candidate",
            severity="medium",
            url=url,
            parameter="token",
            payload=token[:60],
            evidence=f"kid={header.get('kid')}, alg={alg}",
            response_snippet=str(header),
            confidence=0.6,
        ))
    log_event(urllib.parse.urlparse(url).netloc, "jwt_deep_scan", {"url": url, "findings": len(findings)})
    return findings

def scan_url(url):
    from scan.jwt import scan_url as base_scan
    findings = base_scan(url)
    # extract tokens from response
    import re
    r = get(url) if False else None
    from core.http import get
    resp = get(url)
    if resp.status == 0:
        return findings
    for m in re.finditer(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", resp.text or ""):
        findings.extend(scan_token(m.group(0), url))
    # dedup
    seen = set(); uniq = []
    for f in findings:
        if f.id in seen: continue
        seen.add(f.id); uniq.append(f)
    return uniq
