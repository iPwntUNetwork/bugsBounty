"""Default credentials scanner."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("root", "root"),
    ("root", "toor"), ("test", "test"), ("guest", "guest"), ("user", "user"),
    ("administrator", "administrator"), ("admin", "admin123"),
]

LOGIN_PATHS = ["/login", "/admin", "/admin/login", "/signin", "/auth", "/wp-login.php"]

def scan_base(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    for path in LOGIN_PATHS:
        url = root + path
        r = get(url)
        if r.status != 200:
            continue
        for user, pwd in DEFAULT_CREDS:
            # try form POST
            resp = post(url, data={"username": user, "password": pwd, "user": user, "pass": pwd, "login": "Login"})
            if resp.status == 0:
                continue
            text = (resp.text or "").lower()
            # success indicators
            if any(k in text for k in ["dashboard", "welcome", "logout", "profile", "admin panel"]) and "invalid" not in text and "error" not in text:
                findings.append(Finding(
                    id=f"defaultcreds-{user}-{hash(url) & 0xffff:x}",
                    target=parsed.netloc,
                    type="Default Credentials",
                    severity="critical",
                    url=url,
                    parameter="username/password",
                    payload=f"{user}:{pwd}",
                    evidence=f"Login accepted with default creds (status {resp.status})",
                    response_snippet=resp.snippet(200),
                    confidence=0.6,
                ))
                break
    log_event(parsed.netloc, "default_creds_scan", {"base": base_url, "findings": len(findings)})
    return findings
