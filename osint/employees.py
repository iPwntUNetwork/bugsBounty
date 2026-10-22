"""OSINT: employee names, emails, breach data."""
from core.http import get
from core.memory import log_event
import re, urllib.parse

def harvest_emails(domain):
    emails = set()
    # Google dork style via search (best effort)
    # Check common patterns
    patterns = [r"[a-zA-Z0-9._%+-]+@" + re.escape(domain)]
    # Hunter.io (if API key)
    import os
    hunter_key = os.environ.get("HUNTER_API_KEY", "")
    if hunter_key:
        try:
            r = get("https://api.hunter.io/v2/domain-search?domain={}&api_key={}".format(domain, hunter_key))
            if r.status == 200:
                import json
                data = json.loads(r.text)
                for e in data.get("data", {}).get("emails", []):
                    emails.add(e.get("value"))
        except Exception:
            pass
    log_event(domain, "osint_emails", {"count": len(emails)})
    return sorted(emails)

def breach_check(email):
    """Check HIBP (k-anonymity)."""
    import hashlib
    prefix = hashlib.sha1(email.encode()).hexdigest().upper()[:5]
    try:
        r = get("https://api.pwnedpasswords.com/range/{}".format(prefix))
        if r.status == 200:
            for line in r.text.splitlines():
                h, count = line.strip().split(":")
                if h == hashlib.sha1(email.encode()).hexdigest().upper()[5:]:
                    return int(count)
    except Exception:
        pass
    return 0

def github_recon(org):
    """Search GitHub for secrets in org repos."""
    findings = []
    try:
        r = get("https://api.github.com/search/code?q=org:{}+password+OR+secret+OR+token+OR+api_key".format(org))
        if r.status == 200:
            import json
            data = json.loads(r.text)
            for item in data.get("items", [])[:20]:
                findings.append({"repo": item.get("repository", {}).get("full_name"), "path": item.get("path"), "url": item.get("html_url")})
    except Exception:
        pass
    log_event(org, "github_recon", {"findings": len(findings)})
    return findings
