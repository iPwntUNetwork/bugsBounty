"""Subdomain takeover candidate scanner."""
from core.http import get
from core.findings import Finding
from core.memory import log_event

FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "404 Web Site not found",
    "cloudfront.net": "Bad request",
    "fastly": "Fastly error: unknown domain",
    "shopify": "Sorry, this shop is currently unavailable",
    "tumblr.com": "There's nothing here",
    "wordpress.com": "Do you want to register",
    "bitbucket.io": "Repository not found",
    "pantheon.io": "The gods are wise",
    "surge.sh": "project not found",
    "netlify.app": "Not Found - Request ID",
    "vercel.app": "The deployment could not be found",
}

def scan_hosts(hosts):
    findings = []
    for host in hosts:
        r = get(f"https://{host}")
        if r.status == 0:
            r = get(f"http://{host}")
        if r.status == 0:
            continue
        text = r.text or ""
        for svc, fp in FINGERPRINTS.items():
            if fp.lower() in text.lower():
                findings.append(Finding(
                    id=f"takeover-{host}",
                    target=host,
                    type="Subdomain Takeover Candidate",
                    severity="high",
                    url=f"https://{host}",
                    parameter="host",
                    payload=svc,
                    evidence=f"Fingerprint matched: {fp}",
                    response_snippet=r.snippet(200),
                    confidence=0.6,
                ))
                break
    log_event("global", "takeover_scan", {"hosts": len(hosts), "findings": len(findings)})
    return findings
