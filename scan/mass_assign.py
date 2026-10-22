"""Mass assignment scanner."""
from core.http import post, get
from core.findings import Finding
from core.memory import log_event
import urllib.parse, json

EXTRA_FIELDS = ["isAdmin", "is_admin", "role", "admin", "privileged", "verified", "active", "balance", "credit"]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # try POST with extra fields
    for field in EXTRA_FIELDS:
        data = {field: "true" if field not in ("balance", "credit") else "99999"}
        r = post(url, data=data)
        if r.status == 0:
            continue
        text = (r.text or "").lower()
        if field.lower() in text and ("true" in text or "99999" in text):
            findings.append(Finding(
                id=f"massassign-{field}-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="Mass Assignment (potential)",
                severity="medium",
                url=url,
                parameter=field,
                payload=f"{field}=true",
                evidence="Extra field accepted/reflected",
                response_snippet=r.snippet(200),
                confidence=0.4,
            ))
    log_event(parsed.netloc, "mass_assign_scan", {"url": url, "findings": len(findings)})
    return findings
