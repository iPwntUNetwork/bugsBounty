"""Exposed sensitive files scanner."""
from core.http import get
from scan.payloads import SENSITIVE_FILES
from core.findings import Finding
from core.memory import log_event
import urllib.parse, uuid

def scan_base(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    # soft-404 baseline
    baseline = get(f"{root}/.this_should_not_exist_{uuid.uuid4().hex}")
    baseline_body = baseline.text if baseline.status == 200 else None
    baseline_len = len(baseline.content or b"")
    for f in SENSITIVE_FILES:
        url = f"{root}/{f}"
        r = get(url)
        if r.status == 0:
            continue
        if r.status != 200 or not r.content:
            continue
        # soft 404 filter
        if baseline_body is not None and r.text == baseline_body:
            continue
        if baseline_len > 0 and len(r.content) == baseline_len and r.text == baseline_body:
            continue
        # generic not found text
        text = r.text or ""
        if "404" in text.lower() and "not found" in text.lower():
            continue
        # require some content difference from baseline
        if baseline_body is not None and len(text) < 5:
            continue
        sev = "high" if f in (".env", ".git/config", "id_rsa", ".aws/credentials", "backup.sql", "db.sql", "dump.sql", "secrets.yml") else "medium"
        if f in ("robots.txt", "sitemap.xml", "package.json", "composer.json"):
            sev = "info"
        findings.append(Finding(
            id=f"file-{f}-{hash(url) & 0xffff:x}",
            target=parsed.netloc,
            type="Exposed Sensitive File",
            severity=sev,
            url=url,
            parameter="path",
            payload=f,
            evidence=f"HTTP {r.status}, {len(r.content)} bytes",
            response_snippet=r.snippet(200),
            confidence=0.7,
        ))
    log_event(parsed.netloc, "files_scan", {"base": base_url, "findings": len(findings)})
    return findings

scan_url = scan_base
