"""Insecure deserialization scanner (basic)."""
from core.http import post, get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

JAVA_PAYLOAD = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubGFuZy5PYmplY3QAAAAAAAAAAQIAAHhw"
PHP_PAYLOAD = 'O:8:"stdClass":1:{s:4:"test";s:4:"poll";}'
PY_PAYLOAD = "cos\nsystem\n(S'id'\ntR."

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    for ct, payload, name in [("application/x-java-serialized-object", JAVA_PAYLOAD, "Java"),
                              ("application/php-serialized", PHP_PAYLOAD, "PHP")]:
        r = post(url, data=payload, headers={"Content-Type": ct})
        if r.status == 0:
            continue
        text = (r.text or "").lower()
        if any(e in text for e in ["exception", "deserialization", "classnotfound", "unserialize", "traceback", "error"]):
            findings.append(Finding(
                id=f"deser-{name}-{hash(url) & 0xffff:x}",
                target=parsed.netloc,
                type=f"Insecure Deserialization ({name})",
                severity="high",
                url=url,
                parameter="body",
                payload=payload[:60],
                evidence="Deserialization error in response",
                response_snippet=r.snippet(300),
                confidence=0.5,
            ))
    log_event(parsed.netloc, "deser_scan", {"url": url, "findings": len(findings)})
    return findings
