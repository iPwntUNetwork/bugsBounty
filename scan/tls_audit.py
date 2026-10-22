"""TLS/SSL audit: weak ciphers, cert issues, protocol versions."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse, ssl, socket

def scan_host(host, port=443):
    findings = []
    # cert info
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                cipher = ssock.cipher()
                # weak protocol
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(Finding(
                        id="tls-weakproto-{}".format(hash(host) & 0xffff),
                        target=host,
                        type="Weak TLS Protocol",
                        severity="medium",
                        url="https://{}:{}".format(host, port),
                        parameter="tls",
                        payload=proto,
                        evidence="Server supports {}".format(proto),
                        response_snippet="",
                        confidence=0.9,
                    ))
                # weak cipher
                if cipher and ("RC4" in cipher[0] or "3DES" in cipher[0] or "NULL" in cipher[0] or "EXPORT" in cipher[0] or "anon" in cipher[0]):
                    findings.append(Finding(
                        id="tls-weakcipher-{}".format(hash(host) & 0xffff),
                        target=host,
                        type="Weak TLS Cipher",
                        severity="medium",
                        url="https://{}:{}".format(host, port),
                        parameter="cipher",
                        payload=cipher[0],
                        evidence="Weak cipher: {}".format(cipher[0]),
                        response_snippet="",
                        confidence=0.9,
                    ))
                # cert expiry
                import datetime
                not_after = cert.get("notAfter")
                if not_after:
                    exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    if exp < datetime.datetime.utcnow():
                        findings.append(Finding(
                            id="tls-expired-{}".format(hash(host) & 0xffff),
                            target=host,
                            type="Expired TLS Certificate",
                            severity="medium",
                            url="https://{}:{}".format(host, port),
                            parameter="cert",
                            payload=not_after,
                            evidence="Certificate expired on {}".format(not_after),
                            response_snippet="",
                            confidence=0.99,
                        ))
    except Exception as e:
        pass
    log_event(host, "tls_audit", {"host": host, "findings": len(findings)})
    return findings

def scan_url(url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port == 80:
        return []
    return scan_host(host, port)
