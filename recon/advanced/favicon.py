"""Favicon hash for Shodan/Censys discovery."""
from core.http import get
from core.memory import log_event
import hashlib, base64
try:
    import mmh3
except Exception:
    mmh3 = None

def favicon_hash(url):
    """Compute MurmurHash3 of favicon for Shodan search."""
    parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url)
    root = "{}://{}".format(parsed.scheme, parsed.netloc)
    for path in ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]:
        r = get(root + path)
        if r.status == 200 and r.content:
            # mmh3 hash of base64-encoded favicon
            if mmh3 is not None:
                try:
                    h = mmh3.hash(base64.encodebytes(r.content))
                    log_event(root, "favicon_hash", {"hash": h, "path": path})
                    return h
                except Exception:
                    pass
            return hashlib.md5(r.content).hexdigest()
    return None
