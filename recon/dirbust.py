"""Directory/endpoint brute-forcing."""
from core.http import get
from core.memory import log_event
import urllib.parse

COMMON_DIRS = [
    "admin", "api", "v1", "v2", "login", "dashboard", "config", "backup", "uploads",
    "static", "assets", "js", "css", "images", "img", "media", "files", "docs",
    "swagger", "openapi", "graphql", "actuator", "health", "metrics", "status",
    "debug", "test", "dev", "staging", "old", "backup.zip", "backup.sql", ".git",
    ".env", "robots.txt", "sitemap.xml", "crossdomain.xml", "phpinfo.php",
    "server-status", "wp-admin", "wp-login.php", "administrator", "panel",
]

def brute(base_url, wordlist=None, extensions=None):
    wl = wordlist or COMMON_DIRS
    exts = extensions or [""]
    found = []
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    for w in wl:
        for ext in exts:
            path = w + ext
            url = f"{root}/{path}"
            r = get(url)
            if r.status in (200, 301, 302, 307, 401, 403):
                found.append({"url": url, "status": r.status, "length": len(r.content or b"")})
    log_event(parsed.netloc, "dirbust", {"found": len(found)})
    return found
