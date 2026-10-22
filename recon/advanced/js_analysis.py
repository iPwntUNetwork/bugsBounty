"""JavaScript analysis: extract endpoints, secrets, source maps."""
from core.http import get
from core.memory import log_event
import re, urllib.parse

def analyze_js(url):
    findings_endpoints = set()
    secrets = []
    r = get(url)
    if r.status != 200:
        return {"endpoints": [], "secrets": [], "sourcemaps": []}
    text = r.text or ""
    # endpoints
    for m in re.finditer(r'["\'](/[a-zA-Z0-9_\-./?=&%]+)["\']', text):
        p = m.group(1)
        if len(p) < 200 and not p.endswith((".js", ".css", ".png", ".jpg")):
            findings_endpoints.add(p)
    for m in re.finditer(r'fetch\(["\']([^"\']+)["\']', text):
        findings_endpoints.add(m.group(1))
    for m in re.finditer(r'axios\.[a-z]+\(["\']([^"\']+)["\']', text):
        findings_endpoints.add(m.group(1))
    # secrets
    secret_patterns = [
        (r'AKIA[0-9A-Z]{16}', "AWS Key"),
        (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
        (r'gh[pousr]_[A-Za-z0-9]{36,}', "GitHub Token"),
        (r'sk-[A-Za-z0-9]{20,}', "OpenAI Key"),
        (r'xox[baprs]-[0-9A-Za-z-]{10,}', "Slack Token"),
    ]
    for pat, name in secret_patterns:
        for m in re.finditer(pat, text):
            secrets.append({"type": name, "value": m.group(0)[:40]})
    # source maps
    sourcemaps = []
    m = re.search(r'//# sourceMappingURL=(.+)', text)
    if m:
        sm_url = urllib.parse.urljoin(url, m.group(1).strip())
        sourcemaps.append(sm_url)
    log_event(url, "js_analysis", {"endpoints": len(findings_endpoints), "secrets": len(secrets)})
    return {"endpoints": sorted(findings_endpoints), "secrets": secrets, "sourcemaps": sourcemaps}

def scan_page(url):
    r = get(url)
    if r.status != 200:
        return []
    # find script srcs
    import re as _re
    scripts = _re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text or "")
    results = []
    for s in scripts[:20]:
        full = urllib.parse.urljoin(url, s)
        results.append({"script": full, "analysis": analyze_js(full)})
    return results
