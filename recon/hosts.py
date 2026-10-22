"""Live host discovery and tech fingerprinting."""
import concurrent.futures
from core.http import get, follow
from core.memory import log_event

INTERESTING_HEADERS = ["server", "x-powered-by", "x-framework", "x-generator", "via", "cf-ray", "x-amz-cf-id"]


def probe(host):
    # host may include port
    for scheme in ("http", "https"):
        # if host already has scheme? no
        url = f"{scheme}://{host}"
        r = get(url)
        if r.status != 0:
            info = _info(host, url, r)
            return info
    return None


def probe_url(host):
    return probe(host)


def _info(host, url, r):
    info = {
        "host": host,
        "url": url,
        "status": r.status,
        "title": _title(r.text),
        "server": r.headers.get("server", ""),
        "powered_by": r.headers.get("x-powered-by", ""),
        "content_type": r.headers.get("content-type", ""),
        "length": len(r.content or b""),
        "redirect": r.headers.get("location", ""),
        "headers": {k: v for k, v in r.headers.items() if k.lower() in INTERESTING_HEADERS},
    }
    info["tech"] = fingerprint(r)
    return info


def _title(html):
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    return (m.group(1).strip() if m else "")[:120]


def fingerprint(r):
    tech = []
    h = {k.lower(): v for k, v in (r.headers or {}).items()}
    body = (r.text or "").lower()
    server = h.get("server", "").lower()
    if "nginx" in server: tech.append("nginx")
    if "apache" in server: tech.append("apache")
    if "cloudflare" in h.get("server", "").lower() or "cf-ray" in h: tech.append("cloudflare")
    if "iis" in server: tech.append("iis")
    if "php" in h.get("x-powered-by", "").lower() or "php" in body[:500]: tech.append("php")
    if "asp.net" in h.get("x-powered-by", "").lower(): tech.append("aspnet")
    if "express" in h.get("x-powered-by", "").lower(): tech.append("express")
    if "django" in body or "csrfmiddlewaretoken" in body: tech.append("django")
    if "laravel" in body or "laravel_session" in (r.headers.get("set-cookie", "")).lower(): tech.append("laravel")
    if "wordpress" in body or "wp-content" in body: tech.append("wordpress")
    if "react" in body: tech.append("react")
    if "vue" in body: tech.append("vue")
    if "angular" in body: tech.append("angular")
    if "jquery" in body: tech.append("jquery")
    if "bootstrap" in body: tech.append("bootstrap")
    return tech


def discover_live(hosts, workers=20):
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe, h): h for h in hosts}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r:
                out.append(r)
    log_event("global", "live_hosts", {"count": len(out)})
    return out
