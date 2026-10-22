"""URL crawler: extracts links, forms, JS endpoints, params."""
import re, urllib.parse, concurrent.futures
from bs4 import BeautifulSoup
from core.http import get
from core.memory import log_event

MAX_PAGES = 60


def _same_domain(url, base):
    try:
        return urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(base).netloc or not urllib.parse.urlparse(url).netloc
    except Exception:
        return False


def crawl(start_url, max_pages=MAX_PAGES):
    base = start_url
    seen = set()
    queue = [start_url]
    urls = set([start_url])
    forms = []
    js_files = set()
    params = set()
    endpoints = set()
    # interesting file extensions
    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        r = get(url)
        if r.status == 0 or r.status >= 400:
            continue
        ct = r.headers.get("content-type", "")
        if "html" not in ct and "text" not in ct:
            continue
        # params from url
        q = urllib.parse.urlparse(url).query
        if q:
            for k in urllib.parse.parse_qs(q):
                params.add(k)
        try:
            soup = BeautifulSoup(r.text, "lxml")
        except Exception:
            soup = BeautifulSoup(r.text, "html.parser")
        # links
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            full = urllib.parse.urljoin(url, href)
            if _same_domain(full, base):
                if full not in seen and full not in urls:
                    urls.add(full)
                    queue.append(full)
        # forms
        for form in soup.find_all("form"):
            action = urllib.parse.urljoin(url, form.get("action", ""))
            method = (form.get("method") or "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({"name": name, "type": inp.get("type", "text"), "value": inp.get("value", "")})
                    params.add(name)
            forms.append({"page": url, "action": action, "method": method, "inputs": inputs})
        # scripts
        for s in soup.find_all("script", src=True):
            js = urllib.parse.urljoin(url, s["src"])
            js_files.add(js)
        # inline endpoints in js-ish text
        for m in re.finditer(r'["\'](/(?:api|v\d|graphql|rest|endpoint)[^"\']*)["\']', r.text):
            endpoints.add(urllib.parse.urljoin(base, m.group(1)))
        # generic path-ish
        for m in re.finditer(r'fetch\(["\']([^"\']+)["\']', r.text):
            endpoints.add(urllib.parse.urljoin(base, m.group(1)))
        for m in re.finditer(r'axios\.[a-z]+\(["\']([^"\']+)["\']', r.text):
            endpoints.add(urllib.parse.urljoin(base, m.group(1)))
    # fetch js files and extract endpoints/params
    for js in list(js_files)[:40]:
        r = get(js)
        if r.status == 200:
            for m in re.finditer(r'["\'](/[a-zA-Z0-9_\-./?=&%]+)["\']', r.text):
                pth = m.group(1)
                if len(pth) < 200:
                    endpoints.add(urllib.parse.urljoin(base, pth))
            for m in re.finditer(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', r.text):
                params.add(m.group(1))
    log_event(base, "crawl", {"pages": len(seen), "forms": len(forms), "js": len(js_files), "params": len(params)})
    return {
        "start": start_url,
        "pages": sorted(urls),
        "forms": forms,
        "js_files": sorted(js_files),
        "params": sorted(params),
        "endpoints": sorted(endpoints),
    }
