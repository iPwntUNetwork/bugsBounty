"""Active spidering & hidden parameter discovery wiring `.bin/katana`, `.bin/hakrawler`, `.bin/arjun` + HTML/JS parser."""
import json
import re
import urllib.parse
from bs4 import BeautifulSoup
from core.http import get
from core.scope import in_scope
from core.memory import recon_dir, log_event
from tools.adapters import run_katana, run_hakrawler, run_arjun

JS_ENDPOINT_RE = re.compile(r"""(?:"|')((?:/|https?://)[A-Za-z0-9_./?=&%-]{2,160})(?:"|')""")


def crawl(start_url: str, max_pages: int = 40, discover_hidden_params: bool = True) -> dict:
    if "://" not in start_url:
        start_url = f"http://{start_url}"
    parsed_root = urllib.parse.urlparse(start_url)
    base_origin = f"{parsed_root.scheme}://{parsed_root.netloc}"

    visited = set()
    queue = [start_url]
    urls = set()
    param_urls = set()
    forms = []
    js_files = set()

    for external_spider in (lambda u: run_katana(u, depth=2, timeout=25), lambda u: run_hakrawler(u, depth=2, timeout=20)):
        try:
            for found in external_spider(start_url):
                full = urllib.parse.urljoin(base_origin, found)
                if urllib.parse.urlparse(full).netloc == parsed_root.netloc or in_scope(full):
                    urls.add(full)
                    if "?" in full and "=" in full:
                        param_urls.add(full)
                    if full.split("?", 1)[0].endswith(".js"):
                        js_files.add(full)
                    if len(queue) < max_pages * 2:
                        queue.append(full)
        except Exception:
            pass

    while queue and len(visited) < max_pages:
        u = queue.pop(0)
        if u in visited:
            continue
        visited.add(u)
        r = get(u)
        if r.status == 0:
            continue
        urls.add(u)
        if "?" in u and "=" in u:
            param_urls.add(u)
        ctype = r.headers.get("Content-Type", "").lower()
        body = r.text or ""
        if "html" in ctype or "<html" in body[:500].lower() or "<a " in body.lower():
            soup = BeautifulSoup(body, "lxml")
            for a in soup.find_all(["a", "link", "area"], href=True):
                nxt = urllib.parse.urljoin(u, a["href"]).split("#", 1)[0]
                if urllib.parse.urlparse(nxt).netloc == parsed_root.netloc:
                    urls.add(nxt)
                    if "?" in nxt and "=" in nxt:
                        param_urls.add(nxt)
                    if nxt not in visited:
                        queue.append(nxt)
            for sc in soup.find_all("script", src=True):
                js_url = urllib.parse.urljoin(u, sc["src"])
                if urllib.parse.urlparse(js_url).netloc == parsed_root.netloc:
                    js_files.add(js_url)
                    queue.append(js_url)
            for form in soup.find_all("form"):
                action = urllib.parse.urljoin(u, form.get("action") or u)
                method = (form.get("method") or "GET").upper()
                inputs = [inp.get("name") for inp in form.find_all(["input", "textarea", "select"]) if inp.get("name")]
                forms.append({"url": action, "method": method, "inputs": inputs})
                if inputs:
                    qs = "&".join(f"{urllib.parse.quote(i)}=1" for i in inputs)
                    synth = f"{action}{'&' if '?' in action else '?'}{qs}"
                    urls.add(synth)
                    param_urls.add(synth)

        for m in JS_ENDPOINT_RE.finditer(body):
            cand = urllib.parse.urljoin(u, m.group(1))
            if urllib.parse.urlparse(cand).netloc == parsed_root.netloc:
                urls.add(cand)
                if "?" in cand and "=" in cand:
                    param_urls.add(cand)
                elif cand not in visited and len(queue) < max_pages * 2:
                    queue.append(cand)

    if discover_hidden_params:
        parameterless = [
            u for u in sorted(urls)
            if "?" not in u and not any(u.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".ico", ".svg"))
        ][:8]
        for ep in parameterless:
            found_params = run_arjun(ep, method="GET", timeout=20)
            if found_params:
                qs = "&".join(f"{p}=1" for p in found_params)
                synth = f"{ep}?{qs}"
                urls.add(synth)
                param_urls.add(synth)

    out = {
        "start_url": start_url,
        "urls": sorted(urls),
        "param_urls": sorted(param_urls),
        "forms": forms,
        "js_files": sorted(js_files),
    }
    rd = recon_dir(parsed_root.netloc)
    (rd / "crawl.json").write_text(json.dumps(out, indent=2))
    (rd / "urls.txt").write_text("\n".join(sorted(urls)))
    (rd / "param_urls.txt").write_text("\n".join(sorted(param_urls)))
    log_event(parsed_root.netloc, "crawl", {"urls": len(urls), "param_urls": len(param_urls), "forms": len(forms)})
    return out
