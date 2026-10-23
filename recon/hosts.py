"""Live host probing wiring `.bin/httpx` (with tech/status/title/CDN) + fallback HTTP prober."""
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import get
from core.memory import recon_dir, log_event
from tools.adapters import run_httpx

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def probe_one(url_or_host: str) -> dict | None:
    targets = [url_or_host] if "://" in url_or_host else [f"https://{url_or_host}", f"http://{url_or_host}"]
    for u in targets:
        r = get(u)
        if r.status > 0:
            m = TITLE_RE.search(r.text or "")
            return {
                "url": u,
                "status_code": r.status,
                "status": r.status,
                "title": m.group(1).strip()[:120] if m else "",
                "server": r.headers.get("Server", ""),
                "tech": [t for t in [r.headers.get("Server", ""), r.headers.get("X-Powered-By", "")] if t],
                "content_length": len(r.text or ""),
            }
    return None


def probe_hosts(target: str, hosts: list[str] | None = None) -> list[dict]:
    rd = recon_dir(target)
    if hosts is None:
        sub_file = rd / "subdomains.txt"
        hosts = [x.strip() for x in sub_file.read_text().splitlines() if x.strip()] if sub_file.exists() else [target]

    alive = []
    seen = set()
    httpx_rows = run_httpx(hosts, timeout=30)
    for row in httpx_rows:
        u = row.get("url")
        if u and u not in seen:
            seen.add(u)
            alive.append({
                "url": u,
                "status_code": row.get("status_code") or row.get("status", 0),
                "status": row.get("status_code") or row.get("status", 0),
                "title": row.get("title", ""),
                "server": row.get("webserver", ""),
                "tech": row.get("tech") or [],
                "content_length": row.get("content_length", 0),
            })

    if not alive:
        with ThreadPoolExecutor(max_workers=16) as ex:
            for fut in as_completed([ex.submit(probe_one, h) for h in hosts]):
                res = fut.result()
                if res and res["url"] not in seen:
                    seen.add(res["url"])
                    alive.append(res)

    (rd / "live_hosts.json").write_text(json.dumps(alive, indent=2))
    (rd / "alive.json").write_text(json.dumps(alive, indent=2))
    (rd / "alive.txt").write_text("\n".join(x["url"] for x in alive))
    log_event(target, "probe_hosts", {"alive": len(alive)})
    return alive
