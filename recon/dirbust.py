"""Directory & hidden content fuzzing wiring `.bin/ffuf` and `.bin/gobuster` with smart 404 calibration."""
import json
import urllib.parse
from core.http import get
from core.memory import recon_dir, log_event
from tools.adapters import run_ffuf, run_gobuster
from tools.wordlists import ensure_wordlist


def dirbust(base_url: str, wordlist: str | None = None, timeout: int = 35) -> list[dict]:
    if "://" not in base_url:
        base_url = f"http://{base_url}"
    base_url = base_url.rstrip("/")
    parsed = urllib.parse.urlparse(base_url)

    hits_by_url: dict[str, dict] = {}
    for row in run_ffuf(base_url, wordlist=wordlist, timeout=timeout):
        u = row.get("url", "")
        if u:
            hits_by_url[u] = {"url": u, "status": row.get("status", 0), "length": row.get("length", 0), "source": "ffuf"}

    if not hits_by_url:
        for row in run_gobuster(base_url, wordlist=wordlist, timeout=timeout):
            u = f"{base_url}/{row['path'].lstrip('/')}"
            hits_by_url[u] = {"url": u, "status": row.get("status", 0), "length": row.get("length", 0), "source": "gobuster"}

    if not hits_by_url:
        wl_path = wordlist or str(ensure_wordlist("directories"))
        notfound = get(f"{base_url}/definitely-nonexistent-bb-canary-998172")
        nf_len = len(notfound.text or "")
        for word in open(wl_path).read().splitlines()[:120]:
            word = word.strip().lstrip("/")
            if not word:
                continue
            u = f"{base_url}/{word}"
            r = get(u)
            if r.status in (200, 204, 301, 302, 307, 401, 403) and abs(len(r.text or "") - nf_len) > 15:
                hits_by_url[u] = {"url": u, "status": r.status, "length": len(r.text or ""), "source": "builtin"}

    out = sorted(hits_by_url.values(), key=lambda x: (x["status"], x["url"]))
    rd = recon_dir(parsed.netloc)
    (rd / "dirbust.json").write_text(json.dumps(out, indent=2))
    log_event(parsed.netloc, "dirbust", {"hits": len(out)})
    return out
