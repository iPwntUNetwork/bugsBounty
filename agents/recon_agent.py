"""`GHOST` — Recon & Attack-Surface Cartographer Agent.

Wires `.bin/` binaries directly into a cohesive attack-surface discovery pipeline:
  1. Subdomain & DNS mapping (`subfinder` + `assetfinder` + `dnsx` + `crt.sh`)
  2. Live host & tech fingerprinting (`httpx`)
  3. WAF vendor detection (`wafw00f` + 20-vendor signature probe -> primes `PAYLOAD_MUTEX`)
  4. Active spidering + JS endpoint extraction + hidden parameter mining (`katana` + `hakrawler` + `arjun`)
  5. Directory & locked-endpoint fuzzing (`ffuf` + `gobuster`)
  6. Historical URL & parameter mining (`waybackurls` + `gau` + `paramspider`)
"""
import json
import urllib.parse
from core.memory import recon_dir, set_phase
from recon.subdomains import enumerate_subdomains
from recon.hosts import probe_hosts
from recon.crawl import crawl
from recon.dirbust import dirbust
from recon.wayback import fetch_wayback
from scan.waf import detect_waf
from agents.crew import CREW_BUS


def run_recon(target: str, max_pages: int = 35, run_dirbust: bool = True, discover_params: bool = True) -> dict:
    set_phase(target, "recon")
    start_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(start_url)
    host_label = parsed.netloc or target

    CREW_BUS.say(
        "GHOST",
        f"Cracking third double-shot and lighting up `.bin/` recon array against `{start_url}` — "
        "keep your sticky fingers off the trigger till I map the hidden params, BLITZ.",
        kind="banter",
        to="BLITZ",
        target=host_label,
    )

    subs = enumerate_subdomains(host_label)
    alive = probe_hosts(host_label, [start_url])
    waf_info = detect_waf(start_url)
    if waf_info.get("detected"):
        CREW_BUS.say(
            "GHOST",
            f"Heads up BLITZ — `{waf_info['waf']}` is sitting right in front of `{start_url}`! "
            f"Primed `PAYLOAD_MUTEX` with stealth UAs + vendor tamper chain.",
            kind="waf",
            to="BLITZ",
            target=host_label,
        )

    crawled = crawl(start_url, max_pages=max_pages, discover_hidden_params=discover_params)
    dirs = dirbust(start_url) if run_dirbust else []
    wb = fetch_wayback(start_url)

    all_urls = set(crawled.get("urls", [])) | set(wb.get("urls", []))
    locked_urls = []
    for d in dirs:
        u = d.get("url", "")
        if u:
            all_urls.add(u)
            if d.get("status") in (401, 403):
                locked_urls.append(u)

    param_urls = sorted(
        {u for u in all_urls if "?" in u and "=" in u}
        | set(crawled.get("param_urls", []))
        | set(wb.get("param_urls", []))
    )

    surface = {
        "target": host_label,
        "start_url": start_url,
        "waf": waf_info,
        "subdomains": subs,
        "live_hosts": alive,
        "urls": sorted(all_urls),
        "param_urls": param_urls,
        "locked_urls": sorted(set(locked_urls)),
        "forms": crawled.get("forms", []),
        "js_files": crawled.get("js_files", []),
        "dirbust_hits": dirs,
    }

    rd = recon_dir(host_label)
    (rd / "surface.json").write_text(json.dumps(surface, indent=2))

    CREW_BUS.handoff(
        "GHOST",
        "BLITZ",
        f"Surface map locked for `{host_label}`: {len(all_urls)} URLs, {len(param_urls)} parameterized endpoints, "
        f"{len(locked_urls)} locked 401/403 gates, WAF={waf_info.get('waf')}. Tear it apart mate!",
        target=host_label,
        meta={"urls": len(all_urls), "param_urls": len(param_urls), "locked": len(locked_urls)},
    )
    return surface


run = run_recon
