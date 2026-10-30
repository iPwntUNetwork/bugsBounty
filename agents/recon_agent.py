"""Stage 1 — Recon & Attack-Surface Mapping (single `AGENT`).

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
from core.telemetry import TELEMETRY
from recon.subdomains import enumerate_subdomains
from recon.hosts import probe_hosts
from recon.crawl import crawl
from recon.dirbust import dirbust
from recon.wayback import fetch_wayback
from scan.waf import detect_waf
from agents.agent import AGENT_BUS, AGENT_HANDLE


def run_recon(target: str, max_pages: int = 35, run_dirbust: bool = True, discover_params: bool = True) -> dict:
    set_phase(target, "recon")
    start_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(start_url)
    host_label = parsed.netloc or target

    with TELEMETRY.agent_scope(AGENT_HANDLE, task=f"Stage 1/6 · Recon on {host_label}", target=start_url, tool="subfinder", stage="recon"):
        AGENT_BUS.stage_started("recon", f"mapping `{start_url}`", target=host_label)

        TELEMETRY.set_agent_step(AGENT_HANDLE, f"Subdomain & DNS enumeration on {host_label}", tool="subfinder/dnsx")
        subs = enumerate_subdomains(host_label)
        TELEMETRY.set_agent_step(AGENT_HANDLE, f"Live HTTP host probing on {start_url}", tool="httpx")
        alive = probe_hosts(host_label, [start_url])
        TELEMETRY.set_agent_step(AGENT_HANDLE, f"Fingerprinting WAF vendor on {start_url}", tool="wafw00f")
        waf_info = detect_waf(start_url)
        if waf_info.get("detected"):
            AGENT_BUS.say(
                f"`{waf_info['waf']}` detected in front of `{start_url}`. "
                "`PAYLOAD_MUTEX` primed with stealth UAs and the vendor tamper chain.",
                kind="waf",
                stage="recon",
                target=host_label,
            )

        TELEMETRY.set_agent_step(AGENT_HANDLE, f"Spidering & hidden param discovery (max_pages={max_pages})", tool="katana/arjun")
        crawled = crawl(start_url, max_pages=max_pages, discover_hidden_params=discover_params)
        TELEMETRY.set_agent_step(AGENT_HANDLE, f"Calibrated directory & 403 gate fuzzing on {host_label}", tool="ffuf/gobuster")
        dirs = dirbust(start_url) if run_dirbust else []
        TELEMETRY.set_agent_step(AGENT_HANDLE, f"Mining historical URLs & query parameters on {host_label}", tool="gau/waybackurls")
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

        AGENT_BUS.stage_done(
            "recon",
            f"{len(all_urls)} URLs, {len(param_urls)} parameterized endpoints, "
            f"{len(locked_urls)} locked 401/403 gates, WAF={waf_info.get('waf')}. Moving to hunting.",
            target=host_label,
        )
        return surface


run = run_recon
