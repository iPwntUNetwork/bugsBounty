"""Recon agent: subdomains -> live hosts -> crawl -> endpoints + wayback + dirbust."""
from recon.subdomains import enumerate_subdomains
from recon.hosts import discover_live, probe_url
from recon.crawl import crawl
from recon.wayback import fetch_urls as wayback_urls
from recon.dirbust import brute as dirbust
from core.memory import log_event, recon_dir
import json, os

def run(target):
    t = target.replace("https://", "").replace("http://", "").strip().rstrip("/")
    if "/" in t:
        t = t.split("/")[0]
    domain = t
    hostpart = t.split(":")[0]
    rd = recon_dir(domain)
    is_domain = not _is_ip(hostpart)
    if is_domain and ":" not in domain:
        subs = enumerate_subdomains(hostpart, deep=True)
        hosts = discover_live(subs)
    else:
        subs = [domain]
        h = probe_url(domain)
        hosts = [h] if h else []
    (rd / "subdomains.txt").write_text("\n".join(subs))
    (rd / "live_hosts.json").write_text(json.dumps(hosts, indent=2))
    crawled = {}
    for h in hosts[:8]:
        url = h["url"]
        try:
            c = crawl(url)
            crawled[url] = c
        except Exception as e:
            crawled[url] = {"error": str(e)}
    (rd / "crawl.json").write_text(json.dumps(crawled, indent=2, default=str))
    try:
        wb = wayback_urls(hostpart)
        (rd / "wayback_urls.txt").write_text("\n".join(wb))
    except Exception:
        wb = []
    dirbust_results = []
    for h in hosts[:5]:
        try:
            dirbust_results.extend(dirbust(h["url"]))
        except Exception:
            pass
    (rd / "dirbust.json").write_text(json.dumps(dirbust_results, indent=2, default=str))
    log_event(domain, "recon_complete", {"subs": len(subs), "live": len(hosts), "crawled": len(crawled), "wayback": len(wb), "dirbust": len(dirbust_results)})
    return {"domain": domain, "subdomains": subs, "hosts": hosts, "crawled": crawled, "wayback": wb, "dirbust": dirbust_results}

def _is_ip(s):
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() for p in parts)
