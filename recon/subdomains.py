"""Subdomain enumeration: crt.sh, DNS brute, common list."""
import json, socket, concurrent.futures
from core.http import get
from core.memory import log_event

COMMON_SUBS = [
    "www", "api", "app", "admin", "dev", "staging", "test", "beta", "portal",
    "mail", "smtp", "ftp", "vpn", "cdn", "static", "assets", "img", "images",
    "blog", "docs", "help", "support", "status", "dashboard", "panel", "login",
    "auth", "sso", "oauth", "graphql", "api2", "v1", "v2", "mobile", "m",
    "shop", "store", "pay", "billing", "account", "accounts", "user", "users",
    "internal", "intranet", "corp", "office", "git", "gitlab", "jenkins",
    "ci", "cd", "build", "deploy", "k8s", "kubernetes", "docker", "registry",
    "db", "database", "mysql", "postgres", "redis", "elastic", "search",
    "backup", "backups", "old", "legacy", "new", "demo", "sandbox", "lab",
    "qa", "uat", "preprod", "prod", "production", "monitor", "monitoring",
    "grafana", "prometheus", "kibana", "logs", "metrics", "health", "ping",
    "webhook", "hooks", "callback", "ws", "wss", "socket", "realtime",
    "upload", "uploads", "files", "media", "download", "downloads",
]


def crtsh(domain):
    subs = set()
    try:
        r = get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        if r.status == 200 and r.text:
            data = json.loads(r.text)
            for e in data:
                name = e.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lstrip("*.")
                    if line.endswith(domain) and " " not in line:
                        subs.add(line.lower())
    except Exception:
        pass
    return subs


def dns_resolve(host):
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False


def brute(domain, wordlist=None, workers=30):
    wl = wordlist or COMMON_SUBS
    found = set()
    def check(sub):
        host = f"{sub}.{domain}"
        if dns_resolve(host):
            return host
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(check, wl):
            if res:
                found.add(res)
    return found


def enumerate_subdomains(domain, deep=True):
    subs = set()
    subs |= crtsh(domain)
    subs.add(domain)
    if deep:
        subs |= brute(domain)
    # resolve filter
    alive = set()
    for h in subs:
        if dns_resolve(h):
            alive.add(h)
    log_event(domain, "subdomains", {"count": len(alive)})
    return sorted(alive)
