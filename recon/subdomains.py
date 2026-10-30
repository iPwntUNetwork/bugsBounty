"""Subdomain enumeration wiring `.bin/subfinder`, `.bin/assetfinder`, `.bin/dnsx`, crt.sh & passive sources."""
import json
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import get
from core.memory import recon_dir, log_event
from core.scope import SCOPE
from tools.adapters import run_subfinder, run_assetfinder, run_dnsx


def _clean_host(target: str) -> str:
    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    return (parsed.hostname or target).strip().lower()


def from_crtsh(domain: str) -> set[str]:
    subs = set()
    try:
        r = get(f"https://crt.sh/?q=%25.{domain}&output=json", scope_exempt=True)
        if r.status == 200 and r.text:
            for row in json.loads(r.text):
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain):
                        subs.add(name)
    except Exception:
        pass
    return subs


def resolve(host: str):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def enumerate_subdomains(domain: str, resolve_only: bool = True) -> list[dict]:
    domain = _clean_host(domain)
    subs = {domain}
    if "." in domain and domain not in ("localhost", "127.0.0.1"):
        for fn in (run_subfinder, run_assetfinder, from_crtsh):
            try:
                subs.update(fn(domain))
            except Exception:
                pass

    # Scope gate: passive sources happily return unrelated hosts — never resolve or probe them.
    SCOPE.ensure_target(domain)
    in_scope_subs = {h for h in subs if SCOPE.allows_host(h, source="recon:subdomains")}
    dropped = len(subs) - len(in_scope_subs)
    if dropped:
        log_event(domain, "scope_blocked_subdomains", {"count": dropped, "kept": len(in_scope_subs)})
    subs = in_scope_subs

    resolved_map: dict[str, list[str]] = {}
    dnsx_rows = run_dnsx(sorted(subs))
    for row in dnsx_rows:
        host = row.get("host", "")
        if host:
            resolved_map[host] = row.get("a") or []

    out = []
    with ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(resolve, h): h for h in sorted(subs)}
        for fut in as_completed(futs):
            h = futs[fut]
            ip = fut.result()
            if ip:
                ips = resolved_map.get(h) or [ip]
                out.append({"host": h, "ip": ips[0], "ips": ips})
            elif not resolve_only:
                out.append({"host": h, "ip": None, "ips": []})

    out.sort(key=lambda x: x["host"])
    rd = recon_dir(domain)
    (rd / "subdomains.txt").write_text("\n".join(x["host"] for x in out))
    (rd / "subdomains.json").write_text(json.dumps(out, indent=2))
    log_event(domain, "subdomains", {"count": len(out)})
    return out
