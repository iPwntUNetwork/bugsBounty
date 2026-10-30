"""Historical URL & parameter mining wiring `.bin/waybackurls`, `.bin/gau`, and `.bin/paramspider`."""
import json
import urllib.parse
from core.http import get
from core.memory import recon_dir, log_event
from core.scope import SCOPE
from tools.adapters import run_waybackurls, run_gau, run_paramspider


def fetch_wayback(domain_or_url: str, timeout: int = 25) -> dict:
    parsed = urllib.parse.urlparse(domain_or_url if "://" in domain_or_url else f"http://{domain_or_url}")
    domain = parsed.hostname or domain_or_url
    urls = set()

    if "." in domain and domain not in ("localhost", "127.0.0.1"):
        for fn in (
            lambda d: run_waybackurls(d, timeout=timeout),
            lambda d: run_gau(d, timeout=timeout),
            lambda d: run_paramspider(d, timeout=timeout),
        ):
            try:
                urls.update(fn(domain))
            except Exception:
                pass
        try:
            r = get(
                f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=500",
                scope_exempt=True,
            )
            if r.status == 200 and r.text:
                urls.update(line.strip() for line in r.text.splitlines() if line.strip())
        except Exception:
            pass

    SCOPE.ensure_target(domain)
    all_urls = sorted(urls)
    in_scope_urls = set(SCOPE.filter_urls(all_urls, source="recon:wayback"))
    blocked = len(all_urls) - len(in_scope_urls)
    param_urls = sorted(u for u in in_scope_urls if "?" in u and "=" in u)
    out = {"domain": domain, "urls": sorted(in_scope_urls), "param_urls": param_urls, "blocked": blocked}
    rd = recon_dir(parsed.netloc or domain)
    (rd / "wayback.json").write_text(json.dumps(out, indent=2))
    log_event(parsed.netloc or domain, "wayback", {"urls": len(in_scope_urls), "param_urls": len(param_urls), "blocked": blocked})
    return out


wayback_urls = fetch_wayback
