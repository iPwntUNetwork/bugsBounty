"""`BLITZ` — Active Vulnerability Hunter & WAF-Evading Scanner Agent.

Takes `GHOST`'s attack surface (or runs quick surface discovery if needed), hunts across:
  - Parameterized endpoints: SQLi, XSS, SSRF (with OOB canary), CMDi, SSTI, LFI/Traversal, Open Redirect
  - Locked 401/403 endpoints: `scan/bypass_403.py` header/path ACL bypasses
  - Base host exposures: YAML templates (`templates/engine.py` / `.bin/nuclei`), Nikto baseline, CORS, secrets
All HTTP probes coordinate through `PAYLOAD_MUTEX` + `core/waf_bypass.py` with automatic UA rotation.
"""
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.findings import Finding, FindingStore
from core.memory import set_phase
from core.telemetry import TELEMETRY
from scan import sqli, xss, ssrf, cmdi, ssti, lfi, bypass_403
from templates.engine import scan_target_with_templates
from agents.crew import CREW_BUS

PARAM_SCANNERS = [
    ("sqli", sqli.scan_url),
    ("xss", xss.scan_url),
    ("ssrf", ssrf.scan_url),
    ("cmdi", cmdi.scan_url),
    ("ssti", ssti.scan_url),
    ("lfi", lfi.scan_url),
]


def _scan_single_endpoint(url: str) -> list[Finding]:
    found: list[Finding] = []
    for name, fn in PARAM_SCANNERS:
        try:
            res = fn(url)
            for item in res:
                if not item.detected_by:
                    item.detected_by = f"hunter:{name}"
                found.append(item)
        except Exception:
            continue
    return found


def run_hunter(target: str, surface: dict | None = None, max_workers: int = 6) -> list[Finding]:
    start_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(start_url)
    host_label = parsed.netloc or target
    set_phase(host_label, "hunt")

    if surface is None:
        from agents.recon_agent import run_recon
        surface = run_recon(start_url)

    param_urls = list(surface.get("param_urls") or [])
    if "?" in start_url and start_url not in param_urls:
        param_urls.insert(0, start_url)
    locked_urls = list(surface.get("locked_urls") or [])

    with TELEMETRY.agent_scope("BLITZ", task=f"WAF-evading active scan on {host_label}", target=start_url, tool="swarm-scanners"):
        CREW_BUS.say(
            "BLITZ",
            f"Hold my Red Bull — firing multi-threaded WAF-bypassing scanners across {len(param_urls)} param URLs "
            f"and {len(locked_urls)} locked 403 gates on `{host_label}`!",
            kind="banter",
            to="SWITCH",
            target=host_label,
        )

        store = FindingStore(host_label)
        collected: list[Finding] = []

        TELEMETRY.set_agent_step("BLITZ", f"Scanning {len(param_urls)} parameterized endpoints (SQLi/XSS/SSRF/CMDi/SSTI/LFI)", tool="scan/*")
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(_scan_single_endpoint, u) for u in param_urls]
            for fut in as_completed(futs):
                for f in fut.result():
                    store.add(f)
                    collected.append(f)

        TELEMETRY.set_agent_step("BLITZ", f"Probing {len(locked_urls)} 401/403 ACL gates with header & path mutations", tool="bypass_403")
        for locked in locked_urls:
            for f in bypass_403.scan_url(locked):
                store.add(f)
                collected.append(f)

        TELEMETRY.set_agent_step("BLITZ", f"Running declarative YAML exposure rules against {start_url}", tool="nuclei")
        for f in scan_target_with_templates(start_url):
            store.add(f)
            collected.append(f)

        deduped = list({(f.type, f.url, f.parameter): f for f in collected}.values())
        for df in deduped:
            TELEMETRY.record_finding("lead", "BLITZ", df.type, df.url, detail=df.parameter or "")

        CREW_BUS.handoff(
            "BLITZ",
            "SWITCH",
            f"Bagged {len(deduped)} raw leads on `{host_label}`! SWITCH, spin up `.bin/sqlmap`, `.bin/dalfox` + BeEF hook, "
            "`.bin/commix`, and Interactsh OOB before RAZOR tries to moon me!",
            target=host_label,
            meta={"raw_findings": len(deduped)},
        )
        return deduped


run = run_hunter
