"""Stage 2 — Active Vulnerability Hunting & WAF-Evading Scanning (single `AGENT`).

Takes the recon stage's attack surface (or runs quick surface discovery itself), hunting across:
  - Parameterized endpoints: SQLi, XSS, SSRF (with OOB canary), CMDi, SSTI, LFI/Traversal, Open Redirect
  - Locked 401/403 endpoints: `scan/bypass_403.py` header/path ACL bypasses
  - Base host exposures: YAML templates (`templates/engine.py` / `.bin/nuclei`), Nikto baseline, CORS, secrets
All HTTP probes coordinate through `PAYLOAD_MUTEX` + `core/waf_bypass.py` with automatic UA rotation.
"""
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.findings import Finding, FindingStore
from core.memory import set_phase
from core.scope import SCOPE
from core.telemetry import TELEMETRY
from scan import sqli, xss, ssrf, cmdi, ssti, lfi, bypass_403
from templates.engine import scan_target_with_templates
from agents.agent import AGENT_BUS, AGENT_HANDLE

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

    SCOPE.ensure_target(start_url)
    blocked_before = SCOPE.blocked_count

    # Scope gate: the hunter only ever touches the target's own domain.
    param_urls = SCOPE.filter_urls(list(surface.get("param_urls") or []), source="hunt:params")
    if "?" in start_url and start_url not in param_urls and SCOPE.is_in_scope(start_url, source="hunt:start"):
        param_urls.insert(0, start_url)
    locked_urls = SCOPE.filter_urls(list(surface.get("locked_urls") or []), source="hunt:locked")

    with TELEMETRY.agent_scope(AGENT_HANDLE, task=f"Stage 2/6 · Hunting on {host_label}", target=start_url, tool="swarm-scanners", stage="hunt"):
        AGENT_BUS.stage_started(
            "hunt",
            f"scanning {len(param_urls)} parameterized endpoints and {len(locked_urls)} locked 403 gates on `{host_label}`",
            target=host_label,
        )

        store = FindingStore(host_label)
        collected: list[Finding] = []

        TELEMETRY.set_agent_step(AGENT_HANDLE, f"Scanning {len(param_urls)} parameterized endpoints (SQLi/XSS/SSRF/CMDi/SSTI/LFI)", tool="scan/*")
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(_scan_single_endpoint, u) for u in param_urls]
            for fut in as_completed(futs):
                for f in fut.result():
                    store.add(f)
                    collected.append(f)

        TELEMETRY.set_agent_step(AGENT_HANDLE, f"Probing {len(locked_urls)} 401/403 ACL gates with header & path mutations", tool="bypass_403")
        for locked in locked_urls:
            for f in bypass_403.scan_url(locked):
                store.add(f)
                collected.append(f)

        TELEMETRY.set_agent_step(AGENT_HANDLE, f"Running declarative YAML exposure rules against {start_url}", tool="nuclei")
        for f in scan_target_with_templates(start_url):
            store.add(f)
            collected.append(f)

        deduped = list({(f.type, f.url, f.parameter): f for f in collected}.values())
        for df in deduped:
            TELEMETRY.record_finding("lead", AGENT_HANDLE, df.type, df.url, detail=df.parameter or "")

        blocked_this_stage = SCOPE.blocked_count - blocked_before
        scope_note = f" ({blocked_this_stage} out-of-scope asset(s) skipped)" if blocked_this_stage else ""
        AGENT_BUS.stage_done(
            "hunt",
            f"{len(deduped)} raw leads collected on `{host_label}`{scope_note}. Moving to tool escalation.",
            target=host_label,
        )
        return deduped


run = run_hunter
