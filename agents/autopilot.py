"""`AUTOPILOT` — Full single-agent pipeline (one agent, six ordered stages).

The agent runs the complete offensive workflow end-to-end under one identity:
  Stage 1 (`recon`)    : Attack-surface mapping (`subfinder`, `assetfinder`, `dnsx`, `httpx`, `wafw00f`,
                         `katana`, `hakrawler`, `arjun`, `ffuf`, `gobuster`, `waybackurls`, `gau`, `paramspider`)
  Stage 2 (`hunt`)     : Active WAF-evading vulnerability hunting (`PAYLOAD_MUTEX` + 24 tampers + UA rotation)
  Stage 3 (`escalate`) : Heavy-tool confirmation (`sqlmap`, `dalfox` + live `BeefServer`, `commix`, `interactsh`/OOB)
  Stage 4 (`verify`)   : 100% Deterministic control-probe verification (no LLM calls, no self-certification)
  Stage 5 (`chains`)   : Multi-step exploit chain synthesis on verified findings ONLY
  Stage 6 (`report`)   : CVSS v3.1 triage, reproducible PoCs, transcript & Markdown report
"""
import urllib.parse

from core.findings import FindingStore
from core.memory import set_phase
from core.telemetry import TELEMETRY
from agents.agent import AGENT_BUS, AGENT_HANDLE, STAGE_COUNT
from agents.recon_agent import run_recon
from agents.hunter import run_hunter
from agents.escalator import run_escalator
from agents.critic import run_critic
from chains.builder import build_chains
from agents.poc_generator import generate_pocs
from agents.triage import triage_findings
from agents.reporter import generate_report


def run_autopilot(
    target: str,
    max_pages: int = 35,
    run_dirbust: bool = True,
    discover_params: bool = True,
    report_out: str | None = None,
) -> dict:
    start_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(start_url)
    host_label = parsed.netloc or target

    with TELEMETRY.agent_scope(AGENT_HANDLE, task=f"Autopilot ({STAGE_COUNT} stages) on {host_label}", target=start_url, tool="autopilot"):
        AGENT_BUS.say(
            f"Autopilot engaged on `{start_url}` — running recon, hunting, escalation, verification, "
            "chaining and reporting as one agent.",
            kind="info",
            target=host_label,
        )

        # 1. Recon + WAF fingerprinting
        surface = run_recon(
            start_url,
            max_pages=max_pages,
            run_dirbust=run_dirbust,
            discover_params=discover_params,
        )
        waf_vendor = (surface.get("waf") or {}).get("waf") or "generic"

        # 2. Active hunting
        raw_findings = run_hunter(start_url, surface=surface)

        # 3. Tool escalation
        escalated_findings = run_escalator(start_url, raw_findings, waf_vendor=waf_vendor)

        # 4. Deterministic verification (the detector never certifies itself)
        audit = run_critic(host_label, escalated_findings)
        verified = audit["verified"]
        disproved = audit["disproved"]

        # Persist verified findings cleanly
        store = FindingStore(host_label)
        for vf in verified:
            store.add(vf)

        # 5. Multi-step attack chains
        with TELEMETRY.agent_scope(
            AGENT_HANDLE,
            task=f"Stage 5/{STAGE_COUNT} · Synthesising chains on {host_label}",
            target=start_url,
            tool="chain-builder",
            stage="chains",
        ):
            AGENT_BUS.stage_started("chains", f"correlating {len(verified)} verified findings", target=host_label)
            set_phase(host_label, "chains")
            chains = build_chains(host_label, verified)
            AGENT_BUS.stage_done(
                "chains",
                f"{len(chains)} multi-step chain(s) built. Moving to triage and reporting.",
                target=host_label,
            )

        # 6. Triage + PoCs + final Markdown advisory
        with TELEMETRY.agent_scope(
            AGENT_HANDLE,
            task=f"Stage 6/{STAGE_COUNT} · Scoring & reporting on {host_label}",
            target=start_url,
            tool="reporter",
            stage="report",
        ):
            AGENT_BUS.stage_started("report", "computing CVSS v3.1, PoCs and the Markdown advisory", target=host_label)
            set_phase(host_label, "report")
            triaged = triage_findings(host_label, verified)
            pocs = generate_pocs(host_label, verified)
            transcript_path = AGENT_BUS.save(host_label)
            report_path = generate_report(
                start_url,
                verified_findings=verified,
                chains=chains,
                pocs=pocs,
                disproved=disproved,
                waf_info=surface.get("waf"),
                out_path=report_out,
            )
            AGENT_BUS.stage_done(
                "report",
                f"advisory written to `{report_path}` ({len(verified)} verified, {len(disproved)} disproved, {len(chains)} chains).",
                target=host_label,
            )

        AGENT_BUS.save(host_label)

        return {
            "target": host_label,
            "surface": surface,
            "raw_findings": raw_findings,
            "verified": verified,
            "disproved": disproved,
            "chains": chains,
            "triaged": triaged,
            "pocs": pocs,
            "report_path": report_path,
            "transcript_path": transcript_path,
            "transcript": AGENT_BUS.transcript(),
        }


run = run_autopilot
