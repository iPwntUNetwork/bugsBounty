"""`AUTOPILOT` — Full 6-Agent War-Room Pipeline Orchestrator.

Executes the complete separated-duty offensive workflow end-to-end:
  Phase 1 (`GHOST`)    : Recon (`subfinder`, `assetfinder`, `dnsx`, `httpx`, `wafw00f`, `katana`, `hakrawler`, `arjun`, `ffuf`, `gobuster`, `waybackurls`, `gau`, `paramspider`)
  Phase 2 (`BLITZ`)    : Active WAF-evading vulnerability hunting (`PAYLOAD_MUTEX` + 24 tampers + UA rotation)
  Phase 3 (`SWITCH`)   : Heavy-artillery tool handoffs (`sqlmap`, `dalfox` + live `BeefServer`, `commix`, `interactsh`/OOB)
  Phase 4 (`RAZOR`)    : 100% Deterministic Falsification Critic (strict Separation of Duties; cheers wins, brown-eyes flops)
  Phase 5 (`CHAINSAW`) : Multi-step exploit chain synthesis on RAZOR-certified findings ONLY
  Phase 6 (`FIXER`)    : CVSS v3.1 triage, reproducible PoCs, war-room transcript & Markdown report
"""
import urllib.parse
from core.findings import FindingStore
from core.memory import set_phase
from agents.crew import CREW_BUS
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

    CREW_BUS.say(
        "GHOST",
        f"=== WAR ROOM LIVE ON `{start_url}` === Six espresso mugs full, `.bin/` arsenal hot, let's get paid crew!",
        kind="banter",
        target=host_label,
    )

    # 1. GHOST: Recon + WAF Fingerprinting
    surface = run_recon(
        start_url,
        max_pages=max_pages,
        run_dirbust=run_dirbust,
        discover_params=discover_params,
    )
    waf_vendor = (surface.get("waf") or {}).get("waf") or "generic"

    # 2. BLITZ: Active Hunting
    raw_findings = run_hunter(start_url, surface=surface)

    # 3. SWITCH: Tool Handoff Escalation
    escalated_findings = run_escalator(start_url, raw_findings, waf_vendor=waf_vendor)

    # 4. RAZOR: Deterministic Falsification Critic (NEVER the detector!)
    audit = run_critic(host_label, escalated_findings)
    verified = audit["verified"]
    disproved = audit["disproved"]

    # Persist verified findings cleanly
    store = FindingStore(host_label)
    for vf in verified:
        store.add(vf)

    # 5. CHAINSAW: Multi-step Attack Chains
    from core.telemetry import TELEMETRY
    with TELEMETRY.agent_scope("CHAINSAW", task=f"Synthesizing P1 attack chains on {host_label}", target=start_url, tool="chain-builder"):
        set_phase(host_label, "chains")
        chains = build_chains(host_label, verified)
        if chains:
            CREW_BUS.say(
                "CHAINSAW",
                f"Stitched {len(chains)} critical kill-chain(s) out of RAZOR's verified bugs — "
                "FIXER, slap P1 impact on these beauties!",
                kind="handoff",
                to="FIXER",
                target=host_label,
            )

    # 6. FIXER: Triage + PoCs + Final Markdown Advisory
    with TELEMETRY.agent_scope("FIXER", task=f"Scoring CVSS v3.1, PoCs & Markdown report for {host_label}", target=start_url, tool="reporter"):
        set_phase(host_label, "report")
        triaged = triage_findings(host_label, verified)
        pocs = generate_pocs(host_label, verified)
        transcript_path = CREW_BUS.save(host_label)
        report_path = generate_report(
            start_url,
            verified_findings=verified,
            chains=chains,
            pocs=pocs,
            disproved=disproved,
            waf_info=surface.get("waf"),
            out_path=report_out,
        )
    CREW_BUS.say(
        "FIXER",
        f"Report locked & loaded at `{report_path}` ({len(verified)} verified exploits, "
        f"{len(disproved)} false positives binned, {len(chains)} chains). Time to crack a cold one crew!",
        kind="cheer",
        target=host_label,
    )
    CREW_BUS.save(host_label)

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
        "transcript": CREW_BUS.transcript(),
    }


run = run_autopilot
