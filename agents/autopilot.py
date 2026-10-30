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


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _pursuit_priority(finding) -> tuple[int, float]:
    """Chase the highest-severity, highest-confidence leads first."""
    return (
        SEVERITY_ORDER.get((finding.severity or "").lower(), 4),
        -float(finding.confidence or 0.0),
    )


def run_auto(
    target: str,
    max_pages: int = 35,
    run_dirbust: bool = True,
    discover_params: bool = True,
    report_out: str | None = None,
    max_pursuits: int = 12,
) -> dict:
    """Agent-driven `AUTO` mode: recon, hunt, then actively pursue every bug it finds.

    Unlike the batch pipeline, each discovered lead is chased individually: the agent
    escalates it with heavy tools, immediately tries to disprove it with deterministic
    controls, and keeps going with the confirmed ones until it has verified impact,
    kill chains and a report.
    """
    from agents.escalator import escalate_finding
    from agents.critic import SeparationOfDutiesError, critique_finding

    start_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(start_url)
    host_label = parsed.netloc or target

    with TELEMETRY.agent_scope(AGENT_HANDLE, task=f"Auto mode on {host_label}", target=start_url, tool="autopilot"):
        AGENT_BUS.say(
            f"Auto mode engaged on `{start_url}`. I'll map the surface, hunt for bugs, then chase every lead I find "
            "and only keep what survives deterministic verification.",
            kind="info",
            target=host_label,
        )

        # 1. Recon
        surface = run_recon(start_url, max_pages=max_pages, run_dirbust=run_dirbust, discover_params=discover_params)
        waf_vendor = (surface.get("waf") or {}).get("waf") or "generic"

        # 2. Hunt
        raw_findings = run_hunter(start_url, surface=surface)

        # 3+4. Pursue: escalate then verify each lead, highest severity first
        leads = sorted(raw_findings, key=_pursuit_priority)[: max(1, max_pursuits)]
        AGENT_BUS.stage_started(
            "escalate",
            f"pursuing {len(leads)} of {len(raw_findings)} leads individually (heaviest first)",
            target=host_label,
        )

        verified: list = []
        disproved: list = []
        for idx, lead in enumerate(leads, 1):
            AGENT_BUS.say(
                f"[{idx}/{len(leads)}] Chasing `{lead.type}` on `{lead.url}`"
                + (f" (param `{lead.parameter}`)" if lead.parameter else ""),
                kind="stage",
                stage="escalate",
                target=host_label,
            )
            try:
                escalated = escalate_finding(lead, waf_vendor=waf_vendor, target=host_label)
            except Exception as exc:  # never let one bad lead stop the run
                AGENT_BUS.say(f"Escalation failed on `{lead.url}`: `{exc}`", kind="warn", stage="escalate", target=host_label)
                escalated = lead
            if not (escalated.detected_by or "").strip():
                escalated.detected_by = "hunter:auto"
            try:
                audited = critique_finding(escalated, target=host_label)
            except SeparationOfDutiesError as exc:
                AGENT_BUS.say(
                    f"Skipping `{escalated.type}` on `{escalated.url}` — {exc}",
                    kind="warn",
                    stage="verify",
                    target=host_label,
                )
                continue
            (verified if audited.verified else disproved).append(audited)
            if audited.verified:
                extra = []
                if audited.escalated_with:
                    extra.append("confirmed with " + ", ".join(f"`{t}`" for t in audited.escalated_with))
                if audited.waf_bypass_used:
                    extra.append(f"WAF bypass `{audited.waf_bypass_used}`")
                AGENT_BUS.say(
                    f"Keeping `{audited.type}` on `{audited.url}`"
                    + (f" ({'; '.join(extra)})" if extra else "")
                    + f" — severity `{audited.severity}`. Pursuing impact next.",
                    kind="verified",
                    stage="verify",
                    target=host_label,
                )

        AGENT_BUS.stage_done(
            "escalate",
            f"pursued {len(leads)} leads: {len(verified)} kept, {len(disproved)} disproved.",
            target=host_label,
        )
        AGENT_BUS.stage_done("verify", f"{len(verified)} verified, {len(disproved)} disproved.", target=host_label)

        store = FindingStore(host_label)
        for vf in verified:
            store.add(vf)

        # 5. Chains built only from the bugs that survived pursuit
        with TELEMETRY.agent_scope(
            AGENT_HANDLE,
            task=f"Stage 5/{STAGE_COUNT} · Chains on {host_label}",
            target=start_url,
            tool="chain-builder",
            stage="chains",
        ):
            AGENT_BUS.stage_started("chains", f"correlating {len(verified)} verified bugs", target=host_label)
            set_phase(host_label, "chains")
            chains = build_chains(host_label, verified)
            AGENT_BUS.stage_done("chains", f"{len(chains)} multi-step chain(s) built.", target=host_label)

        # 6. Triage, PoCs and advisory
        with TELEMETRY.agent_scope(
            AGENT_HANDLE,
            task=f"Stage 6/{STAGE_COUNT} · Report on {host_label}",
            target=start_url,
            tool="reporter",
            stage="report",
        ):
            AGENT_BUS.stage_started("report", "scoring CVSS v3.1, building PoCs and the advisory", target=host_label)
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
                f"{len(verified)} bug(s) verified and reported, {len(disproved)} disproved, "
                f"{len(chains)} chain(s) — advisory at `{report_path}`.",
                target=host_label,
            )

        AGENT_BUS.save(host_label)

        return {
            "mode": "auto",
            "target": host_label,
            "surface": surface,
            "raw_findings": raw_findings,
            "pursued": len(leads),
            "verified": verified,
            "disproved": disproved,
            "chains": chains,
            "triaged": triaged,
            "pocs": pocs,
            "report_path": report_path,
            "transcript_path": transcript_path,
            "transcript": AGENT_BUS.transcript(),
        }
