"""Autopilot: autonomous hunt loop. Only needs target."""
import time, json
from agents.recon_agent import run as recon_run
from agents.hunter import run as hunt_run
from agents.validator import validate_finding, seven_question_gate
from core.memory import log_event, LeadBoard, recon_dir, scan_dir
from core.llm import get_llm
from chains.builder import build_chains

def run(target, validate=True, report=True, username=None, password=None, login_url=None):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"[*] Starting autopilot on {domain}")
    # authenticated scanning
    from core.config import AUTH_USERNAME, AUTH_PASSWORD, AUTH_LOGIN_URL, AUTH_USER_FIELD, AUTH_PASS_FIELD
    u = username or AUTH_USERNAME
    pw = password or AUTH_PASSWORD
    lu = login_url or AUTH_LOGIN_URL
    if u and pw:
        from core.auth import Session, set_current
        sess = Session()
        if not lu:
            # guess login url
            lu = "https://{}/login".format(domain) if ":" not in domain else "http://{}/login".format(domain)
        ok = sess.login_form(lu, u, pw, AUTH_USER_FIELD, AUTH_PASS_FIELD)
        if not ok:
            ok = sess.login_json(lu, u, pw, AUTH_USER_FIELD, AUTH_PASS_FIELD)
        if ok:
            set_current(sess)
            print("[*] Authenticated as {} (session active)".format(u))
        else:
            print("[!] Login failed; continuing unauthenticated")
    from core.scope import verify
    ok, msg = verify(domain)
    print(f"[*] Scope: {msg}")
    print("[*] Legal: only scan targets you own or are authorized to test.")

    print("[*] Phase 1: Recon")
    recon = recon_run(domain)
    print(f"    subdomains: {len(recon['subdomains'])}, live: {len(recon['hosts'])}")

    lb = LeadBoard(domain)
    leads = [{"id": h["host"], "status": "new", "priority": "medium", "type": "host"} for h in recon["hosts"]]
    lb.ingest(leads)

    print("[*] Phase 2: Hunt (parallel swarm)")
    findings = hunt_run(recon)
    print(f"    raw findings: {len(findings)}")

    llm = get_llm(fast=True)
    if llm.available() and findings:
        try:
            summary = "\n".join(f"- {f.type} @ {f.url} ({f.severity})" for f in findings[:60])
            plan = llm.chat([
                {"role": "system", "content": "You are a bug bounty strategist. Output a short prioritized plan (max 12 lines) including chaining ideas and zero-day angles."},
                {"role": "user", "content": f"Target {domain}. Findings:\n{summary}\n\nPrioritize validation and chains."},
            ], temperature=0.3, max_tokens=600)
            print("[*] LLM plan:\n" + (plan or ""))
        except Exception as e:
            print(f"    plan error: {e}")
    else:
        from agents.deterministic.stub import plan as det_plan
        print("[*] Deterministic plan:\n" + det_plan(findings))

    print("[*] Phase 3: Validate (critic)")
    valid_findings = []
    for f in findings:
        ok, reason = validate_finding(f, use_llm=llm.available())
        if ok:
            valid_findings.append(f)
    print(f"    valid findings: {len(valid_findings)} (filtered {len(findings)-len(valid_findings)})")

    gated = []
    for f in valid_findings:
        gate = seven_question_gate(f)
        score = sum(1 for v in gate.values() if v)
        if score >= 4:
            gated.append((f, score, gate))
    gated.sort(key=lambda x: -x[1])
    print(f"    gated (score>=4): {len(gated)}")

    sd = scan_dir(domain)
    (sd / "findings_validated.json").write_text(json.dumps([f.to_dict() for f,_,_ in gated], indent=2, default=str))

    # chains
    print("[*] Phase 3b: Chain building")
    chains = build_chains([f for f,_,_ in gated], domain)
    if chains:
        (sd / "chains.json").write_text(json.dumps(chains, indent=2))
        print(f"    chains: {len(chains)}")
        for c in chains:
            print(f"      - {c.get('name')} ({c.get('severity')})")

    if report:
        print("[*] Phase 4: Report")
        from agents.reporter import run as report_run
        if llm.available():
            path = report_run(domain, [f for f,_,_ in gated])
        else:
            from agents.deterministic.stub import generate_report
            rep = generate_report([f for f,_,_ in gated], domain, domain)
            (sd / "report-deterministic.md").write_text(rep)
            path = str(sd / "report-deterministic.md")
        print(f"    report: {path}")
    # PoC generation
    if gated:
        from agents.poc_generator import generate_poc
        poc = generate_poc(gated[0][0], domain)
        (sd / "poc.txt").write_text(poc or "")
        print("    PoC saved to poc.txt")

    from core.auth import clear_current
    clear_current()
    log_event(domain, "autopilot_complete", {"valid": len(valid_findings), "gated": len(gated), "chains": len(chains)})
    return {"recon": recon, "findings": findings, "valid": valid_findings, "gated": gated, "chains": chains}
