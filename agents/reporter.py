"""Report writer: generates submission-ready markdown reports."""
from core.memory import REPORTS, recon_dir, scan_dir
from core.cvss import score, vector
from core.llm import get_llm
from report.templates import render
from agents.poc_generator import generate_poc, generate_all
from agents.triage import check_never_submit, prepare_triage
from agents.duplicate_checker import check_local
import json, time, os

def run(target, findings):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    rd = REPORTS / domain.replace("/", "_")
    rd.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    path = rd / f"report-{ts}.md"
    llm = get_llm()
    lines = []
    lines.append(f"# Bug Bounty Report — {domain}")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"Total validated findings: {len(findings)}")
    lines.append("")
    # group by severity
    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)
    for sev in ["critical", "high", "medium", "low"]:
        if sev in by_sev:
            lines.append(f"### {sev.upper()} ({len(by_sev[sev])})")
            for f in by_sev[sev]:
                lines.append(f"- **{f.type}** — {f.url}")
                lines.append(f"  - Param: `{f.parameter}`")
                lines.append(f"  - Payload: `{f.payload}`")
                lines.append(f"  - Evidence: {f.evidence}")
                lines.append(f"  - Confidence: {f.confidence}")
                lines.append(f"  - CVSS: {score(f)} ({vector(f)})")
            lines.append("")
    # LLM-written narrative if available
    if llm.available() and findings:
        try:
            data = "\n".join(f"{f.type} | {f.severity} | {f.url} | {f.evidence}" for f in findings[:20])
            nar = llm.chat([
                {"role": "system", "content": "You are a professional bug bounty report writer. Write concise, human-tone, submission-ready report sections: Impact, Reproduction steps, Remediation. No fluff."},
                {"role": "user", "content": f"Target: {domain}\nFindings:\n{data}\n\nWrite a consolidated report with sections: ## Impact, ## Reproduction, ## Remediation. Use markdown."},
            ], temperature=0.3, max_tokens=1500)
            if nar:
                lines.append("## Detailed Narrative (AI-drafted)")
                lines.append(nar)
        except Exception as e:
            lines.append(f"<!-- narrative error: {e} -->")
    # per-finding details
    lines.append("")
    # PoC + triage prep
    for f in findings:
        ns, reason = check_never_submit(f)
        if ns:
            f.notes = reason
    # render platform template for first finding if any
    if findings:
        f = findings[0]
        poc = generate_poc(f, domain)
        data = {
            "title": f.type,
            "target": domain,
            "vuln_type": f.type,
            "severity": f.severity.upper(),
            "description": f.evidence,
            "steps": "1. Navigate to {}\n2. Inject payload: {}".format(f.url, f.payload),
            "impact": "Attacker can {}".format(f.type.lower()),
            "poc": poc,
            "evidence": f.response_snippet,
            "fix": "Validate and sanitize input; implement proper access controls.",
            "cvss": __import__("core.cvss", fromlist=["score"]).score(f),
            "vector": __import__("core.cvss", fromlist=["vector"]).vector(f),
        }
        lines.append("")
        lines.append("## Platform Report (HackerOne template)")
        lines.append(render("hackerone", data))
    lines.append("## Findings Detail")
    for i, f in enumerate(findings, 1):
        lines.append(f"### Finding {i}: {f.type}")
        lines.append(f"- **Severity:** {f.severity}")
        lines.append(f"- **URL:** {f.url}")
        lines.append(f"- **Parameter:** {f.parameter}")
        lines.append(f"- **Payload:** `{f.payload}`")
        lines.append(f"- **Evidence:** {f.evidence}")
        lines.append(f"- **PoC:**")
        lines.append("```")
        lines.append(generate_poc(f, domain) or "")
        lines.append("```")
        lines.append(f"- **Response snippet:**")
        lines.append("```")
        lines.append((f.response_snippet or "")[:500])
        lines.append("```")
        lines.append("")
    # save individual PoCs
    poc_dir = rd / "pocs"
    poc_dir.mkdir(parents=True, exist_ok=True)
    pocs = generate_all(findings, domain)
    for fid, poc in pocs.items():
        import re
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", fid)
        (poc_dir / (safe + ".txt")).write_text(poc or "")
    path.write_text("\n".join(lines))
    return str(path)
