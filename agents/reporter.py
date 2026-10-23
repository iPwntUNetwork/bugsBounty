"""`FIXER` Markdown & JSON Bounty Report Generator (includes verified findings, kill chains, PoCs & crew log)."""
import json
import pathlib
import urllib.parse
from core.memory import scan_dir
from agents.crew import CREW_BUS


def generate_report(
    target: str,
    verified_findings: list,
    chains: list[dict] | None = None,
    pocs: list[dict] | None = None,
    disproved: list | None = None,
    waf_info: dict | None = None,
    out_path: str | None = None,
) -> str:
    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    host_label = parsed.netloc or target
    sd = scan_dir(host_label)

    poc_by_id = {p.get("finding_id"): p for p in (pocs or [])}
    lines = [
        f"# bugsBounty Offensive Assessment Report — `{host_label}`",
        "",
        "## Executive Summary",
        f"- **Target**: `{target}`",
        f"- **WAF Detected**: `{(waf_info or {}).get('waf', 'None')}`",
        f"- **RAZOR Deterministic Verified Exploits**: **{len(verified_findings)}**",
        f"- **Disproved False-Positive Claims Rejected by RAZOR**: **{len(disproved or [])}**",
        f"- **Attack Chains Synthesized (`CHAINSAW`)**: **{len(chains or [])}**",
        "",
        "## Verified Vulnerabilities",
    ]

    for idx, f in enumerate(verified_findings, 1):
        d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        poc = poc_by_id.get(d.get("id"), {})
        lines.extend([
            f"### {idx}. [{str(d.get('severity', 'high')).upper()}] {d.get('type')}",
            f"- **ID**: `{d.get('id')}`",
            f"- **Endpoint**: `{d.get('url')}` (parameter: `{d.get('parameter')}`)",
            f"- **Detected By**: `{d.get('detected_by')}` | **Audited By**: `critic:razor` (`{d.get('critic_verdict')}`)",
            f"- **Escalated With**: `{', '.join(d.get('escalated_with') or []) or 'direct'}`",
            f"- **WAF Bypass Used**: `{d.get('waf_bypass_used') or 'baseline'}`",
            f"- **Payload**: `{d.get('payload')}`",
            f"- **Evidence**: {d.get('evidence')}",
            f"- **Critic Notes**: `{'; '.join(d.get('critic_notes') or [])}`",
        ])
        if poc.get("curl"):
            lines.extend(["", "```bash", poc["curl"], "```"])
        lines.append("")

    if chains:
        lines.append("## Multi-Step Attack Chains (`CHAINSAW`)")
        for c in chains:
            lines.append(f"### [{c.get('severity', 'critical').upper()}] {c.get('title')}")
            for s in c.get("steps", []):
                lines.append(f"- {s}")
            lines.append("")

    transcript = CREW_BUS.transcript()[-15:]
    if transcript:
        lines.append("## War-Room Crew Highlight Reel")
        for entry in transcript:
            lines.append(f"- **[{entry['kind'].upper()}] {entry['speaker']}**: {entry['text']}")

    md = "\n".join(lines) + "\n"
    dest = pathlib.Path(out_path) if out_path else (sd / "report.md")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(md)
    (sd / "report_summary.json").write_text(json.dumps({
        "target": host_label,
        "verified_count": len(verified_findings),
        "disproved_count": len(disproved or []),
        "chains_count": len(chains or []),
        "report_path": str(dest),
    }, indent=2))
    return str(dest)


run = generate_report
