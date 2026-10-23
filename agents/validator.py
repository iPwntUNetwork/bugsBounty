"""Validator shim routing legacy validation calls cleanly through `RAZOR` (`agents/critic.py`)."""
from core.findings import Finding
from agents.critic import run_critic, critique_finding


def validate_findings(target: str, findings: list[Finding]) -> list[Finding]:
    for f in findings:
        if not f.detected_by:
            f.detected_by = "hunter:legacy"
    res = run_critic(target, findings)
    return res["verified"]


run_validator = validate_findings
run = validate_findings
__all__ = ["validate_findings", "run_validator", "run", "critique_finding"]
