"""Platform-specific report templates: H1, Bugcrowd, Intigriti, Immunefi."""
from core.cvss import score, vector

TEMPLATES = {
    "hackerone": """## Summary
{title}

## Severity
CVSS: {cvss} ({vector})

## Description
{description}

## Steps to Reproduce
{steps}

## Impact
{impact}

## Supporting Material/References
{evidence}

## Suggested Fix
{fix}
""",
    "bugcrowd": """# {title}

## Target
{target}

## Vulnerability Type
{vuln_type}

## Severity (P1-P4)
{severity}

## Description
{description}

## Steps to Reproduce
{steps}

## Impact
{impact}

## Proof of Concept
{poc}

## Recommended Fix
{fix}
""",
    "intigriti": """# {title}

## Asset
{target}

## Vulnerability Details
**Type:** {vuln_type}
**CVSS:** {cvss}

## Description
{description}

## Reproduction Steps
{steps}

## Impact
{impact}

## Proof of Concept
{poc}

## Remediation
{fix}
""",
    "immunefi": """# {title}

## Bug Description
{description}

## Impact
{impact}

## Risk Breakdown
- Difficulty to exploit: {difficulty}
- CVSS: {cvss}

## Proof of Concept
{poc}

## Recommended Mitigation
{fix}
""",
}

def render(platform, data):
    tmpl = TEMPLATES.get(platform, TEMPLATES["hackerone"])
    data.setdefault("cvss", "N/A")
    data.setdefault("vector", "")
    data.setdefault("title", "Vulnerability Report")
    data.setdefault("target", "")
    data.setdefault("vuln_type", "")
    data.setdefault("severity", "P3")
    data.setdefault("description", "")
    data.setdefault("steps", "")
    data.setdefault("impact", "")
    data.setdefault("poc", "")
    data.setdefault("evidence", "")
    data.setdefault("fix", "")
    data.setdefault("difficulty", "Medium")
    return tmpl.format(**data)
