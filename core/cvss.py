"""CVSS 3.1 scoring helper."""
SEVERITY_TO_CVSS = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}

def score(finding):
    return SEVERITY_TO_CVSS.get(finding.severity, 0.0)

def vector(finding):
    # simplified vector string
    sev = finding.severity
    if sev == "critical":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    if sev == "high":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
    if sev == "medium":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    if sev == "low":
        return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    return "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"
