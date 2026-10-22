"""Duplicate detection via HackerOne Hacktivity."""
from core.http import get
from core.memory import log_event
import json, re

def check_hacktivity(program, vuln_type, url):
    """Check if similar finding already reported."""
    try:
        r = get("https://api.hackerone.com/v1/hackers/programs/{}/hacktivity".format(program), timeout=20)
        if r.status == 200:
            data = r.json() if hasattr(r, "json") else {}
            reports = data.get("data", [])
            matches = []
            for rep in reports:
                attrs = rep.get("attributes", {})
                title = attrs.get("title", "")
                if vuln_type.lower() in title.lower():
                    matches.append(title)
            if matches:
                return True, "Possible duplicate: {}".format(matches[:3])
            return False, "No obvious duplicate in hacktivity"
    except Exception as e:
        pass
    return None, "Could not check (manual): {}".format(e)

def check_local(target, vuln_type):
    """Check local memory for same finding on same target."""
    from memory.pattern_db import query
    existing = query(finding_type=vuln_type, target=target)
    if existing:
        return True, "Previously found on this target ({} times)".format(len(existing))
    return False, "New finding"
