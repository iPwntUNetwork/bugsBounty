"""Scope verification: check if asset is in program scope."""
from core.http import get
from core.memory import log_event
import json, re

def check_hackerone(program, asset):
    """Check HackerOne program scope (public API)."""
    try:
        r = get("https://api.hackerone.com/v1/hackers/programs/{}".format(program), timeout=20)
        if r.status == 200:
            data = r.json() if hasattr(r, "json") else {}
            # parse scope
            scopes = []
            if "relationships" in data:
                for s in data["relationships"].get("structured_scopes", {}).get("data", []):
                    scopes.append(s.get("attributes", {}).get("asset_identifier", ""))
            for s in scopes:
                if asset in s or s in asset:
                    return True, "In scope: {}".format(s)
            return False, "Not in scope. Known: {}".format(scopes[:5])
    except Exception as e:
        pass
    return None, "Could not verify (manual check required): {}".format(e)

def check_asset(asset):
    """Basic scope check: ensure not obviously out of scope."""
    out_of_scope = ["google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com"]
    for oos in out_of_scope:
        if asset == oos or asset.endswith("." + oos):
            return False, "Likely out of scope (major vendor root domain)"
    return True, "Appears in scope (verify with program policy)"

def verify(target, program=None):
    if program:
        return check_hackerone(program, target)
    return check_asset(target)
