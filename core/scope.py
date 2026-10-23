"""Scope verification & local allow/deny policy (`core/scope.py`)."""
import json
import urllib.parse
from core.config import HOME
from core.http import get

SCOPE_FILE = HOME / "scope.json"


def load_scope() -> dict:
    if SCOPE_FILE.exists():
        try:
            return json.loads(SCOPE_FILE.read_text())
        except Exception:
            pass
    default = {"in_scope": ["127.0.0.1", "localhost"], "out_of_scope": ["google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com"]}
    SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCOPE_FILE.write_text(json.dumps(default, indent=2))
    return default


def check_hackerone(program, asset):
    err = "unknown"
    try:
        r = get(f"https://api.hackerone.com/v1/hackers/programs/{program}", timeout=20)
        if r.status == 200:
            data = r.json() if hasattr(r, "json") else {}
            scopes = []
            if "relationships" in data:
                for s in data["relationships"].get("structured_scopes", {}).get("data", []):
                    scopes.append(s.get("attributes", {}).get("asset_identifier", ""))
            for s in scopes:
                if asset in s or s in asset:
                    return True, f"In scope: {s}"
            return False, f"Not in scope. Known: {scopes[:5]}"
    except Exception as e:
        err = str(e)
    return None, f"Could not verify (manual check required): {err}"


def check_asset(asset):
    parsed = urllib.parse.urlparse(asset if "://" in str(asset) else f"http://{asset}")
    host = (parsed.hostname or str(asset)).lower()
    scope = load_scope()
    for oos in scope.get("out_of_scope", []):
        oos_l = oos.lower().lstrip("*.")
        if host == oos_l or host.endswith("." + oos_l):
            return False, f"Out of scope ({oos})"
    for ins in scope.get("in_scope", []):
        ins_l = ins.lower().lstrip("*.")
        if host == ins_l or host.endswith("." + ins_l) or ins in str(asset):
            return True, f"Explicitly in scope ({ins})"
    return True, "Appears in scope (verify with program policy)"


def is_allowed(asset) -> bool:
    ok, _ = check_asset(asset)
    return bool(ok)


def verify(target, program=None):
    if program:
        return check_hackerone(program, target)
    return check_asset(target)


in_scope = is_allowed

