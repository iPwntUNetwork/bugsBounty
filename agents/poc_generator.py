"""PoC Generator — reproducible `curl`, Python script, BeEF stager & `sqlmap`/`commix` artifacts."""
import json
import shlex
import urllib.parse
from core.findings import Finding
from core.waf_bypass import inject_param
from core.memory import scan_dir
from exploit.stagers import generate_stagers


def _as_dict(f) -> dict:
    return f.to_dict() if hasattr(f, "to_dict") else dict(f)


def build_poc(finding) -> dict:
    d = _as_dict(finding)
    url = d.get("url", "")
    param = d.get("parameter", "")
    payload = d.get("payload", "")

    headers = {}
    target_url = url
    if param == "header/path" and ": " in payload:
        hk, hv = payload.split(": ", 1)
        headers[hk] = hv
    elif param and param not in ("path", "dom", "header/path") and payload:
        target_url = inject_param(url, param, payload)

    hdr_flags = " ".join(f"-H {shlex.quote(f'{k}: {v}')}" for k, v in headers.items())
    curl_cmd = f"curl -isk {hdr_flags} {shlex.quote(target_url)}".strip()
    py_script = (
        "import requests\n"
        f"resp = requests.get({target_url!r}, headers={headers!r}, verify=False, timeout=15)\n"
        "print(resp.status_code, len(resp.text))\n"
        "print(resp.text[:500])\n"
    )
    stagers = generate_stagers(d)
    return {
        "finding_id": d.get("id"),
        "type": d.get("type"),
        "severity": d.get("severity"),
        "repro_url": target_url,
        "curl": curl_cmd,
        "python": py_script,
        "stagers": stagers,
    }


def generate_pocs(target: str, findings: list[Finding]) -> list[dict]:
    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    host_label = parsed.netloc or target
    pocs = [build_poc(f) for f in findings]
    sd = scan_dir(host_label)
    (sd / "pocs.json").write_text(json.dumps(pocs, indent=2))
    return pocs


run = generate_pocs
