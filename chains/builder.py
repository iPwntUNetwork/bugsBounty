"""Multi-step Attack Chain Builder (`CHAINSAW` persona compatible)."""
import json
from core.memory import scan_dir, log_event


def _as_dict(f) -> dict:
    return f.to_dict() if hasattr(f, "to_dict") else dict(f)


def build_chains(target: str, findings: list) -> list[dict]:
    items = [_as_dict(f) for f in findings]
    chains = []

    by_class: dict[str, list[dict]] = {}
    for f in items:
        t = (f.get("type") or "").lower()
        if "xss" in t or "mitb" in t:
            by_class.setdefault("xss", []).append(f)
        if "sql" in t:
            by_class.setdefault("sqli", []).append(f)
        if "ssrf" in t:
            by_class.setdefault("ssrf", []).append(f)
        if "command" in t or "cmdi" in t or "rce" in t:
            by_class.setdefault("cmdi", []).append(f)
        if "403" in t or "bypass" in t:
            by_class.setdefault("bypass403", []).append(f)
        if "env" in t or "git" in t or "secret" in t or "exposure" in t or "lfi" in t or "traversal" in t:
            by_class.setdefault("disclosure", []).append(f)
        if "cors" in t or "csrf" in t:
            by_class.setdefault("session", []).append(f)

    if by_class.get("xss"):
        x = by_class["xss"][0]
        steps = [
            f"1. Deliver reflected/DOM XSS payload on `{x.get('url')}` (`{x.get('parameter')}`)",
            f"2. Load live BeEF browser hook (`{x.get('beef_hook_url') or 'hook.js'}`) to maintain interactive JS execution in victim session",
            "3. Exfiltrate authenticated session state / perform privileged actions as victim user (Account Takeover)",
        ]
        chains.append({
            "id": "chain-xss-beef-ato",
            "title": "Reflected XSS + BeEF C2 Hook -> Authenticated Session Takeover",
            "severity": "critical",
            "finding_ids": [x.get("id")],
            "steps": steps,
        })

    if by_class.get("disclosure") and (by_class.get("sqli") or by_class.get("cmdi") or by_class.get("bypass403")):
        d = by_class["disclosure"][0]
        p = (by_class.get("cmdi") or by_class.get("sqli") or by_class.get("bypass403"))[0]
        chains.append({
            "id": "chain-disclosure-pivot",
            "title": f"{d.get('type')} -> Credential/Config Harvest -> {p.get('type')}",
            "severity": "critical",
            "finding_ids": [d.get("id"), p.get("id")],
            "steps": [
                f"1. Extract secrets/internal layout via `{d.get('url')}` ({d.get('type')})",
                f"2. Pivot to `{p.get('url')}` and exploit `{p.get('type')}` for backend compromise",
            ],
        })

    if by_class.get("bypass403") and (by_class.get("sqli") or by_class.get("cmdi") or by_class.get("ssrf")):
        b = by_class["bypass403"][0]
        rce = (by_class.get("cmdi") or by_class.get("sqli") or by_class.get("ssrf"))[0]
        chains.append({
            "id": "chain-403-to-backend",
            "title": f"403 Edge Bypass (`{b.get('payload')}`) + Backend Injection (`{rce.get('type')}`)",
            "severity": "critical",
            "finding_ids": [b.get("id"), rce.get("id")],
            "steps": [
                f"1. Bypass reverse-proxy ACL on `{b.get('url')}` using `{b.get('payload')}`",
                f"2. Chain backend `{rce.get('type')}` on `{rce.get('url')}` to achieve full server compromise",
            ],
        })

    sd = scan_dir(target)
    (sd / "chains.json").write_text(json.dumps(chains, indent=2))
    log_event(target, "chains", {"count": len(chains)})
    return chains
