"""Declarative YAML exposure & misconfiguration template scanner (used directly by `.bin/nuclei` & `Hunter`)."""
import pathlib
import re
import urllib.parse
import yaml
from core.http import get
from core.findings import Finding

RULES_DIR = pathlib.Path(__file__).resolve().parent / "rules"


def load_templates(custom_dir: str | None = None, tags: list[str] | None = None, severities: list[str] | None = None) -> list[dict]:
    root = pathlib.Path(custom_dir) if custom_dir else RULES_DIR
    templates = []
    if not root.exists():
        return templates
    tag_filter = {t.lower() for t in (tags or []) if t}
    sev_filter = {s.lower() for s in (severities or []) if s}
    for yf in sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml")):
        try:
            doc = yaml.safe_load(yf.read_text())
            entries = doc if isinstance(doc, list) else ([doc] if isinstance(doc, dict) else [])
            for item in entries:
                info = item.get("info", item)
                sev = str(info.get("severity", item.get("severity", "info"))).lower()
                item_tags = {str(t).lower() for t in (info.get("tags") or item.get("tags") or [])}
                if sev_filter and sev not in sev_filter:
                    continue
                if tag_filter and not (item_tags & tag_filter):
                    continue
                templates.append(item)
        except Exception:
            continue
    return templates


def _eval_matcher(matcher: dict, status: int, body: str, headers: dict) -> bool:
    mtype = matcher.get("type", "word")
    part = matcher.get("part", "body")
    haystack = "\n".join(f"{k}: {v}" for k, v in headers.items()) if part == "header" else body
    condition = matcher.get("condition", "or").lower()
    if mtype == "status":
        return status in (matcher.get("status") or [])
    if mtype == "word":
        words = matcher.get("words") or []
        fn = all if condition == "and" else any
        return fn(w in haystack for w in words) if words else False
    if mtype == "regex":
        regs = matcher.get("regex") or []
        fn = all if condition == "and" else any
        return fn(bool(re.search(rx, haystack, re.I)) for rx in regs) if regs else False
    return False


def scan_target_with_templates(base_url: str, custom_dir: str | None = None, tags: list[str] | None = None, severities: list[str] | None = None) -> list[Finding]:
    if "://" not in base_url:
        base_url = f"http://{base_url}"
    base_url = base_url.rstrip("/")
    parsed = urllib.parse.urlparse(base_url)
    notfound = get(f"{base_url}/definitely-nonexistent-nuclei-canary-88712")
    nf_body = (notfound.text or "")[:200]

    findings = []
    for tpl in load_templates(custom_dir=custom_dir, tags=tags, severities=severities):
        tid = tpl.get("id", "tpl")
        info = tpl.get("info", tpl)
        name = info.get("name", tid)
        sev = str(info.get("severity", "medium")).lower()
        reqs = tpl.get("http") or tpl.get("requests") or [{"path": tpl.get("paths", []), "matchers": tpl.get("matchers", [])}]
        for req in reqs:
            paths = req.get("path") or req.get("paths") or []
            method = (req.get("method") or "GET").upper()
            matchers = req.get("matchers") or []
            cond = (req.get("matchers-condition") or "and").lower()
            for raw_p in paths:
                url = raw_p.replace("{{BaseURL}}", base_url).replace("{{RootURL}}", base_url)
                if not url.startswith("http"):
                    url = f"{base_url}/{url.lstrip('/')}"
                r = get(url) if method == "GET" else get(url)
                if r.status == 0 or (nf_body and nf_body == (r.text or "")[:200] and r.status == notfound.status):
                    continue
                results = [_eval_matcher(m, r.status, r.text or "", r.headers) for m in matchers]
                matched = (all(results) if cond == "and" else any(results)) if results else False
                if matched:
                    findings.append(Finding(
                        id=f"tpl-{tid}-{hash(url) & 0xffff:x}",
                        target=parsed.netloc,
                        type=name,
                        severity=sev,
                        url=url,
                        parameter="path",
                        payload=raw_p,
                        evidence=f"Template `{tid}` matched HTTP {r.status} at `{url}`",
                        request=r.raw_request,
                        response_snippet=r.snippet(300),
                        confidence=0.9,
                        detected_by=f"hunter:template:{tid}",
                    ))
                    break
    return findings


def run_templates(url: str, custom_dir: str | None = None) -> list[Finding]:
    return scan_target_with_templates(url, custom_dir=custom_dir)


def run_dir(tmpl_dir: str, url: str) -> list[Finding]:
    return scan_target_with_templates(url, custom_dir=tmpl_dir)


def run_template(tmpl_file: str, url: str) -> list[Finding]:
    import tempfile
    import shutil
    with tempfile.TemporaryDirectory() as td:
        shutil.copy2(tmpl_file, td)
        return scan_target_with_templates(url, custom_dir=td)

