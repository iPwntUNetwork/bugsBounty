"""Nuclei-style template engine: run YAML templates."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import yaml, urllib.parse, re, os

def run_template(template_path, target):
    findings = []
    try:
        with open(template_path) as f:
            tmpl = yaml.safe_load(f)
    except Exception:
        return findings
    if not tmpl:
        return findings
    parsed = urllib.parse.urlparse(target)
    root = "{}://{}".format(parsed.scheme, parsed.netloc)
    for req in tmpl.get("requests", []):
        method = req.get("method", "GET").upper()
        path = req.get("path", ["/"])[0]
        url = root + path
        matchers = req.get("matchers", [])
        r = get(url)
        if r.status == 0:
            continue
        matched = False
        for m in matchers:
            if m.get("type") == "status":
                if r.status in m.get("status", []):
                    matched = True
            if m.get("type") == "word":
                words = m.get("words", [])
                if any(w in (r.text or "") for w in words):
                    matched = True
        if matched:
            findings.append(Finding(
                id="template-{}-{}".format(tmpl.get("id", "unknown"), hash(url) & 0xffff),
                target=parsed.netloc,
                type=tmpl.get("info", {}).get("name", "Template Match"),
                severity=tmpl.get("info", {}).get("severity", "info"),
                url=url,
                parameter="template",
                payload=path,
                evidence="Template matched",
                response_snippet=r.snippet(200),
                confidence=0.7,
            ))
    log_event(parsed.netloc, "template_scan", {"template": template_path, "findings": len(findings)})
    return findings

def run_dir(template_dir, target):
    findings = []
    for root_dir, _, files in os.walk(template_dir):
        for f in files:
            if f.endswith((".yaml", ".yml")):
                findings.extend(run_template(os.path.join(root_dir, f), target))
    return findings
