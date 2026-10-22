"""PoC generator: produce working exploit code for findings."""
from core.llm import get_llm
from core.findings import Finding
from core.memory import log_event
import json

def generate_poc(finding, target):
    llm = get_llm()
    if not llm.available():
        # template-based
        return _template_poc(finding)
    prompt = [
        {"role": "system", "content": "You are a security researcher. Generate a working, minimal PoC (curl command or HTML/JS) for the finding. Output only the PoC code, no explanation."},
        {"role": "user", "content": "Type: {}\nURL: {}\nParam: {}\nPayload: {}\nEvidence: {}\n\nGenerate PoC.".format(finding.type, finding.url, finding.parameter, finding.payload, finding.evidence)},
    ]
    poc = llm.chat(prompt, temperature=0.2, max_tokens=500)
    log_event(target, "poc_generated", {"type": finding.type})
    return poc or _template_poc(finding)

def _template_poc(finding):
    t = finding.type.lower()
    if "xss" in t:
        return "curl -s '{}' | grep -i '{}'\n# Or open in browser: {}".format(finding.url, finding.payload[:30], finding.url)
    if "sqli" in t:
        return "curl -s '{}'".format(finding.url)
    if "ssrf" in t:
        return "curl -s '{}'".format(finding.url)
    if "redirect" in t:
        return "curl -sI '{}' | grep -i location".format(finding.url)
    return "curl -s '{}'".format(finding.url)


def generate_all(findings, target):
    """Generate PoC for every finding. Returns dict id->poc."""
    out = {}
    for f in findings:
        out[f.id] = generate_poc(f, target)
    return out
