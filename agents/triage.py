"""Triage preparation: anticipate triager questions, prepare evidence."""
from core.llm import get_llm
from core.findings import Finding
from core.memory import log_event
import json

NEVER_SUBMIT = [
    "missing security header without chain",
    "clickjacking without sensitive action",
    "csrf without state change",
    "self-xss",
    "open redirect without oauth/token",
    "rate limiting not a vuln",
    "version disclosure alone",
    "email bombing",
    "username enumeration alone",
    "logout csrf",
]

def check_never_submit(finding):
    t = finding.type.lower()
    for ns in NEVER_SUBMIT:
        if ns in t:
            return True, "Never-submit: {}".format(ns)
    return False, "OK"

def prepare_triage(finding, target):
    llm = get_llm(fast=True)
    if not llm.available():
        return {"verdict": "manual review required"}
    prompt = [
        {"role": "system", "content": "You are a bug bounty triager. Anticipate questions a triager would ask and prepare answers. Respond JSON: {\"questions\": [str], \"answers\": [str], \"likely_verdict\": str, \"improvements\": [str]}."},
        {"role": "user", "content": "Finding: {}\nURL: {}\nEvidence: {}\nPayload: {}".format(finding.type, finding.url, finding.evidence, finding.payload)},
    ]
    res = llm.json(prompt, temperature=0.2, max_tokens=600)
    log_event(target, "triage_prep", {"type": finding.type})
    return res or {}
