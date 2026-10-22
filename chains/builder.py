"""Exploit chain builder: combine findings into A->B->C chains using LLM."""
from core.llm import get_llm
from core.findings import Finding
from core.memory import log_event
import json

def build_chains(findings, target):
    llm = get_llm()
    if not findings:
        return []
    if not llm.available():
        # deterministic fallback chains
        chains = []
        types = [f.type.lower() for f in findings]
        if any("xss" in t for t in types) and any("content-security" in t for t in types):
            chains.append({"name": "XSS + Missing CSP", "steps": ["Reflected XSS payload", "No CSP to mitigate", "Account takeover via session theft"], "impact": "Stored/reflected XSS leads to session hijack", "severity": "high"})
        if any("exposed sensitive file" in t for t in types) or any(".env" in (f.url) for f in findings):
            chains.append({"name": "Secret Leak -> Account Takeover", "steps": ["Read .env secrets", "Use leaked DB/API keys", "Full system compromise"], "impact": "Credential compromise", "severity": "critical"})
        if any("idor" in t for t in types):
            chains.append({"name": "IDOR -> Data Exfiltration", "steps": ["Enumerate object IDs", "Access other users' data", "Mass data breach"], "impact": "Unauthorized data access", "severity": "high"})
        if any("ssrf" in t for t in types):
            chains.append({"name": "SSRF -> Cloud Metadata", "steps": ["SSRF to metadata", "Steal IAM creds", "Cloud account takeover"], "impact": "Cloud compromise", "severity": "critical"})
        return chains
    data = "\n".join(f"{i}. {f.type} | {f.severity} | {f.url} | {f.evidence}" for i, f in enumerate(findings))
    prompt = [
        {"role": "system", "content": "You are an exploit chain architect. Given a list of findings, propose 1-3 multi-step exploit chains (A->B->C) that combine them for higher impact. Respond JSON: {\"chains\": [{\"name\": str, \"steps\": [str], \"impact\": str, \"severity\": str}]}."},
        {"role": "user", "content": f"Target: {target}\nFindings:\n{data}\n\nBuild chains."},
    ]
    res = llm.json(prompt, temperature=0.3, max_tokens=1200)
    if not res:
        return []
    chains = res.get("chains", [])
    log_event(target, "chains_built", {"count": len(chains)})
    return chains
