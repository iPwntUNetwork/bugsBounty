"""LLM-driven novel payload generation for unknown vulnerabilities."""
from core.llm import get_llm
from core.memory import log_event

def generate_payloads(context, vuln_type, n=10):
    llm = get_llm()
    if not llm.available():
        return []
    prompt = [
        {"role": "system", "content": "You are a security researcher. Generate novel, non-standard payloads to test for a vulnerability. Output JSON: {\"payloads\": [str,...]}."},
        {"role": "user", "content": f"Context: {context}\nVuln type: {vuln_type}\nGenerate {n} novel payloads that might bypass filters or reveal unknown issues. Be creative."},
    ]
    res = llm.json(prompt, temperature=0.7, max_tokens=800)
    if not res:
        return []
    return res.get("payloads", [])
