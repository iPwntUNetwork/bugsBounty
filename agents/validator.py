"""Validator: 7-Question Gate + deterministic checks + LLM critic."""
from core.llm import get_llm
from core.findings import Finding
from core.memory import log_event

QUESTIONS = [
    "Can an attacker exploit this right now without special access?",
    "Is the impact concrete and in-scope (not theoretical)?",
    "Is the evidence reproducible (request/response captured)?",
    "Is this not a duplicate of a known/common non-issue?",
    "Does it bypass existing security controls?",
    "Is the affected asset in scope?",
    "Would a triager accept this as valid?",
]

# deterministic reject patterns (common false positives)
REJECT_PATTERNS = [
    "missing header",  # low-value unless chain
    "information disclosure (version)",
    "graphql batching",
    "field suggestions",
]


def deterministic_check(f: Finding):
    """Return (keep: bool, reason: str)."""
    # empty evidence
    if not f.evidence or len(f.evidence) < 10:
        return False, "No evidence captured"
    # low confidence
    if f.confidence < 0.4:
        return False, "Confidence too low"
    # info severity with no chain -> likely noise
    if f.severity == "info":
        return False, "Info-level finding; skip unless chained"
    t = f.type.lower()
    # reject low-value header findings unless high/critical
    if t.startswith("missing ") and f.severity in ("low", "info"):
        return False, "Low-value missing header"
    for rp in REJECT_PATTERNS:
        if rp in t:
            if f.severity not in ("high", "critical"):
                return False, f"Rejected pattern: {rp}"
    # XSS: ensure payload actually reflected unencoded
    if "xss" in t:
        if "<" not in f.payload and "javascript" not in f.payload.lower():
            return False, "XSS payload lacks markup"
    # SQLi time-based: require delay evidence
    if "time-based" in t:
        if "delayed" not in f.evidence.lower():
            return False, "No delay evidence"
    return True, "passed deterministic checks"


def llm_critic(f: Finding, target_scope=""):
    llm = get_llm(fast=True)
    if not llm.available():
        return True, "LLM unavailable; deterministic only"
    prompt = [
        {"role": "system", "content": "You are a strict bug bounty triager. Decide if a finding is a real, reportable vulnerability or a false positive. Respond JSON: {\"valid\": bool, \"reason\": str, \"severity_adjust\": str|null}."},
        {"role": "user", "content": f"Target: {f.target}\nType: {f.type}\nSeverity: {f.severity}\nURL: {f.url}\nParam: {f.parameter}\nPayload: {f.payload}\nEvidence: {f.evidence}\nResponse snippet: {f.response_snippet[:500]}\nScope: {target_scope}\n\nIs this a genuine, exploitable vulnerability a triager would accept?"},
    ]
    res = llm.json(prompt, temperature=0.1, max_tokens=300)
    if not res:
        return True, "LLM no response"
    valid = bool(res.get("valid", True))
    reason = res.get("reason", "")
    adj = res.get("severity_adjust")
    if adj and adj in ("critical", "high", "medium", "low"):
        f.severity = adj
    return valid, reason


def validate_finding(f: Finding, use_llm=True):
    ok, reason = deterministic_check(f)
    if not ok:
        f.false_positive = True
        f.notes = reason
        return False, reason
    if use_llm:
        valid, reason = llm_critic(f)
        if not valid:
            f.false_positive = True
            f.notes = reason
            return False, reason
        f.verified = True
        f.confidence = min(1.0, f.confidence + 0.15)
    else:
        f.verified = True
    return True, "valid"


def seven_question_gate(f: Finding):
    """Return dict of question->bool via LLM if available else heuristic."""
    llm = get_llm(fast=True)
    if not llm.available():
        from agents.deterministic.stub import seven_question_gate as det_gate
        gate, _ = det_gate(f)
        return gate
    prompt = [
        {"role": "system", "content": "You are a bug bounty triage gate. For the finding, answer each of the 7 questions true/false. Respond JSON: {\"answers\": [bool,...], \"score\": int, \"verdict\": \"submit|revise|reject\"}."},
        {"role": "user", "content": f"Finding: {f.type} | {f.severity} | {f.url}\nEvidence: {f.evidence}\nPayload: {f.payload}\nQuestions:\n" + "\n".join(f"{i+1}. {q}" for i, q in enumerate(QUESTIONS))},
    ]
    res = llm.json(prompt, temperature=0.1, max_tokens=400)
    if not res:
        base = f.verified
        return {q: base for q in QUESTIONS}
    answers = res.get("answers", [True] * 7)
    out = {}
    for i, q in enumerate(QUESTIONS):
        out[q] = bool(answers[i]) if i < len(answers) else False
    return out
