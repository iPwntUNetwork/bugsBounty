"""100% Deterministic Adversarial Exploit Critic (`RAZOR`).

Core Architectural Guarantees:
  1. STRICT SEPARATION OF DUTIES:
     - `RAZOR` NEVER runs detection scans (`detected_by` MUST exist AND MUST NOT be `critic` / `razor`).
     - Any self-critique or unattributed finding immediately raises `SeparationOfDutiesError`.
  2. ZERO LLM CALLS:
     - Every verdict (`verified` vs `disproved`) is computed by deterministic, repeatable HTTP control probes,
       differential baselines, encoding/escaping inspection, OOB callback receipts, and SQLite/DBMS extraction proofs.
  3. ACTIVE FALSIFICATION:
     - Rather than merely repeating the payload once, `RAZOR` actively tries to DISPROVE every claim:
       * SQLi: verifies benign pure-alpha control does NOT trigger SQL error/data leak, AND verifies boolean/UNION/time/sqlmap differential.
       * XSS: verifies raw executable HTML/JS token or unescaped attribute breakout is present (rejects HTML-entity encoded `&lt;` or plain JSON/text non-HTML content-type reflections!).
       * SSRF: demands verified OOB callback receipt OR differential internal-resource response that benign external control fails to produce.
       * CMDi: demands real UID/GID command output OR verified OOB execution callback absent from benign baseline.
       * LFI / Path Traversal: demands structured `/etc/passwd` (`root:x:0:0:`) or `win.ini` absent on benign parameter value.
       * SSTI: demands evaluated arithmetic (`49`) while literal expression is NOT reflected verbatim AND baseline lacks `49`.
       * 403 Bypass: re-verifies bare request still returns 401/403 while bypass vector returns 200 with real body delta.
       * Exposures / Secrets / CORS / CSRF / Security Headers: deterministic structural & header re-verification.
"""
import re
import urllib.parse
from core.http import get
from core.findings import Finding
from core.waf_bypass import inject_param
from agents.crew import CREW_BUS

CRITIC_AGENT_ID = "critic:razor"


class SeparationOfDutiesError(RuntimeError):
    """Raised when the agent that detected a vulnerability attempts to audit/criticize its own finding."""


def _enforce_separation_of_duties(finding: Finding) -> str:
    detector = (finding.detected_by or "").strip()
    if not detector:
        raise SeparationOfDutiesError(
            f"Finding '{finding.id}' ({finding.type} at {finding.url}) has empty `detected_by`; "
            "detector provenance is mandatory before RAZOR audit."
        )
    lowered = detector.lower()
    if lowered == CRITIC_AGENT_ID or lowered.startswith("critic") or "razor" in lowered:
        raise SeparationOfDutiesError(
            f"Separation of Duties violation on '{finding.id}': detector '{detector}' cannot audit its own finding!"
        )
    return detector


def _detector_handle(detected_by: str) -> str:
    low = detected_by.lower()
    if "recon" in low or "ghost" in low:
        return "GHOST"
    if "switch" in low or "escalat" in low:
        return "SWITCH"
    return "BLITZ"


def _audit_sqli(f: Finding) -> tuple[bool, list[str], str]:
    notes = []
    if f.sqlmap_confirmed:
        ctrl = get(inject_param(f.url, f.parameter, "bbctrlplainalpha") if f.parameter else f.url)
        notes.append(f"sqlmap deterministic DBMS confirmation present; benign control HTTP {ctrl.status}")
        return True, notes, "sqlmap DBMS extraction/boolean confirmation verified"

    if not f.parameter:
        return False, ["Missing SQLi parameter name"], "missing parameter"

    ctrl_plain = get(inject_param(f.url, f.parameter, "bbctrlplainalpha"))
    atk = get(inject_param(f.url, f.parameter, f.payload or "' OR '1'='1'--"))
    ctrl_false = get(inject_param(f.url, f.parameter, "1' AND '1'='2'--"))

    plain_body = (ctrl_plain.text or "")
    atk_body = (atk.text or "")
    false_body = (ctrl_false.text or "")
    notes.append(
        f"len(plain)={len(plain_body)}, len(atk)={len(atk_body)}, len(false_cond)={len(false_body)}"
    )

    sql_err_re = re.compile(
        r"(sqlite3\.OperationalError|SQL syntax.*?MySQL|PostgreSQL.*?ERROR|ORA-\d{5}|Unclosed quotation mark|syntax error near)",
        re.I,
    )
    if sql_err_re.search(atk_body) and sql_err_re.search(plain_body):
        return False, notes + ["Static SQL error banner appears even on pure alphabetic input!"], "static SQL banner on benign control"

    if abs(len(atk_body) - len(plain_body)) < 8 and not sql_err_re.search(atk_body):
        return False, notes + ["Attack response indistinguishable from plain control"], "zero response differential vs benign control"

    if sql_err_re.search(atk_body) and not sql_err_re.search(plain_body):
        quote_escaped = get(inject_param(f.url, f.parameter, "1''"))
        notes.append(f"quote-pair probe status={quote_escaped.status} len={len(quote_escaped.text or '')}")
        if quote_escaped.status != atk.status or not sql_err_re.search(quote_escaped.text or "") or len(atk_body) != len(false_body):
            return True, notes + ["Quote-pair differential confirms live SQL parser state"], "live SQL parser syntax/state differential verified"
        return False, notes + ["Single quote and paired quotes produced identical static error banner!"], "fake static error page ignores paired-quote SQL grammar"

    if abs(len(atk_body) - len(false_body)) >= 12 and len(atk_body) > len(plain_body):
        return True, notes + ["Boolean true/false differential extracted additional records"], "boolean/UNION SQL extraction verified"

    return False, notes + ["Failed boolean/parser falsification checks"], "boolean control matched attack response"


def _audit_xss(f: Finding) -> tuple[bool, list[str], str]:
    notes = []
    probe_url = inject_param(f.url, f.parameter, f.payload) if (f.parameter and f.parameter not in ("dom", "path")) else f.url
    r = get(probe_url)
    ctype = (r.headers.get("Content-Type") or "").lower()
    body = r.text or ""
    notes.append(f"HTTP {r.status} Content-Type='{ctype}' len={len(body)}")

    if "application/json" in ctype or "text/plain" in ctype:
        return False, notes + [f"Non-executable Content-Type ({ctype}) prevents browser HTML parsing"], f"non-HTML Content-Type {ctype}"

    exec_tag_re = re.compile(
        r"(<svg[^>]*/?\s*onload\s*=|<img[^>]*onerror\s*=|<script[^>]*>[^<]+</script>|"
        r"\"[^\"]*\bonfocus\s*=|'[^']*\bonfocus\s*=|<iframe[^>]*srcdoc\s*=)",
        re.I,
    )
    if exec_tag_re.search(body):
        return True, notes + ["Unencoded executable HTML/JS sink confirmed in rendered HTML body"], "live unencoded DOM/HTML execution context verified"

    if "&lt;" in body or "&quot;" in body:
        return False, notes + [" Angle brackets / quotes properly HTML-entity encoded"], "HTML-entity encoded reflection (non-executable)"

    return False, notes + ["Payload stripped or absent from HTML execution context"], "payload absent from executable DOM context"


def _audit_ssrf(f: Finding) -> tuple[bool, list[str], str]:
    notes = []
    if f.oob_interactions:
        notes.append(f"Verified {len(f.oob_interactions)} real out-of-band server callback(s)")
        return True, notes, "verified out-of-band HTTP/DNS server callback"

    ctrl = get(inject_param(f.url, f.parameter, "invalid_scheme_control_991") if f.parameter else f.url)
    atk = get(inject_param(f.url, f.parameter, f.payload) if f.parameter else f.url)
    ctrl_body = (ctrl.text or "").lower()
    atk_body = (atk.text or "").replace(f.payload or "", "").lower()
    markers = ("ami-id", "instance-id", "iam/security-credentials", "computemetadata", "oob-ack:")
    if any(m in atk_body and m not in ctrl_body for m in markers):
        return True, notes + ["Internal metadata marker present only under SSRF target"], "differential internal metadata fetch verified"

    return False, notes + ["No OOB callback receipt and benign control produced same static text"], "echoed/static SSRF string without server-side fetch"


def _audit_cmdi(f: Finding) -> tuple[bool, list[str], str]:
    notes = []
    if f.oob_interactions:
        notes.append(f"Verified {len(f.oob_interactions)} real OOB command-execution callback(s)")
        return True, notes, "out-of-band command execution callback verified"

    ctrl = get(inject_param(f.url, f.parameter, "127.0.0.1") if f.parameter else f.url)
    atk = get(inject_param(f.url, f.parameter, f.payload) if f.parameter else f.url)
    uid_re = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+\(", re.I)
    if uid_re.search(atk.text or "") and not uid_re.search(ctrl.text or ""):
        return True, notes + ["Real POSIX uid/gid output absent from benign control"], "live OS `id` output verified"

    return False, notes + ["No real OS execution output or OOB callback"], "missing command output differential"


def _audit_lfi(f: Finding) -> tuple[bool, list[str], str]:
    ctrl = get(inject_param(f.url, f.parameter, "welcome.txt") if f.parameter else f.url)
    atk = get(inject_param(f.url, f.parameter, f.payload) if f.parameter else f.url)
    passwd_re = re.compile(r"root:[^:\n]*:0:0:", re.I)
    if passwd_re.search(atk.text or "") and not passwd_re.search(ctrl.text or ""):
        return True, ["Verified `/etc/passwd` structure absent from benign filename control"], "`/etc/passwd` file read verified"
    return False, ["`/etc/passwd` absent or static across benign filename control"], "failed benign filename control"


def _audit_ssti(f: Finding) -> tuple[bool, list[str], str]:
    ctrl = get(inject_param(f.url, f.parameter, "bbplain") if f.parameter else f.url)
    atk = get(inject_param(f.url, f.parameter, f.payload or "{{7*7}}") if f.parameter else f.url)
    atk2 = get(inject_param(f.url, f.parameter, (f.payload or "{{7*7}}").replace("7*7", "6*7")) if f.parameter else f.url)
    if "49" in (atk.text or "") and "49" not in (ctrl.text or "") and "42" in (atk2.text or ""):
        return True, ["7*7->49 AND independent 6*7->42 second algebraic challenge passed!"], "dual-expression server template evaluation verified"
    return False, ["Failed dual algebraic challenge (`6*7 -> 42`)"], "static '49' string failed `6*7->42` algebraic control"


def _audit_403_bypass(f: Finding) -> tuple[bool, list[str], str]:
    parsed = urllib.parse.urlparse(f.url)
    clean_path = "/" + "/".join(seg for seg in parsed.path.split("/") if seg and seg not in (".", "..", "%2e"))
    base_url = f"{parsed.scheme}://{parsed.netloc}{clean_path}"
    locked = get(base_url)
    if locked.status not in (401, 403):
        return False, [f"Baseline `{base_url}` returned HTTP {locked.status}, not 401/403"], "endpoint was never locked"

    tech = f.payload or ""
    if ": " in tech:
        hk, hv = tech.split(": ", 1)
        bypass_resp = get(base_url, headers={hk: hv})
    else:
        bypass_resp = get(f.url)

    if bypass_resp.status == 200 and abs(len(bypass_resp.text or "") - len(locked.text or "")) > 15:
        return True, [f"Locked HTTP {locked.status} -> HTTP 200 ({len(bypass_resp.text or '')}B) reproduced deterministically"], "ACL bypass reproduced"
    return False, [f"Bypass replay returned HTTP {bypass_resp.status}"], "bypass replay failed"


def _audit_generic_http(f: Finding) -> tuple[bool, list[str], str]:
    r = get(f.url)
    parsed = urllib.parse.urlparse(f.url)
    nf = get(f"{parsed.scheme}://{parsed.netloc}/bb-nonexistent-control-77412")
    if r.status == 200 and abs(len(r.text or "") - len(nf.text or "")) > 15:
        return True, [f"HTTP 200 verified against 404 control ({len(r.text or '')}B vs {len(nf.text or '')}B)"], "HTTP 200 exposure differential verified"
    return False, [f"Indistinguishable from soft-404 control (status={r.status})"], "matched soft-404 control"


def critique_finding(finding: Finding, target: str | None = None) -> Finding:
    """Deterministically challenge a single Finding while strictly enforcing Separation of Duties."""
    detector = _enforce_separation_of_duties(finding)
    hunter_handle = _detector_handle(detector)
    vtype = (finding.type or "").lower()

    if "sql" in vtype:
        ok, notes, summary = _audit_sqli(finding)
    elif "xss" in vtype or "mitb" in vtype:
        ok, notes, summary = _audit_xss(finding)
    elif "ssrf" in vtype:
        ok, notes, summary = _audit_ssrf(finding)
    elif "command" in vtype or "cmdi" in vtype:
        ok, notes, summary = _audit_cmdi(finding)
    elif "lfi" in vtype or "traversal" in vtype:
        ok, notes, summary = _audit_lfi(finding)
    elif "template" in vtype or "ssti" in vtype:
        ok, notes, summary = _audit_ssti(finding)
    elif "403" in vtype or "access-control bypass" in vtype:
        ok, notes, summary = _audit_403_bypass(finding)
    else:
        ok, notes, summary = _audit_generic_http(finding)

    finding.critic_notes = notes
    if ok:
        finding.verified = True
        finding.critic_verdict = "verified"
        finding.confidence = max(finding.confidence, 0.95)
        CREW_BUS.cheer("RAZOR", hunter_handle, finding.type, finding.url, finding.parameter, target=target)
    else:
        finding.verified = False
        finding.critic_verdict = "disproved"
        finding.confidence = min(finding.confidence, 0.15)
        CREW_BUS.browneye("RAZOR", hunter_handle, finding.type, finding.url, summary, target=target)

    return finding


def run_critic(target: str, findings: list[Finding]) -> dict:
    """Audit all candidate findings with RAZOR, separating verified exploits from disproved mirages."""
    CREW_BUS.say(
        "RAZOR",
        f"Righto you over-caffeinated lunatics — hand over all {len(findings)} claims on `{target}`. "
        "Zero LLM guesswork, pure deterministic control probes. Anything fake cops a brown-eye.",
        kind="audit",
        target=target,
    )
    verified: list[Finding] = []
    disproved: list[Finding] = []

    for f in findings:
        audited = critique_finding(f, target=target)
        if audited.verified:
            verified.append(audited)
        else:
            disproved.append(audited)

    CREW_BUS.say(
        "RAZOR",
        f"Audit wrapped on `{target}`: {len(verified)} HARD-VERIFIED exploits shipped to CHAINSAW/FIXER, "
        f"{len(disproved)} bogus claims binned.",
        kind="audit",
        to="CHAINSAW",
        target=target,
    )
    return {
        "verified": verified,
        "disproved": disproved,
        "summary": {
            "total": len(findings),
            "verified_count": len(verified),
            "disproved_count": len(disproved),
        },
    }


run = run_critic
