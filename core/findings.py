"""Finding data model & persistence with strict agent provenance, escalation telemetry, and critic audit trail."""
from dataclasses import dataclass, field, asdict
import json
import time
from core.config import HOME

_CVSS_DEFAULT = {
    "critical": 9.4,
    "high": 8.2,
    "medium": 6.1,
    "low": 3.5,
    "info": 0.0,
}


@dataclass
class Finding:
    id: str
    target: str
    type: str
    severity: str
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    request: str = ""
    response_snippet: str = ""
    confidence: float = 0.5
    verified: bool = False
    false_positive: bool = False
    notes: str = ""
    ts: float = field(default_factory=time.time)
    poc: str = ""
    report_path: str = ""
    detected_by: str = "scanner"
    escalated_with: list = field(default_factory=list)
    exploitable: bool = False
    critic_by: str = ""
    disprove_attempts: list = field(default_factory=list)
    waf_bypass_used: str = ""
    oob_interactions: list = field(default_factory=list)
    beef_hook_url: str = ""
    sqlmap_confirmed: bool = False
    critic_verdict: str = ""
    critic_notes: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    @property
    def cvss(self) -> float:
        return _CVSS_DEFAULT.get((self.severity or "medium").lower(), 5.0)

    def to_dict(self):
        d = asdict(self)
        d["cvss"] = self.cvss
        return d

    def to_json(self):
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        allowed = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**allowed)


def _findings_path(target: str | None = None):
    if target:
        safe = target.replace("://", "_").replace("/", "_")
        return HOME / "scans" / safe / "findings.jsonl"
    return HOME / "memory" / "findings.jsonl"


def save_finding(f: Finding) -> Finding:
    for p in (_findings_path(f.target), _findings_path(None)):
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as fh:
            fh.write(f.to_json() + "\n")
    try:
        from memory.pattern_db import record
        record(f)
    except Exception:
        pass
    return f


def load_findings(target: str | None = None) -> list[Finding]:
    p = _findings_path(target)
    if not p.exists():
        return []
    seen = {}
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = Finding.from_dict(json.loads(line))
            seen[obj.id] = obj
        except Exception:
            pass
    return list(seen.values())


class FindingStore:
    def __init__(self, target: str | None = None):
        self.target = target

    def add(self, f: Finding) -> Finding:
        return save_finding(f)

    def all(self) -> list[Finding]:
        return load_findings(self.target)

