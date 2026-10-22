"""Finding data model."""
from dataclasses import dataclass, field, asdict
import time, json


@dataclass
class Finding:
    id: str
    target: str
    type: str
    severity: str  # critical/high/medium/low/info
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

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(asdict(self))
