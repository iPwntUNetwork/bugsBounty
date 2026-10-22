"""Cross-target pattern learning DB."""
import json, time
from pathlib import Path
from core.config import HOME

DB = HOME / "memory" / "pattern_db.jsonl"

def record(target, finding_type, url, payload):
    obj = {"ts": time.time(), "target": target, "type": finding_type, "url": url, "payload": payload}
    DB.parent.mkdir(parents=True, exist_ok=True)
    with open(DB, "a") as f:
        f.write(json.dumps(obj) + "\n")

def query(finding_type=None, target=None):
    if not DB.exists():
        return []
    out = []
    for line in DB.read_text().splitlines():
        if not line.strip():
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        if finding_type and finding_type.lower() not in o.get("type", "").lower():
            continue
        if target and target not in o.get("target", ""):
            continue
        out.append(o)
    return out

def top_patterns(n=10):
    from collections import Counter
    if not DB.exists():
        return []
    c = Counter()
    for line in DB.read_text().splitlines():
        if not line.strip():
            continue
        try:
            o = json.loads(line)
            c[o.get("type")] += 1
        except Exception:
            pass
    return c.most_common(n)
