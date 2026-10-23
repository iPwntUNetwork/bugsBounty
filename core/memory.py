"""Hunt memory: patterns, audit log, leads."""
import json, time, os
from pathlib import Path
from core.config import HOME

MEM = HOME / "memory"
LEADS = HOME / "leads"
REPORTS = HOME / "reports"
RECON = HOME / "recon"
SCANS = HOME / "scans"


def _append_jsonl(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")


def log_event(target, kind, data):
    _append_jsonl(MEM / "audit.jsonl", {"ts": time.time(), "target": target, "kind": kind, "data": data})


def set_phase(target, phase: str):
    log_event(target, "phase", {"phase": phase})
    try:
        sd = scan_dir(target)
        (sd / "current_phase.txt").write_text(phase)
    except Exception:
        pass


def save_pattern(pattern):
    _append_jsonl(MEM / "patterns.jsonl", {"ts": time.time(), **pattern})


def load_patterns():
    p = MEM / "patterns.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def recon_dir(target):
    d = RECON / target.replace("/", "_")
    d.mkdir(parents=True, exist_ok=True)
    return d


def scan_dir(target):
    d = SCANS / target.replace("/", "_")
    d.mkdir(parents=True, exist_ok=True)
    return d


class LeadBoard:
    def __init__(self, target):
        self.target = target
        self.path = LEADS / f"{target.replace('/', '_')}.jsonl"

    def ingest(self, leads):
        for l in leads:
            self.touch(l.get("id") or l.get("url"), l.get("status", "new"), l)

    def touch(self, lid, status, extra=None):
        obj = {"ts": time.time(), "id": lid, "status": status}
        if extra:
            obj.update({k: v for k, v in extra.items() if k not in ("id",)})
        _append_jsonl(self.path, obj)

    def show(self):
        if not self.path.exists():
            return []
        # collapse by id keeping latest
        latest = {}
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            latest[o.get("id")] = o
        return list(latest.values())

    def next_lead(self):
        leads = [l for l in self.show() if l.get("status") in ("new", "in_progress")]
        # priority sort
        prio = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        leads.sort(key=lambda x: prio.get(x.get("priority", "low"), 3))
        return leads[0] if leads else None
