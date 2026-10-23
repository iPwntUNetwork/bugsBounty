"""Real-time Per-Agent Telemetry, Subprocess Tracker & Live Operations Event Bus (`TELEMETRY`).

Powers live observability across the `#basement-ops` Web War-Room and CLI:
  - Per-agent live status (`IDLE` / `RUNNING` / `DONE` / `ERROR`), active `.bin/` tool, current task,
    HTTP probe count, `.bin/` execution count, WAF blocks/bypasses, verified wins & brown-eyes.
  - Live running `.bin/` subprocess table (`active_processes`) + recent subprocess history.
  - Monotonic ring-buffered live wire stream (`events`, `seq = 1..N`) for real-time UI streaming.
"""
from collections import deque
from contextlib import contextmanager
import contextvars
import threading
import time
import uuid

AGENT_HANDLES = ("GHOST", "BLITZ", "SWITCH", "RAZOR", "CHAINSAW", "FIXER")

_AGENT_CTX: contextvars.ContextVar[str] = contextvars.ContextVar("bugsbounty_agent", default="")


def _empty_agent_stats(handle: str) -> dict:
    return {
        "handle": handle,
        "state": "IDLE",
        "current_tool": "",
        "current_task": "Standing by in #basement-ops",
        "current_target": "",
        "started_at": None,
        "last_active_at": None,
        "total_runtime_ms": 0.0,
        "runs_completed": 0,
        "http_requests": 0,
        "http_errors": 0,
        "bin_runs": 0,
        "waf_blocks": 0,
        "waf_bypasses": 0,
        "leads_found": 0,
        "escalations": 0,
        "verified_wins": 0,
        "browneyes": 0,
        "last_event": "",
    }


class TelemetryHub:
    """Thread-safe real-time telemetry store for agents, `.bin/` processes, HTTP traffic, WAF & BeEF/OOB C2."""

    def __init__(self, max_events: int = 750, max_procs: int = 80):
        self._lock = threading.RLock()
        self._seq = 0
        self._active_stage_agent: str = ""
        self._agents: dict[str, dict] = {h: _empty_agent_stats(h) for h in AGENT_HANDLES}
        self._active_procs: dict[str, dict] = {}
        self._recent_procs: deque[dict] = deque(maxlen=max_procs)
        self._events: deque[dict] = deque(maxlen=max_events)
        self._totals = {
            "http_requests": 0,
            "bin_runs": 0,
            "waf_blocks": 0,
            "waf_bypasses": 0,
            "beef_hooks": 0,
            "beef_commands": 0,
            "oob_hits": 0,
        }

    def current_agent(self) -> str:
        ctx_val = _AGENT_CTX.get()
        if ctx_val:
            return ctx_val
        with self._lock:
            return self._active_stage_agent or "GHOST"

    def _emit_unlocked(self, category: str, agent: str, title: str, detail: str = "", level: str = "info", meta: dict | None = None) -> dict:
        self._seq += 1
        now = round(time.time(), 3)
        ev = {
            "seq": self._seq,
            "ts": now,
            "category": category,
            "agent": agent or "SYSTEM",
            "level": level,
            "title": title,
            "detail": detail,
            "meta": meta or {},
        }
        self._events.append(ev)
        if agent in self._agents:
            self._agents[agent]["last_active_at"] = now
            self._agents[agent]["last_event"] = title[:160]
        return ev

    def emit(self, category: str, title: str, detail: str = "", agent: str | None = None, level: str = "info", meta: dict | None = None) -> dict:
        ag = (agent or self.current_agent() or "SYSTEM").upper()
        with self._lock:
            return self._emit_unlocked(category, ag, title, detail=detail, level=level, meta=meta)

    @contextmanager
    def agent_scope(self, handle: str, task: str = "", target: str = "", tool: str = ""):
        ag = handle.upper()
        tok = _AGENT_CTX.set(ag)
        t0 = time.time()
        with self._lock:
            prev_stage = self._active_stage_agent
            self._active_stage_agent = ag
            if ag in self._agents:
                st = self._agents[ag]
                st["state"] = "RUNNING"
                st["started_at"] = st["started_at"] or round(t0, 3)
                st["last_active_at"] = round(t0, 3)
                if task:
                    st["current_task"] = task
                if target:
                    st["current_target"] = target
                if tool:
                    st["current_tool"] = tool
            self._emit_unlocked("agent", ag, f"{ag} started: {task or 'active operation'}", detail=target, level="info")
        try:
            yield
        except Exception as exc:
            elapsed = round((time.time() - t0) * 1000.0, 1)
            with self._lock:
                self._active_stage_agent = prev_stage
                if ag in self._agents:
                    st = self._agents[ag]
                    st["state"] = "ERROR"
                    st["current_tool"] = ""
                    st["current_task"] = f"Error: {str(exc)[:110]}"
                    st["total_runtime_ms"] = round(st["total_runtime_ms"] + elapsed, 1)
                self._emit_unlocked("agent", ag, f"{ag} error: {exc}", level="error")
            _AGENT_CTX.reset(tok)
            raise
        else:
            elapsed = round((time.time() - t0) * 1000.0, 1)
            with self._lock:
                self._active_stage_agent = prev_stage
                if ag in self._agents:
                    st = self._agents[ag]
                    st["state"] = "DONE"
                    st["current_tool"] = ""
                    st["current_task"] = f"Completed ({elapsed:.0f} ms) — ready for next task"
                    st["runs_completed"] += 1
                    st["total_runtime_ms"] = round(st["total_runtime_ms"] + elapsed, 1)
                self._emit_unlocked("agent", ag, f"{ag} finished ({elapsed:.0f} ms)", detail=task, level="success")
            _AGENT_CTX.reset(tok)

    def set_agent_step(self, handle: str, task: str, tool: str = ""):
        ag = handle.upper()
        with self._lock:
            if ag in self._agents:
                self._agents[ag]["current_task"] = task
                if tool is not None:
                    self._agents[ag]["current_tool"] = tool
                self._agents[ag]["last_active_at"] = round(time.time(), 3)

    @contextmanager
    def proc_scope(self, binary_name: str, args: list[str] | None = None, source: str = ".bin"):
        ag = self.current_agent()
        pid_key = f"proc-{uuid.uuid4().hex[:8]}"
        t0 = time.time()
        cmd_preview = f"{binary_name} {' '.join(str(a) for a in (args or []))}".strip()[:220]
        rec = {
            "id": pid_key,
            "agent": ag,
            "tool": binary_name,
            "source": source,
            "cmd": cmd_preview,
            "started_at": round(t0, 3),
            "status": "RUNNING",
        }
        with self._lock:
            self._active_procs[pid_key] = rec
            self._totals["bin_runs"] += 1
            if ag in self._agents:
                self._agents[ag]["bin_runs"] += 1
                self._agents[ag]["current_tool"] = binary_name
            self._emit_unlocked("process", ag, f"Exec `{binary_name}`", detail=cmd_preview, level="info", meta={"tool": binary_name})
        result_box = {"returncode": 0, "preview": ""}
        try:
            yield result_box
        finally:
            dur = round((time.time() - t0) * 1000.0, 1)
            with self._lock:
                self._active_procs.pop(pid_key, None)
                done = dict(rec)
                done["duration_ms"] = dur
                done["returncode"] = result_box.get("returncode", 0)
                done["preview"] = (result_box.get("preview") or "")[:200]
                done["status"] = "OK" if done["returncode"] in (0, None) or done["preview"] else f"EXIT {done['returncode']}"
                self._recent_procs.appendleft(done)
                if ag in self._agents and self._agents[ag]["current_tool"] == binary_name:
                    self._agents[ag]["current_tool"] = ""
                self._emit_unlocked(
                    "process",
                    ag,
                    f"`{binary_name}` finished in {dur:.0f} ms ({done['status']})",
                    detail=done["preview"] or cmd_preview,
                    level="success" if done["status"] == "OK" else "warn",
                    meta={"tool": binary_name, "duration_ms": dur},
                )

    def record_http(self, method: str, url: str, status: int, elapsed_ms: float, ua: str = "", error: str | None = None):
        ag = self.current_agent()
        lvl = "error" if status == 0 else ("warn" if status in (401, 403, 406, 429, 503) else "info")
        with self._lock:
            self._totals["http_requests"] += 1
            if ag in self._agents:
                self._agents[ag]["http_requests"] += 1
                if status == 0:
                    self._agents[ag]["http_errors"] += 1
                if not self._agents[ag]["current_tool"]:
                    self._agents[ag]["current_tool"] = f"HTTP {method.upper()}"
            self._emit_unlocked(
                "http",
                ag,
                f"{method.upper()} {url[:110]} -> {status or 'ERR'} ({elapsed_ms:.0f} ms)",
                detail=error or (ua[:90] if ua else ""),
                level=lvl,
                meta={"method": method.upper(), "url": url, "status": status, "ms": round(elapsed_ms, 1)},
            )

    def record_waf(self, kind: str, host: str, url: str = "", vendor: str = "", tamper: str = "", status: int = 0):
        ag = self.current_agent()
        with self._lock:
            if kind == "block":
                self._totals["waf_blocks"] += 1
                if ag in self._agents:
                    self._agents[ag]["waf_blocks"] += 1
                self._emit_unlocked(
                    "waf",
                    ag,
                    f"WAF BLOCK ({vendor or 'edge'} HTTP {status}) on `{tamper or 'raw'}`",
                    detail=url or host,
                    level="warn",
                    meta={"kind": "block", "vendor": vendor, "tamper": tamper},
                )
            else:
                self._totals["waf_bypasses"] += 1
                if ag in self._agents:
                    self._agents[ag]["waf_bypasses"] += 1
                self._emit_unlocked(
                    "waf",
                    ag,
                    f"WAF BYPASS WIN via `{tamper}` against {vendor or host}!",
                    detail=url or host,
                    level="success",
                    meta={"kind": "bypass", "vendor": vendor, "tamper": tamper},
                )

    def record_finding(self, event_type: str, agent: str, vuln_type: str, url: str, detail: str = ""):
        ag = agent.upper()
        with self._lock:
            if ag in self._agents:
                if event_type == "lead":
                    self._agents[ag]["leads_found"] += 1
                elif event_type == "escalate":
                    self._agents[ag]["escalations"] += 1
                elif event_type == "verified":
                    self._agents[ag]["verified_wins"] += 1
                elif event_type == "browneye":
                    self._agents[ag]["browneyes"] += 1
            lvl = "success" if event_type in ("verified", "escalate") else ("error" if event_type == "browneye" else "info")
            self._emit_unlocked("critic" if event_type in ("verified", "browneye") else "finding", ag, f"[{event_type.upper()}] {vuln_type} @ {url[:95]}", detail=detail[:180], level=lvl)

    def record_c2(self, channel: str, title: str, detail: str = "", level: str = "success"):
        with self._lock:
            if channel == "beef_hook":
                self._totals["beef_hooks"] += 1
            elif channel == "beef_cmd":
                self._totals["beef_commands"] += 1
            elif channel == "oob":
                self._totals["oob_hits"] += 1
            ag = "SWITCH" if channel.startswith("beef") or channel == "oob" else self.current_agent()
            self._emit_unlocked("c2", ag, title, detail=detail[:220], level=level, meta={"channel": channel})

    def snapshot(self, since_seq: int = 0, limit: int = 160) -> dict:
        now = time.time()
        with self._lock:
            active_list = []
            for p in self._active_procs.values():
                item = dict(p)
                item["elapsed_ms"] = round((now - p["started_at"]) * 1000.0, 1)
                active_list.append(item)
            if since_seq > 0:
                evs = [e for e in self._events if e["seq"] > since_seq][-limit:]
            else:
                evs = list(self._events)[-limit:]
            return {
                "seq": self._seq,
                "totals": dict(self._totals),
                "active_stage_agent": self._active_stage_agent,
                "agents": {k: dict(v) for k, v in self._agents.items()},
                "active_processes": active_list,
                "recent_processes": list(self._recent_procs)[:30],
                "events": evs,
            }


TELEMETRY = TelemetryHub()
