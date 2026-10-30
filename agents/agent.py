"""Single-Agent Core (`AGENT`) — one operator, six ordered internal stages.

`bugsBounty` runs **one** agent. There is no crew, no persona group and no handoff
between separate operators. A single agent owns the whole engagement and executes the
offensive workflow as six strictly ordered internal stages:

  1. `recon`    — Attack-surface mapping (`subfinder`, `assetfinder`, `dnsx`, `httpx`, `wafw00f`,
                  `katana`, `hakrawler`, `arjun`, `ffuf`, `gobuster`, `gau`, `waybackurls`, `paramspider`)
  2. `hunt`     — WAF-evading vulnerability hunting (`PAYLOAD_MUTEX` + 24 tampers + UA rotation)
  3. `escalate` — Heavy-tool confirmation (`sqlmap`, `dalfox` + `BeefServer`, `commix`, `interactsh`/OOB)
  4. `verify`   — 100% deterministic control-probe verification (zero LLM calls, no guessing)
  5. `chains`   — Multi-step exploit-chain synthesis, built only from verified findings
  6. `report`   — CVSS v3.1 triage, reproducible PoCs, transcript & Markdown advisory

The agent still keeps every guardrail of the old split pipeline (deterministic
verification, detector provenance, mutex-coordinated WAF evasion) — it just no longer
pretends to be six different people talking to each other.
"""
from dataclasses import dataclass
import hashlib
import json
import threading
import time

from rich.console import Console

from core.config import CFG
from core.memory import log_event, scan_dir

console = Console()

AGENT_HANDLE = "AGENT"
AGENT_COLOR = "cyan"


@dataclass(frozen=True)
class Stage:
    """One ordered internal stage of the single agent's workflow."""

    key: str
    index: int
    label: str
    task: str
    tool: str


STAGES: tuple[Stage, ...] = (
    Stage("recon", 1, "Recon", "Mapping the attack surface", "subfinder/httpx/katana"),
    Stage("hunt", 2, "Hunt", "Hunting vulnerabilities behind the WAF", "scan/* + PAYLOAD_MUTEX"),
    Stage("escalate", 3, "Escalate", "Confirming leads with heavy tools", "sqlmap/dalfox/commix/interactsh"),
    Stage("verify", 4, "Verify", "Deterministically disproving weak claims", "control-probes"),
    Stage("chains", 5, "Chains", "Synthesising exploit chains", "chain-builder"),
    Stage("report", 6, "Report", "Scoring, packaging and reporting", "cvss/poc/reporter"),
)

STAGE_BY_KEY: dict[str, Stage] = {s.key: s for s in STAGES}
STAGE_COUNT = len(STAGES)


@dataclass(frozen=True)
class AgentProfile:
    handle: str
    role: str
    color: str
    bio: str
    system_prompt: str


AGENT = AgentProfile(
    handle=AGENT_HANDLE,
    role="Offensive Security Agent",
    color=AGENT_COLOR,
    bio=(
        "One agent runs the entire engagement: recon, hunting, tool escalation, deterministic "
        "verification, exploit chaining and bounty reporting."
    ),
    system_prompt=(
        "You are AGENT, the single autonomous offensive-security operator of the bugsBounty framework. "
        "You are technically precise, concise and honest about uncertainty. You never invent findings: every "
        "claim you report has been confirmed by deterministic control probes, and you say so plainly when "
        "something could not be proven."
    ),
)

# Backwards-friendly alias for callers that want the agent as a mapping.
AGENT_INFO: dict[str, dict] = {
    AGENT.handle: {
        "handle": AGENT.handle,
        "role": AGENT.role,
        "color": AGENT.color,
        "bio": AGENT.bio,
    }
}

VERIFIED_TEMPLATES = [
    "VERIFIED `{vuln}` on `{url}` (param: `{param}`) — survived deterministic control probes.",
    "CONFIRMED `{vuln}` at `{url}` (param: `{param}`) — attack response differs from the benign baseline.",
    "VERIFIED `{vuln}` on `{url}` — reproducible and control-probe clean.",
]

DISPROVED_TEMPLATES = [
    "Binned `{vuln}` at `{url}` — {reason}.",
    "Disproved `{vuln}` on `{url}` — {reason}.",
    "Rejected `{vuln}` at `{url}` — deterministic controls say {reason}.",
]


def _pick(templates: list[str], seed: str) -> str:
    idx = int(hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()[:8], 16) % len(templates)
    return templates[idx]


class AgentBus:
    """Thread-safe transcript bus for the single agent (stage updates, verdicts, operator turns)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._messages: list[dict] = []

    def reset(self) -> None:
        with self._lock:
            self._messages.clear()

    def say(
        self,
        text: str,
        kind: str = "info",
        stage: str | None = None,
        target: str | None = None,
        meta: dict | None = None,
        verbose: bool = True,
    ) -> dict:
        stage_obj = STAGE_BY_KEY.get(stage or "")
        entry = {
            "ts": round(time.time(), 3),
            "speaker": AGENT.handle,
            "role": AGENT.role,
            "stage": stage_obj.key if stage_obj else "",
            "stage_label": stage_obj.label if stage_obj else "",
            "kind": kind,
            "text": text,
            "meta": meta or {},
        }
        with self._lock:
            self._messages.append(entry)

        if target:
            log_event(target, f"agent_{kind}", entry)

        if verbose and CFG.get("agent_streaming", True):
            tag = {
                "stage": "[bold cyan][STAGE][/bold cyan]",
                "verified": "[bold green][VERIFIED][/bold green]",
                "disproved": "[bold red][BINNED][/bold red]",
                "waf": "[bold yellow][WAF][/bold yellow]",
                "warn": "[bold yellow][WARN][/bold yellow]",
                "error": "[bold red][ERROR][/bold red]",
            }.get(kind, "[dim][AGENT][/dim]")
            console.print(f"  {tag} [cyan][bold]{AGENT.handle}[/bold][/cyan]: {text}")
        return entry

    # -- stage lifecycle -------------------------------------------------
    def stage_started(self, stage: str, detail: str = "", target: str | None = None) -> dict:
        s = STAGE_BY_KEY[stage]
        text = f"[{s.index}/{STAGE_COUNT}] {s.label} — {s.task}" + (f": {detail}" if detail else "")
        return self.say(text, kind="stage", stage=s.key, target=target)

    def stage_done(self, stage: str, summary: str, target: str | None = None) -> dict:
        s = STAGE_BY_KEY[stage]
        text = f"[{s.index}/{STAGE_COUNT}] {s.label} complete — {summary}"
        return self.say(text, kind="stage", stage=s.key, target=target)

    # -- verdicts (deterministic verifier) -------------------------------
    def verified(self, vuln: str, url: str, param: str = "", target: str | None = None) -> dict:
        msg = _pick(VERIFIED_TEMPLATES, f"{vuln}:{url}:{param}").format(
            vuln=vuln, url=url, param=param or "endpoint"
        )
        return self.say(msg, kind="verified", stage="verify", target=target, meta={"vuln": vuln, "url": url})

    def disproved(self, vuln: str, url: str, reason: str, target: str | None = None) -> dict:
        msg = _pick(DISPROVED_TEMPLATES, f"{vuln}:{url}:{reason}").format(vuln=vuln, url=url, reason=reason)
        return self.say(
            msg,
            kind="disproved",
            stage="verify",
            target=target,
            meta={"vuln": vuln, "url": url, "reason": reason},
        )

    # -- transcript ------------------------------------------------------
    def transcript(self) -> list[dict]:
        with self._lock:
            return list(self._messages)

    def save(self, target: str) -> str:
        sd = scan_dir(target)
        out = sd / "agent_transcript.json"
        out.write_text(json.dumps(self.transcript(), indent=2))
        return str(out)


AGENT_BUS = AgentBus()
