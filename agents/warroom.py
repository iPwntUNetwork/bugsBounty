"""Interactive single-agent session (`#basement-ops`).

Powers:
  1. One conversational agent (`AGENT`) that answers, plans and can be asked to run work
  2. Async live background execution (`submit_async`) so the Web UI streams `.bin/`, HTTP & WAF events in real time
  3. Live BeEF C2 + OOB callback + `PAYLOAD_MUTEX` + `TELEMETRY` unified state snapshot
  4. Six ordered internal stages (recon -> hunt -> escalate -> verify -> chains -> report) owned by that one agent
"""
import json
import re
import threading
import time
import urllib.parse

from rich.console import Console
from rich.panel import Panel

from core.config import CFG, configure_api_key, mask_secret
from core.findings import Finding, FindingStore
from core.llm import get_llm
from core.mutex import PAYLOAD_MUTEX
from core.telemetry import TELEMETRY
from tools.beef import get_beef_server
from tools.oob import get_oob_manager
from tools.registry import tools_for_role
from agents.agent import (
    AGENT,
    AGENT_BUS,
    AGENT_HANDLE,
    STAGES,
    STAGE_BY_KEY,
    STAGE_COUNT,
)
from agents.recon_agent import run_recon
from agents.hunter import run_hunter
from agents.escalator import run_escalator
from agents.critic import run_critic
from agents.autopilot import run_autopilot
from agents.poc_generator import generate_pocs
from agents.triage import triage_findings
from agents.reporter import generate_report
from chains.builder import build_chains
from tests.vuln_server import VulnLabServer

console = Console()

URL_RE = re.compile(r"https?://[^\s<>'\"]+")

COMMANDS_HELP = (
    "`/lab` | `/target <url>` | `/autopilot` | `/recon` | `/hunt` | `/escalate` | `/verify` "
    "| `/chains` | `/report` | `/status` | `/tools` | `/key <API_KEY>` | `/quit`"
)


def stage_rows(done: set[str], current: str = "") -> list[dict]:
    """Render the six stage rows for the UI/CLI, marking done / running / pending."""
    rows = []
    for s in STAGES:
        if s.key in done:
            state = "done"
        elif s.key == current:
            state = "running"
        else:
            state = "pending"
        rows.append({"key": s.key, "index": s.index, "label": s.label, "task": s.task, "state": state})
    return rows


class WarRoomSession:
    """Stateful session shared by the terminal REPL, one-shot CLI and the Web console."""

    def __init__(self, target: str | None = None):
        self.lock = threading.RLock()
        self.target: str = ""
        self.surface: dict | None = None
        self.raw_findings: list[Finding] = []
        self.verified_findings: list[Finding] = []
        self.disproved_findings: list[Finding] = []
        self.chains: list[dict] = []
        self.pocs: list[dict] = []
        self.last_report_path: str = ""
        self.lab_server: VulnLabServer | None = None
        self.running_job: dict | None = None
        self.completed_stages: set[str] = set()
        self.current_stage: str = ""
        if target:
            self.set_target(target)

    @property
    def host_label(self) -> str:
        if not self.target:
            return ""
        return urllib.parse.urlparse(self.target).netloc or self.target

    # -- target & lab ----------------------------------------------------
    def set_target(self, url_or_host: str) -> str:
        u = url_or_host.strip()
        if u and "://" not in u:
            u = f"http://{u}"
        self.target = u
        self.completed_stages = set()
        self.current_stage = ""
        TELEMETRY.emit("agent", f"Active target locked -> {self.target}", agent=AGENT_HANDLE, level="info")
        AGENT_BUS.say(
            f"Target set to `{self.target}`. Say `/autopilot` to run all {STAGE_COUNT} stages, "
            "or run them one at a time.",
            kind="info",
            target=self.host_label or None,
        )
        return self.target

    def start_lab(self, enable_waf: bool = True) -> str:
        with self.lock:
            if self.lab_server is None:
                CFG["rate_limit"] = max(float(CFG.get("rate_limit") or 25.0), 120.0)
                self.lab_server = VulnLabServer(enable_waf=enable_waf)
                url = self.lab_server.start()
            else:
                url = self.lab_server.base_url
            self.target = url
        TELEMETRY.emit("agent", f"VulnCorp Target Lab online at {url} (WAF={'ON' if enable_waf else 'OFF'})", agent=AGENT_HANDLE, level="success")
        AGENT_BUS.say(
            f"Local VulnCorp lab is live at `{url}` (WAF={'ON' if enable_waf else 'OFF'}). "
            "It exposes real SQLi, XSS, SSRF, CMDi, traversal, SSTI, a 403 gate, an exposed `.env` "
            "and six deliberate false-positive traps.",
            kind="info",
            target=self.host_label,
        )
        return url

    # -- state -----------------------------------------------------------
    def status_dict(self) -> dict:
        llm = get_llm()
        beef = get_beef_server()
        oob = get_oob_manager()
        job = dict(self.running_job) if self.running_job else None
        if job and job.get("started_at"):
            job["elapsed_s"] = round(time.time() - job["started_at"], 1)
        return {
            "target": self.target,
            "lab_running": self.lab_server is not None,
            "lab_url": self.lab_server.base_url if self.lab_server else None,
            "running_job": job,
            "surface_urls": len((self.surface or {}).get("urls") or []),
            "param_urls": len((self.surface or {}).get("param_urls") or []),
            "locked_urls": len((self.surface or {}).get("locked_urls") or []),
            "waf": ((self.surface or {}).get("waf") or {}).get("waf") or ("cloudflare (lab)" if self.lab_server else None),
            "raw_count": len(self.raw_findings),
            "verified_count": len(self.verified_findings),
            "disproved_count": len(self.disproved_findings),
            "chains_count": len(self.chains),
            "beef_online": sum(1 for s in beef.sessions.values() if (time.time() - s.get("last_seen", 0)) < 12.0),
            "beef_total": len(beef.sessions),
            "oob_hits": sum(len(v) for v in oob.hits.values()),
            "report_path": self.last_report_path,
            "current_stage": self.current_stage,
            "stage_states": {r["key"]: r["state"] for r in stage_rows(self.completed_stages, self.current_stage)},
            "llm": llm.status_summary(),
        }

    def state_snapshot(self, since_seq: int = 0, public_hook_url: str | None = None) -> dict:
        telem = TELEMETRY.snapshot(since_seq=since_seq)
        agent_stats = telem["agents"].get(AGENT_HANDLE, {})
        return {
            "status": self.status_dict(),
            "telemetry": telem,
            "waf_mutex": PAYLOAD_MUTEX.stats(),
            "beef": get_beef_server().snapshot(public_hook_url=public_hook_url),
            "oob": get_oob_manager().snapshot(),
            "agent": {
                "handle": AGENT.handle,
                "role": AGENT.role,
                "color": AGENT.color,
                "bio": AGENT.bio,
                "stats": agent_stats,
            },
            "stages": stage_rows(self.completed_stages, self.current_stage),
            "verified": [f.to_dict() for f in self.verified_findings],
            "disproved": [f.to_dict() for f in self.disproved_findings],
            "raw": [f.to_dict() for f in self.raw_findings],
            "chains": self.chains,
            "pocs": self.pocs,
            "transcript": AGENT_BUS.transcript()[-160:],
        }

    # -- async dispatch --------------------------------------------------
    def submit_async(self, user_input: str, speaker_target: str | None = None) -> dict:
        """Dispatch a command on a background thread so the UI keeps streaming live events."""
        raw = (user_input or "").strip()
        if not raw:
            return {"queued": False, "status": self.status_dict()}

        job_info = {
            "command": "/key ****" if raw.lower().startswith("/key") else raw[:120],
            "started_at": round(time.time(), 3),
        }

        def _worker():
            self.running_job = job_info
            try:
                self.handle_message(raw, speaker_target=speaker_target)
            except Exception as exc:
                AGENT_BUS.say(f"Command `{job_info['command']}` failed: `{exc}`", kind="error")
            finally:
                self.running_job = None

        t = threading.Thread(target=_worker, daemon=True, name="WarRoomAsyncTurn")
        t.start()
        return {"queued": True, "job": job_info, "status": self.status_dict()}

    # -- stage execution -------------------------------------------------
    def _run_stage(self, action: str, arg: str = "") -> dict:
        if action == "lab":
            url = self.start_lab(enable_waf=("nowaf" not in arg.lower()))
            return {"action": "lab", "target": url}

        if action == "target":
            if not arg:
                return {"action": "target", "target": self.target}
            return {"action": "target", "target": self.set_target(arg)}

        if not self.target:
            AGENT_BUS.say("No target set. Run `/lab` or `/target <url>` first.", kind="warn")
            return {"error": "No target set yet. Run `/lab` or `/target <url>` first."}

        def _mark(stage_key: str):
            self.current_stage = stage_key
            self.completed_stages.add(stage_key)

        if action == "autopilot":
            res = run_autopilot(self.target, max_pages=25)
            self.surface = res["surface"]
            self.raw_findings = res["raw_findings"]
            self.verified_findings = res["verified"]
            self.disproved_findings = res["disproved"]
            self.chains = res["chains"]
            self.pocs = res["pocs"]
            self.last_report_path = res["report_path"]
            self.completed_stages = {s.key for s in STAGES}
            self.current_stage = ""
            return {"action": "autopilot", "summary": self.status_dict()}

        if action == "recon":
            self.surface = run_recon(self.target, max_pages=25)
            _mark("recon")
            return {"action": "recon", "surface": self.surface}

        if action == "hunt":
            self.raw_findings = run_hunter(self.target, surface=self.surface)
            _mark("hunt")
            return {"action": "hunt", "raw_count": len(self.raw_findings)}

        if action == "escalate":
            if not self.raw_findings:
                self.raw_findings = StoreOrHunt(self)
            waf_v = ((self.surface or {}).get("waf") or {}).get("waf") or "generic"
            self.raw_findings = run_escalator(self.target, self.raw_findings, waf_vendor=waf_v)
            _mark("escalate")
            return {"action": "escalate", "count": len(self.raw_findings)}

        if action == "verify":
            candidates = self.raw_findings or FindingStore(self.host_label).all()
            audit = run_critic(self.host_label, candidates)
            self.verified_findings = audit["verified"]
            self.disproved_findings = audit["disproved"]
            _mark("verify")
            return {"action": "verify", "summary": audit["summary"]}

        if action == "chains":
            with TELEMETRY.agent_scope(AGENT_HANDLE, task=f"Stage 5/{STAGE_COUNT} · Chains on {self.host_label}", target=self.target, tool="chain-builder", stage="chains"):
                AGENT_BUS.stage_started("chains", f"building chains for `{self.host_label}`", target=self.host_label)
                src = self.verified_findings or self.raw_findings
                self.chains = build_chains(self.host_label, src)
                AGENT_BUS.stage_done("chains", f"{len(self.chains)} chain(s) built.", target=self.host_label)
            _mark("chains")
            return {"action": "chains", "chains": self.chains}

        if action in ("report", "poc", "triage"):
            with TELEMETRY.agent_scope(AGENT_HANDLE, task=f"Stage 6/{STAGE_COUNT} · Report on {self.host_label}", target=self.target, tool="reporter", stage="report"):
                AGENT_BUS.stage_started("report", f"triage, PoCs and advisory for `{self.host_label}`", target=self.host_label)
                src = self.verified_findings or self.raw_findings
                triage_findings(self.host_label, src)
                self.pocs = generate_pocs(self.host_label, src)
                if not self.chains and src:
                    self.chains = build_chains(self.host_label, src)
                self.last_report_path = generate_report(
                    self.target,
                    verified_findings=src,
                    chains=self.chains,
                    pocs=self.pocs,
                    disproved=self.disproved_findings,
                    waf_info=(self.surface or {}).get("waf"),
                )
                AGENT_BUS.stage_done(
                    "report",
                    f"advisory and {len(self.pocs)} PoC(s) written to `{self.last_report_path}`.",
                    target=self.host_label,
                )
            _mark("report")
            return {"action": "report", "report_path": self.last_report_path, "pocs": len(self.pocs)}

        return {"action": action}

    # -- conversational reply --------------------------------------------
    def _reply(self, raw: str, llm) -> None:
        st = self.status_dict()

        if llm.available:
            recent = "\n".join(f"{m['speaker']}: {m['text']}" for m in AGENT_BUS.transcript()[-8:])
            sys_prompt = (
                f"{AGENT.system_prompt}\n"
                f"You run a {STAGE_COUNT}-stage pipeline: "
                + ", ".join(f"{s.index}.{s.label}" for s in STAGES)
                + ".\nAnswer the operator directly and concisely. Never claim a vulnerability is confirmed "
                "unless the verification stage proved it. Available commands: "
                + COMMANDS_HELP
                + f"\nCurrent engagement state:\n{json.dumps(st, indent=2)}\nRecent activity:\n{recent}"
            )
            allowed = tools_for_role("hunter") | tools_for_role("recon")
            if self.target and any(k in raw.lower() for k in ("run ", "probe ", "test ", "check ", "headers", "nikto", "nuclei")):
                with TELEMETRY.agent_scope(AGENT_HANDLE, task=f"Interactive tool loop: {raw[:60]}", target=self.target, tool="llm-tool-loop"):
                    loop_out = llm.run_tool_loop(sys_prompt, f"Operator says: {raw}", allowed_tools=allowed, max_steps=3)
                for line in loop_out.get("banter") or []:
                    AGENT_BUS.say(line, kind="info", target=self.host_label or None)
                if loop_out.get("final"):
                    AGENT_BUS.say(loop_out["final"], kind="info", target=self.host_label or None)
                return

            reply = llm.chat(
                [{"role": "system", "content": sys_prompt}, {"role": "user", "content": raw}],
                temperature=0.4,
                max_tokens=900,
            )
            if reply:
                AGENT_BUS.say(reply, kind="info", target=self.host_label or None)
                return

        # Deterministic fallback when no LLM is configured.
        stage_hint = (
            f"Stage {STAGE_BY_KEY[st['current_stage']].index}/{STAGE_COUNT} "
            f"({STAGE_BY_KEY[st['current_stage']].label}) is in progress."
            if st["current_stage"] in STAGE_BY_KEY
            else f"Pipeline stages {STAGE_COUNT}: " + " → ".join(s.label for s in STAGES) + "."
        )
        AGENT_BUS.say(
            f"Target=`{st['target'] or 'none'}` · Surface={st['surface_urls']} URLs · Leads={st['raw_count']} · "
            f"Verified={st['verified_count']} · Disproved={st['disproved_count']} · Chains={st['chains_count']}. "
            f"{stage_hint} Commands: {COMMANDS_HELP}",
            kind="info",
            target=self.host_label or None,
        )

    # -- message handling ------------------------------------------------
    def handle_message(self, user_input: str, speaker_target: str | None = None, console=None) -> dict:
        """Process slash commands, URLs or free-form messages for the single agent."""
        start_idx = len(AGENT_BUS.transcript())
        raw = (user_input or "").strip()
        if not raw:
            return {"new_messages": [], "status": self.status_dict()}

        safe_logged_text = raw
        if raw.lower().startswith("/key "):
            kparts = raw.split()
            safe_logged_text = f"/key {mask_secret(kparts[1])}" + (f" {' '.join(kparts[2:])}" if len(kparts) > 2 else "")

        with AGENT_BUS._lock:
            AGENT_BUS._messages.append({
                "ts": round(time.time(), 3),
                "speaker": "YOU",
                "role": "Operator",
                "stage": "",
                "stage_label": "",
                "kind": "operator",
                "text": safe_logged_text,
                "meta": {},
            })

        url_match = URL_RE.search(raw)
        if url_match and not raw.lower().startswith(("/target", "/key", "/provider")):
            extracted = url_match.group(0).rstrip(".,;)")
            if extracted != self.target:
                self.set_target(extracted)

        if raw.startswith("/"):
            parts = raw[1:].split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""

            if cmd in ("key", "apikey"):
                if not arg:
                    st_llm = get_llm().status_summary()
                    AGENT_BUS.say(
                        f"Active LLM: provider=`{st_llm['active_provider']}` | model=`{st_llm['active_model']}` | "
                        f"key=`{st_llm['api_key_masked']}` | base=`{st_llm['base_url']}`. "
                        "Usage: `/key <YOUR_API_KEY> [optional_model]`",
                        kind="info",
                    )
                else:
                    sub = arg.split()
                    info = configure_api_key(api_key=sub[0], model=sub[1] if len(sub) > 1 else None, persist=True)
                    st_llm = get_llm().status_summary()
                    AGENT_BUS.say(
                        f"LLM configured: provider=`{st_llm['active_provider']}` model=`{st_llm['active_model']}` "
                        f"key=`{info['key_masked']}` (saved to `~/.bugsBounty/config.json`).",
                        kind="info",
                    )
                return {"new_messages": AGENT_BUS.transcript()[start_idx:], "status": self.status_dict()}

            if cmd in ("provider", "model", "llm"):
                sub = arg.split()
                if sub:
                    configure_api_key(provider=sub[0], model=sub[1] if len(sub) > 1 else None, persist=True)
                st_llm = get_llm().status_summary()
                AGENT_BUS.say(
                    f"LLM switched: provider=`{st_llm['active_provider']}` model=`{st_llm['active_model']}` "
                    f"endpoint=`{st_llm['base_url']}` ready={st_llm['available']}.",
                    kind="info",
                )
                return {"new_messages": AGENT_BUS.transcript()[start_idx:], "status": self.status_dict()}

            alias = {
                "auto": "autopilot",
                "run": "autopilot",
                "pwn": "autopilot",
                "scan": "hunt",
                "audit": "verify",
                "critic": "verify",
                "validate": "verify",
            }.get(cmd, cmd)

            if alias in ("lab", "target", "autopilot", "recon", "hunt", "escalate", "verify", "chains", "report", "poc", "triage"):
                self._run_stage(alias, arg)
                return {"new_messages": AGENT_BUS.transcript()[start_idx:], "status": self.status_dict()}

            if alias in ("status", "findings"):
                st = self.status_dict()
                AGENT_BUS.say(
                    f"Target=`{st['target'] or 'none'}` · Surface={st['surface_urls']} URLs · Leads={st['raw_count']} · "
                    f"Verified={st['verified_count']} · Disproved={st['disproved_count']} · Chains={st['chains_count']} · "
                    f"BeEF online={st['beef_online']} · LLM=`{st['llm']['display_mode']}`",
                    kind="info",
                )
                return {"new_messages": AGENT_BUS.transcript()[start_idx:], "status": st}

            if alias == "tools":
                from tools.registry import ToolRegistry

                rows = ToolRegistry.audit()
                ready = sum(1 for r in rows if r.get("status") == "READY")
                AGENT_BUS.say(f"Arsenal: {ready}/{len(rows)} tools READY in `.bin/` and the built-in engines.", kind="info")
                return {"new_messages": AGENT_BUS.transcript()[start_idx:], "status": self.status_dict()}

            if alias in ("help", "commands"):
                AGENT_BUS.say(f"Commands: {COMMANDS_HELP}", kind="info")
                return {"new_messages": AGENT_BUS.transcript()[start_idx:], "status": self.status_dict()}

        low = raw.lower()

        # Natural-language stage intent
        if any(k in low for k in ("spin up lab", "start lab", "start target", "run lab", "demo target", "vuln lab")):
            self._run_stage("lab")
            return {"new_messages": AGENT_BUS.transcript()[start_idx:], "status": self.status_dict()}

        if any(k in low for k in ("full autopilot", "autopilot", "full send", "pwn everything", "run full", "run everything")):
            if not self.target:
                self._run_stage("lab")
            self._run_stage("autopilot")
            return {"new_messages": AGENT_BUS.transcript()[start_idx:], "status": self.status_dict()}

        ran_stage = False
        if self.target and any(k in low for k in ("recon", "subdomain", "crawl", "spider", "arjun", "map surface", "map endpoint")):
            self._run_stage("recon")
            ran_stage = True
        elif self.target and any(k in low for k in ("hunt", "scan", "fuzz", "attack", "probe", "test for bugs")):
            self._run_stage("hunt")
            ran_stage = True
        elif self.target and any(k in low for k in ("escalate", "sqlmap", "dalfox", "beef", "commix", "oob", "interactsh")):
            self._run_stage("escalate")
            ran_stage = True
        elif any(k in low for k in ("verify", "audit", "critic", "disprove", "validate", "false positive")) and (self.raw_findings or self.target):
            self._run_stage("verify")
            ran_stage = True
        elif (self.verified_findings or self.raw_findings) and any(k in low for k in ("chain", "build", "stitch", "pivot")):
            self._run_stage("chains")
            ran_stage = True
        elif (self.verified_findings or self.raw_findings) and any(k in low for k in ("report", "poc", "triage", "writeup")):
            self._run_stage("report")
            ran_stage = True

        if not ran_stage:
            self._reply(raw, get_llm())

        return {
            "new_messages": AGENT_BUS.transcript()[start_idx:],
            "status": self.status_dict(),
        }


def StoreOrHunt(session: WarRoomSession) -> list[Finding]:
    stored = FindingStore(session.host_label).all()
    if stored:
        return stored
    return run_hunter(session.target, surface=session.surface)


def run_interactive_warroom(target: str | None = None, auto_lab: bool = False):
    """Interactive terminal REPL (`#basement-ops`) for the single agent."""
    session = WarRoomSession(target=target)
    if auto_lab and not session.target:
        session.start_lab()

    llm_info = session.status_dict()["llm"]
    console.print(Panel.fit(
        f"[bold cyan]#basement-ops — bugsBounty single-agent console[/bold cyan]\n"
        f"Agent online: [{AGENT.color}][bold]{AGENT.handle}[/bold][/{AGENT.color}] — {AGENT.role}\n"
        f"Stages: " + " → ".join(f"[bold]{s.index}.{s.label}[/bold]" for s in STAGES) + "\n"
        f"LLM Backend: [bold]{llm_info['active_provider']}[/bold] (`{llm_info['active_model']}`, live={llm_info['available']})\n\n"
        "[dim]Talk to the agent naturally, drop a target URL, or use:\n"
        f"  {COMMANDS_HELP}[/dim]",
        border_style="cyan",
    ))

    while True:
        try:
            prompt_target = session.target or "no-target"
            line = console.input(f"\n[bold green]YOU[/bold green][dim]({prompt_target})[/dim]> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Leaving #basement-ops.[/dim]")
            break
        if not line:
            continue
        if line.lower() in ("/quit", "/exit", "quit", "exit"):
            console.print("[dim]Leaving #basement-ops.[/dim]")
            break
        prev = CFG.get("agent_streaming", True)
        CFG["agent_streaming"] = True
        try:
            session.handle_message(line)
        finally:
            CFG["agent_streaming"] = prev


def cli_entry():
    run_interactive_warroom()
