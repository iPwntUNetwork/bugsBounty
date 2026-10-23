"""Interactive 6-Agent War-Room Session (`#basement-ops`).

Lets the operator talk directly to the crew (`GHOST`, `BLITZ`, `SWITCH`, `RAZOR`, `CHAINSAW`, `FIXER`)
via CLI REPL (`python bughunter.py warroom`), single-shot CLI (`python bughunter.py crew -m "..."`),
or the live Web War-Room UI (`python bughunter.py ui`).

Works seamlessly BOTH:
  - With local **Ollama** (`--provider ollama`) or **Groq** (`GROQ_API_KEY`) LLM reasoning & live tool execution
  - With **zero API keys / offline deterministic mode** (intent router + real `.bin/` execution + authentic crew banter)
while strictly preserving **Separation of Duties** (`RAZOR` NEVER runs detection scans).
"""
import json
import re
import threading
import urllib.parse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import CFG, configure_api_key, mask_secret
from core.findings import Finding, FindingStore
from core.llm import get_llm
from tools.registry import ToolRegistry, tools_for_role
from agents.crew import CREW, CREW_BUS
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

ROLE_KEY_MAP = {
    "GHOST": "recon",
    "BLITZ": "hunter",
    "SWITCH": "escalator",
    "CHAINSAW": "chainsaw",
}

OFFLINE_GREETINGS = {
    "GHOST": "Four espressos deep and `.bin/subfinder` + `katana` + `arjun` are warm. Drop a target URL (or `/lab` to spin up the local VulnCorp lab) and I'll map every last parameter.",
    "BLITZ": "Point me at an endpoint mate — `PAYLOAD_MUTEX` is loaded with 24 WAF tampers and fresh browser UAs ready to rip.",
    "SWITCH": "Got `.bin/sqlmap`, `.bin/dalfox`, live `BeefServer` (`hook.js`), `.bin/commix`, and `Interactsh` OOB standing by. Give BLITZ a target first or hand me raw leads!",
    "RAZOR": "Listen closely: I don't hunt and I don't guess. Have BLITZ & SWITCH bag some claims first — then I'll hit every single one with benign controls and brown-eye anything fake.",
    "CHAINSAW": "Once RAZOR stamps a bug verified, bring it here and I'll stitch exposures, 403 bypasses, and XSS hooks into full P1 kill chains.",
    "FIXER": "Standing by to score CVSS v3.1, build curl/Python repro scripts, and write clean markdown reports once we have verified hits.",
}

URL_RE = re.compile(r"https?://[^\s<>'\"]+")


class WarRoomSession:
    """Stateful war-room controller shared by Terminal REPL, one-shot CLI, and Web UI."""

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
        if target:
            self.set_target(target)

    @property
    def host_label(self) -> str:
        if not self.target:
            return ""
        return urllib.parse.urlparse(self.target).netloc or self.target

    def set_target(self, url_or_host: str) -> str:
        u = url_or_host.strip()
        if u and "://" not in u:
            u = f"http://{u}"
        self.target = u
        CREW_BUS.say(
            "GHOST",
            f"Locked active target on board -> `{self.target}`. Ready when you give the word, boss!",
            kind="banter",
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
        CREW_BUS.say(
            "GHOST",
            f"Spun up local VulnCorp target lab at `{url}` (Cloudflare WAF={'ON' if enable_waf else 'OFF'}, "
            "SQLite SQLi `/product?id=1`, XSS `/search?q=x`, SSRF `/webhook`, CMDi `/diag`, `/admin` 403 gate, `/.env` + 6 RAZOR traps)!",
            kind="cheer",
            to="BLITZ",
            target=self.host_label,
        )
        return url

    def status_dict(self) -> dict:
        llm = get_llm()
        return {
            "target": self.target,
            "lab_running": self.lab_server is not None,
            "lab_url": self.lab_server.base_url if self.lab_server else None,
            "surface_urls": len((self.surface or {}).get("urls") or []),
            "param_urls": len((self.surface or {}).get("param_urls") or []),
            "waf": ((self.surface or {}).get("waf") or {}).get("waf"),
            "raw_count": len(self.raw_findings),
            "verified_count": len(self.verified_findings),
            "disproved_count": len(self.disproved_findings),
            "chains_count": len(self.chains),
            "report_path": self.last_report_path,
            "llm": llm.status_summary(),
        }

    def state_snapshot(self) -> dict:
        return {
            "status": self.status_dict(),
            "crew": [
                {"handle": m.handle, "role": m.role, "color": m.color, "bio": m.bio}
                for m in CREW.values()
            ],
            "verified": [f.to_dict() for f in self.verified_findings],
            "disproved": [f.to_dict() for f in self.disproved_findings],
            "raw": [f.to_dict() for f in self.raw_findings],
            "chains": self.chains,
            "pocs": self.pocs,
            "transcript": CREW_BUS.transcript()[-120:],
        }

    def _run_action(self, action: str, arg: str = "") -> dict:
        if action == "lab":
            url = self.start_lab(enable_waf=("nowaf" not in arg.lower()))
            return {"action": "lab", "target": url}

        if action == "target":
            if not arg:
                return {"action": "target", "target": self.target}
            return {"action": "target", "target": self.set_target(arg)}

        if not self.target:
            CREW_BUS.say(
                "BLITZ",
                "Oi boss — give us a target URL first (`/target http://host` or `/lab` to boot the local vulnerable target)!",
                kind="banter",
            )
            return {"error": "No target set yet. Run `/lab` or `/target <url>` first."}

        if action == "autopilot":
            res = run_autopilot(self.target, max_pages=25)
            self.surface = res["surface"]
            self.raw_findings = res["raw_findings"]
            self.verified_findings = res["verified"]
            self.disproved_findings = res["disproved"]
            self.chains = res["chains"]
            self.pocs = res["pocs"]
            self.last_report_path = res["report_path"]
            return {"action": "autopilot", "summary": self.status_dict()}

        if action == "recon":
            self.surface = run_recon(self.target, max_pages=25)
            return {"action": "recon", "surface": self.surface}

        if action == "hunt":
            self.raw_findings = run_hunter(self.target, surface=self.surface)
            return {"action": "hunt", "raw_count": len(self.raw_findings)}

        if action == "escalate":
            if not self.raw_findings:
                self.raw_findings = StoreOrHunt(self)
            waf_v = ((self.surface or {}).get("waf") or {}).get("waf") or "generic"
            self.raw_findings = run_escalator(self.target, self.raw_findings, waf_vendor=waf_v)
            return {"action": "escalate", "count": len(self.raw_findings)}

        if action == "critic":
            candidates = self.raw_findings or FindingStore(self.host_label).all()
            audit = run_critic(self.host_label, candidates)
            self.verified_findings = audit["verified"]
            self.disproved_findings = audit["disproved"]
            return {"action": "critic", "summary": audit["summary"]}

        if action == "chains":
            src = self.verified_findings or self.raw_findings
            self.chains = build_chains(self.host_label, src)
            CREW_BUS.say(
                "CHAINSAW",
                f"Built {len(self.chains)} multi-step kill chain(s) for `{self.host_label}`!",
                kind="cheer" if self.chains else "banter",
                to="FIXER",
                target=self.host_label,
            )
            return {"action": "chains", "chains": self.chains}

        if action in ("report", "poc", "triage"):
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
            CREW_BUS.say(
                "FIXER",
                f"Fresh bounty advisory + {len(self.pocs)} PoC(s) written to `{self.last_report_path}`!",
                kind="cheer",
                target=self.host_label,
            )
            return {"action": "report", "report_path": self.last_report_path, "pocs": len(self.pocs)}

        return {"action": action}

    def handle_message(self, user_input: str, speaker_target: str | None = None) -> dict:
        """Process slash commands, `@handle` mentions, OR free-form conversation with full crew banter."""
        start_idx = len(CREW_BUS.transcript())
        raw = (user_input or "").strip()
        if not raw:
            return {"new_messages": [], "status": self.status_dict()}

        # Mask secret API keys before recording operator's line in the war-room log!
        safe_logged_text = raw
        if raw.lower().startswith("/key "):
            kparts = raw.split()
            safe_logged_text = f"/key {mask_secret(kparts[1])}" + (f" {' '.join(kparts[2:])}" if len(kparts) > 2 else "")

        # Record operator's own line in the war-room log
        CREW_BUS.MessagesAppendOperator = None
        with CREW_BUS._lock:
            CREW_BUS._messages.append({
                "ts": round(__import__("time").time(), 3),
                "speaker": "YOU",
                "role": "Crew Lead / Operator",
                "to": (speaker_target or "CREW").upper(),
                "kind": "operator",
                "text": safe_logged_text,
                "meta": {},
            })

        # Auto-extract any inline URL in the user's message and bind it as active target!
        url_match = URL_RE.search(raw)
        if url_match and not raw.lower().startswith(("/target", "/key", "/provider")):
            extracted = url_match.group(0).rstrip(".,;)")
            if extracted != self.target:
                self.set_target(extracted)

        # 1. Explicit slash commands (`/key`, `/provider`, `/lab`, `/target`, `/recon`, `/hunt`, `/escalate`, `/critic`, `/autopilot`, `/report`)
        if raw.startswith("/"):
            parts = raw[1:].split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""
            if cmd in ("key", "apikey"):
                if not arg:
                    st_llm = get_llm().status_summary()
                    CREW_BUS.say(
                        "FIXER",
                        f"Active LLM -> provider=`{st_llm['active_provider']}` | model=`{st_llm['active_model']}` | "
                        f"key=`{st_llm['api_key_masked']}` | base=`{st_llm['base_url']}`. Usage: `/key <YOUR_API_KEY> [optional_model]`",
                        kind="banter",
                    )
                else:
                    sub = arg.split()
                    info = configure_api_key(api_key=sub[0], model=sub[1] if len(sub) > 1 else None, persist=True)
                    st_llm = get_llm().status_summary()
                    CREW_BUS.say(
                        "GHOST",
                        f"Boom — wired `{st_llm['active_provider'].upper()}` (`{st_llm['active_model']}`, key `{info['key_masked']}`) "
                        f"and saved securely to `~/.bugsBounty/config.json`! Crew live brain is ONLINE.",
                        kind="cheer",
                        to="CREW",
                    )
                return {
                    "new_messages": CREW_BUS.transcript()[start_idx:],
                    "status": self.status_dict(),
                }
            if cmd in ("provider", "model", "llm"):
                sub = arg.split()
                if sub:
                    configure_api_key(provider=sub[0], model=sub[1] if len(sub) > 1 else None, persist=True)
                st_llm = get_llm().status_summary()
                CREW_BUS.say(
                    "FIXER",
                    f"Switched LLM -> provider=`{st_llm['active_provider']}` | model=`{st_llm['active_model']}` | "
                    f"endpoint=`{st_llm['base_url']}` | ready={st_llm['available']}.",
                    kind="cheer" if st_llm["available"] else "banter",
                )
                return {
                    "new_messages": CREW_BUS.transcript()[start_idx:],
                    "status": self.status_dict(),
                }
            alias = {
                "auto": "autopilot",
                "run": "autopilot",
                "pwn": "autopilot",
                "scan": "hunt",
                "audit": "critic",
                "validate": "critic",
            }.get(cmd, cmd)
            if alias in ("lab", "target", "autopilot", "recon", "hunt", "escalate", "critic", "chains", "report", "poc", "triage"):
                self._run_action(alias, arg)
                return {
                    "new_messages": CREW_BUS.transcript()[start_idx:],
                    "status": self.status_dict(),
                }
            if alias in ("status", "findings", "tools", "crew", "help"):
                st = self.status_dict()
                CREW_BUS.say(
                    "FIXER",
                    f"Status check -> Target=`{st['target'] or 'none'}` | Surface={st['surface_urls']} URLs | "
                    f"Raw={st['raw_count']} | Verified={st['verified_count']} | Binned={st['disproved_count']} | "
                    f"Chains={st['chains_count']} | LLM=`{st['llm']['active_provider']}` (reachable={st['llm']['available']})",
                    kind="banter",
                )
                return {
                    "new_messages": CREW_BUS.transcript()[start_idx:],
                    "status": st,
                }

        # 2. Detect addressed crew handle (`@ghost`, `@blitz`, `@switch`, `@razor`, `@chainsaw`, `@fixer`, or whole room)
        addressed = (speaker_target or "").strip().upper()
        m_mention = re.match(r"^@([A-Za-z]+)\b\s*(.*)$", raw)
        body = raw
        if m_mention and m_mention.group(1).upper() in CREW:
            addressed = m_mention.group(1).upper()
            body = m_mention.group(2).strip() or raw

        low = body.lower()

        # STRICT SEPARATION OF DUTIES EVEN IN INTERACTIVE CHAT:
        # If user asks RAZOR to scan/hunt directly before detection, RAZOR refuses to detect & tags BLITZ!
        if addressed == "RAZOR" and any(w in low for w in ("scan", "hunt", "fuzz", "find bug", "exploit")) and not any(w in low for w in ("audit", "critic", "verify", "disprove", "check")):
            CREW_BUS.say(
                "RAZOR",
                "Oi! Separation of Duties, remember?! I NEVER run detection scanners — if the critic also hunts, "
                "you get confirmation-bias garbage. BLITZ, get off your arse and hunt it first; I'll tear apart whatever you bring back!",
                kind="audit",
                to="BLITZ",
            )
            if self.target:
                self._run_action("hunt")
                self._run_action("critic")
            return {"new_messages": CREW_BUS.transcript()[start_idx:], "status": self.status_dict()}

        # Natural-language action triggers (works BOTH with AND without an LLM!)
        if any(k in low for k in ("spin up lab", "start lab", "start target", "run lab", "demo target", "vuln lab")):
            self._run_action("lab")
        if any(k in low for k in ("full autopilot", "autopilot", "full send", "pwn everything", "tear it apart", "run full")):
            if not self.target:
                self._run_action("lab")
            self._run_action("autopilot")
            return {"new_messages": CREW_BUS.transcript()[start_idx:], "status": self.status_dict()}

        ran_pipeline_step = False
        if addressed == "GHOST" or any(k in low for k in ("recon", "subdomain", "crawl", "spider", "arjun", "map surface")):
            if self.target:
                self._run_action("recon")
                ran_pipeline_step = True
        elif addressed == "BLITZ" and self.target and any(k in low for k in ("hunt", "scan", "fuzz", "waf", "attack", "hit", "probe")):
            self._run_action("hunt")
            ran_pipeline_step = True
        elif addressed == "SWITCH" and self.target and any(k in low for k in ("escalate", "sqlmap", "dalfox", "beef", "commix", "oob", "interactsh")):
            self._run_action("escalate")
            ran_pipeline_step = True
        elif (addressed == "RAZOR" or any(k in low for k in ("audit", "critic", "disprove", "validate"))) and (self.raw_findings or self.target):
            self._run_action("critic")
            ran_pipeline_step = True
        elif addressed == "CHAINSAW" and (self.verified_findings or self.raw_findings):
            self._run_action("chains")
            ran_pipeline_step = True
        elif addressed == "FIXER" and (self.verified_findings or self.raw_findings) and any(k in low for k in ("report", "poc", "triage", "writeup")):
            self._run_action("report")
            ran_pipeline_step = True

        # 3. Live LLM Multi-Persona Reasoning & Tool Execution (Groq OR Local Ollama!)
        llm = get_llm()
        chosen_handle = addressed if addressed in CREW else _pick_speaker_for_topic(low)
        member = CREW[chosen_handle]

        if llm.available:
            role_key = ROLE_KEY_MAP.get(chosen_handle)
            allowed = tools_for_role(role_key) if role_key else {}
            context_summary = json.dumps(self.status_dict(), indent=2)
            recent_chat = "\n".join(
                f"{m['speaker']}: {m['text']}" for m in CREW_BUS.transcript()[-8:]
            )
            sys_prompt = (
                f"{member.system_prompt}\n"
                "You have known GHOST, BLITZ, SWITCH, RAZOR, CHAINSAW, and FIXER for 20+ years in basement CTF/bounty war-rooms. "
                "Keep replies punchy, technical, caffeinated, profanity-friendly, and directly helpful to the human Crew Lead ('YOU').\n"
                f"Current War-Room State:\n{context_summary}\n"
                f"Recent War-Room Chat:\n{recent_chat}"
            )
            if allowed and not ran_pipeline_step and self.target:
                loop_out = llm.run_tool_loop(
                    sys_prompt,
                    f"Operator says: {raw}",
                    allowed_tools=allowed,
                    max_steps=3,
                )
                for b in loop_out.get("banter") or []:
                    CREW_BUS.say(chosen_handle, b, kind="banter", target=self.host_label or None)
                if loop_out.get("final"):
                    CREW_BUS.say(chosen_handle, loop_out["final"], kind="banter", target=self.host_label or None)
            else:
                reply = llm.chat([
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": raw},
                ], temperature=0.45, max_tokens=450)
                if reply:
                    CREW_BUS.say(chosen_handle, reply, kind="banter", target=self.host_label or None)

                # Have a second teammate chime in with quick banter if whole CREW was addressed!
                if not addressed:
                    sidekick = "RAZOR" if chosen_handle != "RAZOR" else "BLITZ"
                    chime = llm.chat([
                        {"role": "system", "content": CREW[sidekick].system_prompt + " Give a 1-sentence snappy reaction to your teammate."},
                        {"role": "user", "content": f"Operator asked: {raw}\n{chosen_handle} replied: {reply}"},
                    ], temperature=0.5, max_tokens=140)
                    if chime:
                        CREW_BUS.say(sidekick, chime, kind="banter", to=chosen_handle, target=self.host_label or None)
        elif not ran_pipeline_step:
            # Deterministic zero-LLM crew banter response when neither Ollama nor Groq key is configured yet!
            base_line = OFFLINE_GREETINGS[chosen_handle]
            hint = (
                f" (Active target: `{self.target}` — type `/autopilot` to unleash all 6 of us, or run Ollama locally with `--provider ollama` for free-form LLM banter!)"
                if self.target
                else " (Tip: type `/lab` to boot the built-in vulnerable target right now, `/target <url>` for your own box, or pass `--provider ollama --ollama-model llama3.1:8b`!)"
            )
            CREW_BUS.say(chosen_handle, base_line + hint, kind="banter")
            if not addressed:
                CREW_BUS.say(
                    "RAZOR",
                    "And remember: whatever BLITZ drags in gets hit with cold, deterministic control probes before it touches a report!",
                    kind="audit",
                    to=chosen_handle,
                )

        return {
            "new_messages": CREW_BUS.transcript()[start_idx:],
            "status": self.status_dict(),
        }


def StoreOrHunt(session: WarRoomSession) -> list[Finding]:
    stored = FindingStore(session.host_label).all()
    if stored:
        return stored
    return run_hunter(session.target, surface=session.surface)


def _pick_speaker_for_topic(low: str) -> str:
    if any(w in low for w in ("subfinder", "katana", "recon", "surface", "dns", "arjun", "map")):
        return "GHOST"
    if any(w in low for w in ("sqlmap", "dalfox", "beef", "hook", "commix", "interactsh", "escalat")):
        return "SWITCH"
    if any(w in low for w in ("critic", "false positive", "prove", "verify", "brown", "audit")):
        return "RAZOR"
    if any(w in low for w in ("chain", "pivot", "ato", "rce")):
        return "CHAINSAW"
    if any(w in low for w in ("report", "cvss", "bounty", "triage", "poc")):
        return "FIXER"
    return "BLITZ" if any(w in low for w in ("waf", "tamper", "sqli", "xss", "fuzz", "scan", "payload")) else "GHOST"


def run_interactive_warroom(target: str | None = None, auto_lab: bool = False):
    """Interactive terminal REPL (`#basement-ops`) where you talk live with the 6-agent crew."""
    session = WarRoomSession(target=target)
    if auto_lab and not session.target:
        session.start_lab()

    llm_info = session.status_dict()["llm"]
    console.print(Panel.fit(
        "[bold cyan]#basement-ops — bugsBounty 6-Agent Interactive War-Room[/bold cyan]\n"
        "Crew online: [cyan]GHOST[/cyan] | [bright_red]BLITZ[/bright_red] | [magenta]SWITCH[/magenta] | "
        "[bright_yellow]RAZOR[/bright_yellow] | [green]CHAINSAW[/green] | [bright_blue]FIXER[/bright_blue]\n"
        f"LLM Backend: [bold]{llm_info['active_provider']}[/bold] (`{llm_info['active_model']}`, live={llm_info['available']})\n\n"
        "[dim]Talk naturally, `@mention` any hacker (`@ghost`, `@blitz`, `@switch`, `@razor`, `@chainsaw`, `@fixer`), or use:\n"
        "  `/lab` (spawn local VulnCorp target) | `/target <url>` | `/autopilot` | `/recon` | `/hunt` | `/escalate` | `/critic` | `/chains` | `/report` | `/status` | `/quit`[/dim]",
        border_style="bright_magenta",
    ))

    while True:
        try:
            prompt_target = session.target or "no-target"
            line = console.input(f"\n[bold green]YOU[/bold green][dim]({prompt_target})[/dim]> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Leaving #basement-ops — catch ya next bounty run![/dim]")
            break
        if not line:
            continue
        if line.lower() in ("/quit", "/exit", "quit", "exit"):
            console.print("[dim]Leaving #basement-ops — catch ya next bounty run![/dim]")
            break
        # Enable live Rich output during terminal REPL
        prev = CFG.get("crew_banter", True)
        CFG["crew_banter"] = True
        try:
            session.handle_message(line)
        finally:
            CFG["crew_banter"] = prev


def cli_entry():
    run_interactive_warroom()
