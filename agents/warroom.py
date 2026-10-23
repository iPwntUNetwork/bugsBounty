"""Interactive 6-Agent War-Room Session (`#basement-ops`).

Powers:
  1. Group Chat & Multi-Agent Crew Banter (`@CREW` multi-speaker back-and-forth + `@ghost`/`@blitz`/`@switch`/`@razor`/`@chainsaw`/`@fixer`)
  2. Async Live Background Execution (`submit_async`) so Web UI streams live `.bin/`, HTTP, WAF & crew events in real time
  3. Live BeEF C2 + OOB Callback + `PAYLOAD_MUTEX` + Per-Agent `TELEMETRY` Unified State Snapshot
  4. Strict **Separation of Duties** (`RAZOR` NEVER runs detection scans even in interactive chat)
"""
import hashlib
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
    "GHOST": "Four espressos deep and `.bin/subfinder` + `katana` + `arjun` are warm. Drop a target URL (or `/lab`) and I'll map every last hidden param.",
    "BLITZ": "Point me at an endpoint mate — `PAYLOAD_MUTEX` is cocked with 24 polymorphic tampers and rotating browser UAs ready to rip.",
    "SWITCH": "Got `.bin/sqlmap`, `.bin/dalfox`, live `BeefServer` (`hook.js`), `.bin/commix`, and `Interactsh` OOB hot on standby!",
    "RAZOR": "Listen closely: I don't hunt and I don't guess. Have BLITZ & SWITCH bag claims first — then I'll hit every one with deterministic controls and brown-eye anything fake.",
    "CHAINSAW": "Once RAZOR stamps bugs verified, pass 'em over and I'll stitch 403 bypasses, `.env` keys, and BeEF hooks into P1 kill chains.",
    "FIXER": "Standing by to score CVSS v3.1, build one-liner `curl` + Python repro scripts, and ship clean advisories.",
}

GROUP_BANTER_PACKS = [
    [
        ("GHOST", "BLITZ", "Four double-shots deep and `.bin/` is purring ({urls} surface URLs mapped on `{target}`). Try reading my recon notes before spraying blind payloads this time, BLITZ."),
        ("BLITZ", "GHOST", "Oi get stuffed GHOST — my `PAYLOAD_MUTEX` already tracked {waf_wins} WAF bypass wins on `{waf}`. Hand me one parameter and watch me crack it wide open!"),
        ("RAZOR", "BLITZ", "Yeah yeah hero — last time you bragged like that I binned {binned} false positives and gave you a full pressed-ham brown-eye across `#basement-ops`. Bring hard proof or cop another one!"),
        ("SWITCH", "CREW", "Settle down ladies — `BeefServer` has {hooks} zombie browser(s) on standby and `.bin/sqlmap` + `Interactsh` are armed. Say `/autopilot` boss and we send the whole kitchen sink!"),
    ],
    [
        ("BLITZ", "SWITCH", "Red Bull number five boys!! `{target}` looks ripe — who wants first crack at SQLi and reflected XSS?"),
        ("SWITCH", "BLITZ", "You pop the reflection, I'll drop `hook.js` straight onto their admin session and run DOM loot extraction from the BeEF tab before their SOC blinks."),
        ("CHAINSAW", "FIXER", "And the second RAZOR certifies {verified} real bugs, I'm chaining `.env` creds + 403 bypass + XSS hook straight into P1 Critical."),
        ("FIXER", "CREW", "Keep it clean crew — verified hits currently sit at **{verified}** ({chains} kill chains). Ready whenever you give the word, boss!"),
    ],
    [
        ("RAZOR", "CREW", "Status check from the adult table: **{verified} hard-verified exploits**, **{binned} garbage mirages binned**, zero LLM hallucinations tolerated."),
        ("GHOST", "RAZOR", "Oi admit it RAZOR, those hidden params `.bin/arjun` dug up on `{target}` were pure gold."),
        ("BLITZ", "RAZOR", "Even RAZOR cracked a smile when `xss_tag_polymorph` danced right past `{waf}`! What's our next move, boss?"),
    ],
]

URL_RE = re.compile(r"https?://[^\s<>'\"]+")


class WarRoomSession:
    """Stateful war-room controller shared by Terminal REPL, one-shot CLI, and `#basement-ops` Web Console."""

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
        TELEMETRY.emit("agent", f"Active target locked -> {self.target}", agent="GHOST", level="info")
        CREW_BUS.say(
            "GHOST",
            f"Locked active target on the war-room board -> `{self.target}`. Ready when you give the word, boss!",
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
        TELEMETRY.emit("agent", f"VulnCorp Target Lab online at {url} (WAF={'ON' if enable_waf else 'OFF'})", agent="GHOST", level="success")
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
            "llm": llm.status_summary(),
        }

    def state_snapshot(self, since_seq: int = 0, public_hook_url: str | None = None) -> dict:
        telem = TELEMETRY.snapshot(since_seq=since_seq)
        agent_stats = telem["agents"]
        return {
            "status": self.status_dict(),
            "telemetry": telem,
            "waf_mutex": PAYLOAD_MUTEX.stats(),
            "beef": get_beef_server().snapshot(public_hook_url=public_hook_url),
            "oob": get_oob_manager().snapshot(),
            "crew": [
                {
                    "handle": m.handle,
                    "role": m.role,
                    "color": m.color,
                    "bio": m.bio,
                    "stats": agent_stats.get(m.handle, {}),
                }
                for m in CREW.values()
            ],
            "verified": [f.to_dict() for f in self.verified_findings],
            "disproved": [f.to_dict() for f in self.disproved_findings],
            "raw": [f.to_dict() for f in self.raw_findings],
            "chains": self.chains,
            "pocs": self.pocs,
            "transcript": CREW_BUS.transcript()[-160:],
        }

    def submit_async(self, user_input: str, speaker_target: str | None = None) -> dict:
        """Dispatch command/chat on a background thread so UI streams live telemetry & crew banter in real time."""
        raw = (user_input or "").strip()
        if not raw:
            return {"queued": False, "status": self.status_dict()}

        job_info = {
            "command": "/key ****" if raw.lower().startswith("/key") else raw[:120],
            "speaker": speaker_target or "CREW",
            "started_at": round(time.time(), 3),
        }

        def _worker():
            self.running_job = job_info
            try:
                self.handle_message(raw, speaker_target=speaker_target)
            except Exception as exc:
                CREW_BUS.say("FIXER", f"Hit a snag running `{job_info['command']}`: `{exc}`", kind="browneye")
            finally:
                self.running_job = None

        t = threading.Thread(target=_worker, daemon=True, name="WarRoomAsyncTurn")
        t.start()
        return {"queued": True, "job": job_info, "status": self.status_dict()}

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
                "Oi boss — give us a target URL first (`/target http://host` or click **Launch Target Lab**)!",
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
            with TELEMETRY.agent_scope("CHAINSAW", task=f"Building attack chains for {self.host_label}", target=self.target, tool="chain-builder"):
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
            with TELEMETRY.agent_scope("FIXER", task=f"Generating CVSS triage, PoCs & report for {self.host_label}", target=self.target, tool="reporter"):
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

    def _emit_group_banter(self, raw: str, addressed: str, llm) -> None:
        st = self.status_dict()
        mutex_stats = PAYLOAD_MUTEX.stats()
        waf_wins = sum(len(v) for v in (mutex_stats.get("winning_tampers") or {}).values())

        if llm.available:
            recent_chat = "\n".join(f"{m['speaker']}: {m['text']}" for m in CREW_BUS.transcript()[-10:])
            context_summary = json.dumps(st, indent=2)
            if not addressed:
                group_prompt = (
                    "You direct the 6-hacker war-room `#basement-ops` crew who have hacked together for 20+ years: "
                    "GHOST (caffeinated recon obsessive), BLITZ (trigger-happy WAF breaker), SWITCH (sqlmap/dalfox/BeEF heavy weapons), "
                    "RAZOR (ruthless zero-BS deterministic critic who roasts/brown-eyes false positives), "
                    "CHAINSAW (P1 kill-chain architect), FIXER (CVSS & bounty report closer).\n"
                    "Return JSON `{\"turns\": [{\"speaker\": \"HANDLE\", \"to\": \"HANDLE_OR_YOU\", \"kind\": \"banter|cheer|audit\", \"text\": \"...\"}]}` "
                    "with 3 lively, witty, technical, profanity-friendly war-room replies where crew members answer the human operator ('YOU') "
                    "AND banter/chirp at each other using the live war-room stats.\n"
                    f"Live War-Room Stats:\n{context_summary}\nRecent Chat:\n{recent_chat}"
                )
                res = llm.json(
                    [{"role": "system", "content": group_prompt}, {"role": "user", "content": raw}],
                    temperature=0.55,
                    max_tokens=1400,
                )
                turns = (res or {}).get("turns") if isinstance(res, dict) else None
                if isinstance(turns, list) and turns:
                    for item in turns[:4]:
                        sp = str(item.get("speaker", "GHOST")).upper()
                        if sp not in CREW:
                            sp = "GHOST"
                        txt = str(item.get("text") or "").strip()
                        if txt:
                            CREW_BUS.say(sp, txt, kind=str(item.get("kind") or "banter"), to=item.get("to") or None, target=self.host_label or None)
                    return

            chosen = addressed if addressed in CREW else _pick_speaker_for_topic(raw.lower())
            member = CREW[chosen]
            role_key = ROLE_KEY_MAP.get(chosen)
            allowed = tools_for_role(role_key) if role_key else {}
            sys_prompt = (
                f"{member.system_prompt}\n"
                "You have known GHOST, BLITZ, SWITCH, RAZOR, CHAINSAW, and FIXER for 20+ years in `#basement-ops`. "
                "Keep replies sharp, technical, caffeinated, and fun.\n"
                f"Live War-Room Stats:\n{context_summary}\nRecent Chat:\n{recent_chat}"
            )
            if allowed and self.target and any(k in raw.lower() for k in ("run ", "probe ", "test ", "check ", "headers", "nikto", "nuclei")):
                with TELEMETRY.agent_scope(chosen, task=f"Interactive tool loop: {raw[:60]}", target=self.target, tool="llm-tool-loop"):
                    loop_out = llm.run_tool_loop(sys_prompt, f"Operator says: {raw}", allowed_tools=allowed, max_steps=3)
                for b in loop_out.get("banter") or []:
                    CREW_BUS.say(chosen, b, kind="banter", target=self.host_label or None)
                if loop_out.get("final"):
                    CREW_BUS.say(chosen, loop_out["final"], kind="banter", target=self.host_label or None)
                return

            reply = llm.chat(
                [{"role": "system", "content": sys_prompt}, {"role": "user", "content": raw}],
                temperature=0.5,
                max_tokens=900,
            )
            if reply:
                CREW_BUS.say(chosen, reply, kind="banter", target=self.host_label or None)
                return

        # Deterministic multi-speaker banter (instant zero-key fallback!)
        if addressed and addressed in CREW:
            CREW_BUS.say(
                addressed,
                f"{OFFLINE_GREETINGS[addressed]} (Target=`{st['target'] or 'none'}` | Verified={st['verified_count']} | Binned={st['disproved_count']})",
                kind="banter",
            )
            foil = "RAZOR" if addressed != "RAZOR" else "BLITZ"
            CREW_BUS.say(
                foil,
                "Oi keep it moving — either fire a scan or pour another round of espressos!" if foil == "BLITZ"
                else "And anything that isn't backed by a clean control diff goes straight in the bin.",
                kind="audit" if foil == "RAZOR" else "banter",
                to=addressed,
            )
            return

        pack_idx = int(hashlib.sha256(f"{raw}:{len(CREW_BUS.transcript())}".encode()).hexdigest()[:6], 16) % len(GROUP_BANTER_PACKS)
        fmt_vars = {
            "target": st["target"] or "no-target-yet (click Launch Target Lab!)",
            "urls": st["surface_urls"],
            "waf": st["waf"] or "edge WAF",
            "waf_wins": waf_wins,
            "verified": st["verified_count"],
            "binned": st["disproved_count"],
            "hooks": st["beef_online"],
            "chains": st["chains_count"],
        }
        for sp, to_h, tmpl in GROUP_BANTER_PACKS[pack_idx]:
            CREW_BUS.say(
                sp,
                tmpl.format(**fmt_vars),
                kind="audit" if sp == "RAZOR" else "banter",
                to=to_h,
                target=self.host_label or None,
            )

    def handle_message(self, user_input: str, speaker_target: str | None = None, console=None) -> dict:
        """Process slash commands, `@handle` mentions, OR free-form group banter."""
        start_idx = len(CREW_BUS.transcript())
        raw = (user_input or "").strip()
        if not raw:
            return {"new_messages": [], "status": self.status_dict()}

        safe_logged_text = raw
        if raw.lower().startswith("/key "):
            kparts = raw.split()
            safe_logged_text = f"/key {mask_secret(kparts[1])}" + (f" {' '.join(kparts[2:])}" if len(kparts) > 2 else "")

        with CREW_BUS._lock:
            CREW_BUS._messages.append({
                "ts": round(time.time(), 3),
                "speaker": "YOU",
                "role": "Crew Lead / Operator",
                "to": (speaker_target or "CREW").upper(),
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
                return {"new_messages": CREW_BUS.transcript()[start_idx:], "status": self.status_dict()}

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
                return {"new_messages": CREW_BUS.transcript()[start_idx:], "status": self.status_dict()}

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
                return {"new_messages": CREW_BUS.transcript()[start_idx:], "status": self.status_dict()}
            if alias in ("status", "findings", "tools", "crew", "help"):
                st = self.status_dict()
                CREW_BUS.say(
                    "FIXER",
                    f"Status check -> Target=`{st['target'] or 'none'}` | Surface={st['surface_urls']} URLs | "
                    f"Raw={st['raw_count']} | Verified={st['verified_count']} | Binned={st['disproved_count']} | "
                    f"BeEF Online={st['beef_online']} | Chains={st['chains_count']} | LLM=`{st['llm']['display_mode']}`",
                    kind="banter",
                )
                return {"new_messages": CREW_BUS.transcript()[start_idx:], "status": st}

        addressed = (speaker_target or "").strip().upper()
        m_mention = re.match(r"^@([A-Za-z]+)\b\s*(.*)$", raw)
        body = raw
        if m_mention and m_mention.group(1).upper() in CREW:
            addressed = m_mention.group(1).upper()
            body = m_mention.group(2).strip() or raw

        low = body.lower()

        # STRICT SEPARATION OF DUTIES EVEN IN INTERACTIVE CHAT:
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

        if any(k in low for k in ("spin up lab", "start lab", "start target", "run lab", "demo target", "vuln lab")):
            self._run_action("lab")
        if any(k in low for k in ("full autopilot", "autopilot", "full send", "pwn everything", "tear it apart", "run full")):
            if not self.target:
                self._run_action("lab")
            self._run_action("autopilot")
            return {"new_messages": CREW_BUS.transcript()[start_idx:], "status": self.status_dict()}

        ran_pipeline_step = False
        if self.target and any(k in low for k in ("recon", "subdomain", "crawl", "spider", "arjun", "map surface", "map endpoint")):
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
        elif addressed == "CHAINSAW" and (self.verified_findings or self.raw_findings) and any(k in low for k in ("chain", "build", "stitch", "escalat", "pivot")):
            self._run_action("chains")
            ran_pipeline_step = True
        elif addressed == "FIXER" and (self.verified_findings or self.raw_findings) and any(k in low for k in ("report", "poc", "triage", "writeup")):
            self._run_action("report")
            ran_pipeline_step = True

        if not ran_pipeline_step:
            self._emit_group_banter(raw, addressed, get_llm())

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
        "  `/lab` | `/target <url>` | `/key <GROQ_KEY>` | `/autopilot` | `/recon` | `/hunt` | `/escalate` | `/critic` | `/chains` | `/report` | `/status` | `/quit`[/dim]",
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
        prev = CFG.get("crew_banter", True)
        CFG["crew_banter"] = True
        try:
            session.handle_message(line)
        finally:
            CFG["crew_banter"] = prev


def cli_entry():
    run_interactive_warroom()
