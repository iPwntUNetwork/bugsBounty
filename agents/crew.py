"""Rowdy 20-Year Veteran Hacker Crew Personas, Banter Bus & War-Room Transcript Engine.

6 distinct battle-scarred basement operators who have hacked together since the 2005 IRC days:
  - GHOST    (Recon & Attack Surface Cartographer)
  - BLITZ    (Active Vulnerability Hunter & WAF Breaker)
  - SWITCH   (Weaponized Tool Escalator: sqlmap, dalfox, BeEF, interactsh, commix)
  - RAZOR    (100% Deterministic Falsification Critic — NEVER detects, ONLY tears apart weak claims)
  - CHAINSAW (Exploit Chainer & Post-Exploitation Strategist)
  - FIXER    (CVSS Triager, PoC Packager & Bounty Report Writer)

Features:
  - Caffeinated war-room banter with profanity, reasoning handoffs, cheers on verified criticals,
    and Aussie "brown-eye" roasts whenever a sloppy false positive gets shredded by RAZOR.
  - Strictly deterministic default mode + optional LLM flavor augmentation (Groq OR Ollama).
  - Full thread-safe JSONL + in-memory transcript persisted per target scan.
"""
import hashlib
import json
import threading
import time
from dataclasses import dataclass
from rich.console import Console
from core.config import CFG
from core.memory import scan_dir, log_event

console = Console()


@dataclass(frozen=True)
class CrewMember:
    handle: str
    role: str
    color: str
    bio: str
    system_prompt: str


CREW: dict[str, CrewMember] = {
    "GHOST": CrewMember(
        handle="GHOST",
        role="Recon & Surface Cartographer",
        color="cyan",
        bio="Paranoid 22-year OSINT/DNS obsessive running on fourth espresso; maps every forgotten subdomain & hidden param.",
        system_prompt="You are GHOST, a caffeinated 20-year veteran recon hacker. Swear naturally, hand crisp targets to BLITZ, and call out lazy surface coverage.",
    ),
    "BLITZ": CrewMember(
        handle="BLITZ",
        role="Active Vuln Hunter & WAF Breaker",
        color="bright_red",
        bio="Trigger-happy payload maniac who lives to bypass Cloudflare/ModSec and toss juicy leads to SWITCH.",
        system_prompt="You are BLITZ, rowdy offensive vuln hunter of 20 years. Swear, brag when tamper scripts crack a WAF, and take roasts on the chin when RAZOR bins your false positives.",
    ),
    "SWITCH": CrewMember(
        handle="SWITCH",
        role="Weaponized Escalation Specialist",
        color="magenta",
        bio="Heavy-artillery operator wiring sqlmap, dalfox, BeEF hooks, commix & interactsh callbacks onto raw leads.",
        system_prompt="You are SWITCH, heavy-weapons exploit specialist. Turn BLITZ's raw anomalies into undeniable sqlmap dumps, BeEF hooks, and OOB callbacks.",
    ),
    "RAZOR": CrewMember(
        handle="RAZOR",
        role="Deterministic Falsification Critic",
        color="bright_yellow",
        bio="Zero-bullshit deterministic auditor. Never hunts; exists solely to falsify weak exploits and brown-eye sloppy teammates.",
        system_prompt="You are RAZOR, ruthless deterministic exploit critic. You NEVER trust hunters blindly — demand control baselines, negative probes, and hard proof or tell them to cop a brown-eye.",
    ),
    "CHAINSAW": CrewMember(
        handle="CHAINSAW",
        role="Attack-Chain Architect",
        color="green",
        bio="Turns medium exposures + bypasses into full P1 account-takeover and RCE chains.",
        system_prompt="You are CHAINSAW, 20-year red-team chain builder. Stitch RAZOR-verified bugs into devastating P1 kill chains.",
    ),
    "FIXER": CrewMember(
        handle="FIXER",
        role="Triage & Bounty Closer",
        color="bright_blue",
        bio="Turns chaos in the basement into air-tight CVSS v3.1 advisories and reproducible curl/python PoCs that force triage payout.",
        system_prompt="You are FIXER, veteran bug-bounty closer. Package verified exploits so cleanly triage has zero excuse to downgrade.",
    ),
}

CHEER_TEMPLATES = [
    "FUCK YES {target_handle}!! `{vuln}` on `{url}` (`{param}`) is 100% LEGIT — cracked open cold! Beers are on the bounty payout tonight boys!!",
    "GET IN THERE!! `{vuln}` at `{url}` survived every single control probe! {target_handle}, you magnificent caffeinated bastard, that's straight cash!",
    "BOOM! Dead-to-rights `{vuln}` on `{url}` (`{param}`)! Even RAZOR couldn't kill that exploit — absolute clinic crew!",
    "HOLY SHIT `{vuln}` CONFIRMED on `{url}`!! Twenty years in the trenches and watching a clean exploit pop NEVER gets old!!",
]

BROWNEYE_TEMPLATES = [
    "Oi {target_handle}, pull your head in — your '{vuln}' on `{url}` is a deadset mirage ({reason}). Pressing a bare arse against the glass: cop that brown-eye out the window and bring me real exploitation next round!",
    "WHAT A CROCK OF SHIT, {target_handle}! '{vuln}' at `{url}` folded on the very first control probe ({reason}). Full moon brown-eye salute across the war-room — back to kindergarten fuzzing!",
    "Binned! `{vuln}` on `{url}` failed deterministic falsification ({reason}). {target_handle} owes the whole crew espressos AND cops a proper Aussie brown-eye for wasting RAZOR's cycles!",
    "Nah yeah nah {target_handle}, that `{vuln}` claim on `{url}` is pure static reflection garbage ({reason}). Dropped trousers brown-eye from RAZOR — go find something that actually executes!",
]


def _pick_deterministic(templates: list[str], seed: str) -> str:
    idx = int(hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()[:8], 16) % len(templates)
    return templates[idx]


class CrewBus:
    """Thread-safe crew communication bus supporting banter, handoffs, cheers, and brown-eye roasts."""

    def __init__(self):
        self._lock = threading.Lock()
        self._messages: list[dict] = []

    def reset(self):
        with self._lock:
            self._messages.clear()

    def say(
        self,
        speaker: str,
        text: str,
        kind: str = "banter",
        to: str | None = None,
        target: str | None = None,
        meta: dict | None = None,
    ) -> dict:
        member = CREW.get(speaker.upper(), CREW["BLITZ"])
        entry = {
            "ts": round(time.time(), 3),
            "speaker": member.handle,
            "role": member.role,
            "to": to,
            "kind": kind,
            "text": text,
            "meta": meta or {},
        }
        with self._lock:
            self._messages.append(entry)

        if target:
            log_event(target, f"crew_{kind}", entry)

        if CFG.get("crew_banter", True):
            tag_icon = {
                "cheer": "[bold green][CHEER][/bold green]",
                "browneye": "[bold red][BROWNEYE][/bold red]",
                "handoff": "[bold magenta][HANDOFF][/bold magenta]",
                "waf": "[bold yellow][WAF-WAR][/bold yellow]",
                "audit": "[bold bright_yellow][CRITIC][/bold bright_yellow]",
            }.get(kind, "[dim][CREW][/dim]")
            arrow = f" -> [bold]{to}[/bold]" if to else ""
            console.print(f"  {tag_icon} [{member.color}][bold]{member.handle}[/bold][/{member.color}]{arrow}: {text}")
        return entry

    def handoff(self, sender: str, receiver: str, summary: str, target: str | None = None, meta: dict | None = None) -> dict:
        return self.say(sender, summary, kind="handoff", to=receiver, target=target, meta=meta)

    def cheer(self, speaker: str, target_handle: str, vuln: str, url: str, param: str = "", target: str | None = None) -> dict:
        msg = _pick_deterministic(CHEER_TEMPLATES, f"{speaker}:{target_handle}:{vuln}:{url}:{param}").format(
            target_handle=target_handle, vuln=vuln, url=url, param=param or "endpoint"
        )
        return self.say(speaker, msg, kind="cheer", to=target_handle, target=target, meta={"vuln": vuln, "url": url})

    def browneye(self, speaker: str, target_handle: str, vuln: str, url: str, reason: str, target: str | None = None) -> dict:
        msg = _pick_deterministic(BROWNEYE_TEMPLATES, f"{speaker}:{target_handle}:{vuln}:{url}:{reason}").format(
            target_handle=target_handle, vuln=vuln, url=url, reason=reason
        )
        return self.say(
            speaker, msg, kind="browneye", to=target_handle, target=target,
            meta={"vuln": vuln, "url": url, "reason": reason},
        )

    def transcript(self) -> list[dict]:
        with self._lock:
            return list(self._messages)

    def save(self, target: str) -> str:
        sd = scan_dir(target)
        out = sd / "crew_transcript.json"
        out.write_text(json.dumps(self.transcript(), indent=2))
        return str(out)


CREW_BUS = CrewBus()
