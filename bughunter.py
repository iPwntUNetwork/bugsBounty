#!/usr/bin/env python3
"""bugsBounty CLI (`bughunter.py`) — Full Offensive Toolkit, `.bin/` Arsenal, Crew & LLM Orchestrator."""
import json
import pathlib
import sys
import typer
from rich.console import Console
from rich.table import Table

from core.config import CFG
from core.findings import Finding, FindingStore
from core.llm import get_llm

app = typer.Typer(
    name="bugsBounty",
    help="Autonomous 6-Agent Offensive Security, Bug Bounty, Red Team & CTF Framework (.bin/ Arsenal + Groq/Ollama)",
    no_args_is_help=True,
)
console = Console()


@app.callback()
def main_callback(
    provider: str = typer.Option(None, "--provider", help="LLM provider: 'groq' or 'ollama'"),
    ollama_model: str = typer.Option(None, "--ollama-model", help="Local Ollama model name (e.g. llama3.1:8b)"),
    ollama_url: str = typer.Option(None, "--ollama-url", help="Ollama base URL (default http://127.0.0.1:11434)"),
    rate: float = typer.Option(None, "--rate", help="Max HTTP requests/sec"),
    proxy: str = typer.Option(None, "--proxy", help="HTTP/SOCKS proxy URL"),
    stealth: bool = typer.Option(True, "--stealth/--no-stealth", help="Enable browser TLS/UA stealth rotation"),
    banter: bool = typer.Option(True, "--banter/--no-banter", help="Enable 20-year hacker crew war-room banter"),
):
    if provider:
        CFG["llm_provider"] = provider.lower()
    if ollama_model:
        CFG["ollama_model"] = ollama_model
    if ollama_url:
        CFG["ollama_base_url"] = ollama_url
    if rate is not None:
        CFG["rate_limit"] = rate
    if proxy:
        CFG["proxy"] = proxy
    CFG["stealth"] = stealth
    CFG["crew_banter"] = banter


@app.command("tools")
def cmd_tools(json_out: bool = typer.Option(False, "--json", help="Emit JSON inventory")):
    """Verify & display status of all compiled `.bin/` binaries and built-in C2/OOB engines."""
    from tools.registry import ToolRegistry

    rows = ToolRegistry.audit()
    if json_out:
        console.print_json(json.dumps(rows, indent=2))
        return
    tbl = Table(title="bugsBounty `.bin/` & Internal Offensive Arsenal")
    tbl.add_column("Tool", style="cyan", no_wrap=True)
    tbl.add_column("Category", style="magenta")
    tbl.add_column("Source", style="green")
    tbl.add_column("Status", style="bold")
    tbl.add_column("Version / Probe Output")
    for r in rows:
        st = "[green]READY[/green]" if r["status"] == "READY" else "[red]MISSING[/red]"
        tbl.add_row(r["name"], r["category"], r["source"], st, (r["version"] or "")[:70])
    console.print(tbl)


@app.command("crew")
def cmd_crew():
    """Display the 6 veteran war-room crew personas and strict Separation of Duties rules."""
    from agents.crew import CREW

    tbl = Table(title="bugsBounty 20-Year War-Room Crew")
    tbl.add_column("Handle", style="bold")
    tbl.add_column("Role", style="cyan")
    tbl.add_column("Bio")
    for handle, m in CREW.items():
        tbl.add_row(f"[{m.color}]{handle}[/{m.color}]", m.role, m.bio)
    console.print(tbl)


@app.command("ollama")
def cmd_ollama(model: str = typer.Option(None, "--model", help="Optional model to quick-test")):
    """Inspect local Ollama daemon availability & installed models."""
    llm = get_llm(provider="ollama", model=model)
    models = llm.list_ollama_models()
    console.print(f"[bold cyan]Ollama URL:[/bold cyan] {llm.ollama_url}")
    console.print(f"[bold cyan]Reachable:[/bold cyan]  {llm.available}")
    console.print(f"[bold cyan]Models:[/bold cyan]     {models}")


@app.command("autopilot")
def cmd_autopilot(
    target: str = typer.Argument(..., help="Target URL or domain"),
    max_pages: int = typer.Option(35, "--max-pages"),
    out: str = typer.Option(None, "--out", "-o", help="Markdown report path"),
):
    """Run full 6-agent pipeline (`GHOST -> BLITZ -> SWITCH -> RAZOR -> CHAINSAW -> FIXER`)."""
    from agents.autopilot import run_autopilot

    res = run_autopilot(target, max_pages=max_pages, report_out=out)
    console.print(
        f"\n[bold green]Autopilot Complete![/bold green] Verified={len(res['verified'])} | "
        f"Disproved={len(res['disproved'])} | Chains={len(res['chains'])} | Report={res['report_path']}"
    )


@app.command("recon")
def cmd_recon(target: str = typer.Argument(..., help="Target domain or URL")):
    """Run `GHOST` recon pipeline (`subfinder`, `assetfinder`, `dnsx`, `httpx`, `wafw00f`, `katana`, `arjun`, `ffuf`, `gobuster`, `gau`, `waybackurls`, `paramspider`)."""
    from agents.recon_agent import run_recon

    surface = run_recon(target)
    console.print_json(json.dumps({
        "target": surface["target"],
        "waf": surface["waf"],
        "urls": len(surface["urls"]),
        "param_urls": surface["param_urls"],
        "locked_urls": surface["locked_urls"],
    }, indent=2))


@app.command("hunt")
def cmd_hunt(target: str = typer.Argument(..., help="Target URL")):
    """Run `BLITZ` active vulnerability hunter with WAF mutex tamper evasion."""
    from agents.hunter import run_hunter

    findings = run_hunter(target)
    console.print(f"[bold green]BLITZ found {len(findings)} raw leads.[/bold green]")


@app.command("escalate")
def cmd_escalate(target: str = typer.Argument(..., help="Target host label or URL")):
    """Run `SWITCH` tool handoffs (`sqlmap`, `dalfox` + BeEF hook, `commix`, `interactsh`/OOB) on stored findings."""
    import urllib.parse
    from agents.escalator import run_escalator

    host = urllib.parse.urlparse(target if "://" in target else f"http://{target}").netloc or target
    store = FindingStore(host)
    updated = run_escalator(target, store.all())
    for f in updated:
        store.add(f)
    console.print(f"[bold magenta]SWITCH escalated {len(updated)} findings.[/bold magenta]")


@app.command("critic")
@app.command("validate")
def cmd_critic(target: str = typer.Argument(..., help="Target host label or URL")):
    """Run `RAZOR` 100% deterministic falsification audit (strict Separation of Duties)."""
    import urllib.parse
    from agents.critic import run_critic

    host = urllib.parse.urlparse(target if "://" in target else f"http://{target}").netloc or target
    store = FindingStore(host)
    res = run_critic(host, store.all())
    console.print_json(json.dumps(res["summary"], indent=2))


@app.command("scan")
def cmd_scan(
    module: str = typer.Argument(..., help="Scanner module inside `scan/` (e.g. sqli, xss, ssrf, cmdi, waf, bypass_403, mitb)"),
    url: str = typer.Argument(..., help="Target URL"),
):
    """Run any individual scanner module inside `scan/`."""
    import importlib

    mod = importlib.import_module(f"scan.{module}")
    fn = getattr(mod, "scan_url", None) or getattr(mod, "detect_waf", None) or getattr(mod, "scan_base", None)
    res = fn(url)
    payload = [x.to_dict() if hasattr(x, "to_dict") else x for x in res] if isinstance(res, list) else res
    console.print_json(json.dumps(payload, indent=2))


@app.command("beef")
def cmd_beef(url: str = typer.Argument(..., help="Target XSS URL"), param: str = typer.Option("", "--param", "-p")):
    """Stage live BeEF-like browser hook C2 payload against an XSS endpoint."""
    from tools.beef import handoff_xss_to_beef

    res = handoff_xss_to_beef(url, param=param)
    console.print_json(json.dumps(res, indent=2))


@app.command("chains")
def cmd_chains(target: str = typer.Argument(..., help="Target host label or URL")):
    """Build multi-step exploit chains (`CHAINSAW`) from findings."""
    import urllib.parse
    from chains.builder import build_chains

    host = urllib.parse.urlparse(target if "://" in target else f"http://{target}").netloc or target
    store = FindingStore(host)
    chains = build_chains(host, store.all())
    console.print_json(json.dumps(chains, indent=2))


@app.command("triage")
def cmd_triage(target: str = typer.Argument(..., help="Target host label or URL")):
    """Score stored findings with CVSS v3.1 (`FIXER`)."""
    import urllib.parse
    from agents.triage import triage_findings

    host = urllib.parse.urlparse(target if "://" in target else f"http://{target}").netloc or target
    store = FindingStore(host)
    triaged = triage_findings(host, store.all())
    console.print_json(json.dumps(triaged, indent=2))


@app.command("poc")
def cmd_poc(target: str = typer.Argument(..., help="Target host label or URL")):
    """Generate curl/Python/tool PoCs (`FIXER`)."""
    import urllib.parse
    from agents.poc_generator import generate_pocs

    host = urllib.parse.urlparse(target if "://" in target else f"http://{target}").netloc or target
    store = FindingStore(host)
    pocs = generate_pocs(host, store.all())
    console.print_json(json.dumps(pocs, indent=2))


@app.command("report")
def cmd_report(target: str = typer.Argument(..., help="Target host label or URL"), out: str = typer.Option(None, "--out", "-o")):
    """Generate final Markdown vulnerability advisory (`FIXER`)."""
    import urllib.parse
    from agents.reporter import generate_report
    from chains.builder import build_chains
    from agents.poc_generator import generate_pocs

    host = urllib.parse.urlparse(target if "://" in target else f"http://{target}").netloc or target
    store = FindingStore(host)
    verified = [f for f in store.all() if f.verified] or store.all()
    chains = build_chains(host, verified)
    pocs = generate_pocs(host, verified)
    path = generate_report(target, verified_findings=verified, chains=chains, pocs=pocs, out_path=out)
    console.print(f"[bold green]Report written to {path}[/bold green]")


def main():
    app()


if __name__ == "__main__":
    main()
