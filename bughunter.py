#!/usr/bin/env python3
"""bugsBounty CLI (`bughunter.py`) — Single-agent offensive toolkit, `.bin/` arsenal & target lab."""
import json
import time
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import CFG, CONFIG_FILE, configure_api_key
from core.findings import FindingStore
from core.llm import get_llm

app = typer.Typer(
    name="bugsBounty",
    help="Autonomous single-agent Offensive Security, Bug Bounty, Red Team & CTF Framework (Groq qwen/qwen3.8-27b + Ollama + .bin/ Arsenal)",
    no_args_is_help=True,
)
console = Console()


@app.callback()
def main_callback(
    provider: str = typer.Option(None, "--provider", help="LLM provider: 'groq' (default https://api.groq.com/openai/v1), 'ollama', 'openai', or 'xai'"),
    api_key: str = typer.Option(None, "--api-key", "-k", help="API key (defaults to Groq `https://api.groq.com/openai/v1`, model `qwen/qwen3.8-27b`)"),
    model: str = typer.Option(None, "--model", help="LLM model name (default on Groq: `qwen/qwen3.8-27b`)"),
    base_url: str = typer.Option(None, "--base-url", help="Custom OpenAI-compatible API base URL"),
    ollama_model: str = typer.Option(None, "--ollama-model", help="Local Ollama model name (e.g. llama3.1:8b)"),
    ollama_url: str = typer.Option(None, "--ollama-url", help="Ollama base URL (default http://127.0.0.1:11434)"),
    rate: float = typer.Option(None, "--rate", help="Max HTTP requests/sec"),
    proxy: str = typer.Option(None, "--proxy", help="HTTP/SOCKS proxy URL"),
    stealth: bool = typer.Option(True, "--stealth/--no-stealth", help="Enable browser TLS/UA stealth rotation"),
    stream: bool = typer.Option(True, "--stream/--no-stream", help="Stream live agent stage updates to the console"),
):
    if api_key or provider or model or base_url:
        configure_api_key(api_key=api_key, provider=provider, model=model, base_url=base_url, persist=False)
    if ollama_model:
        CFG["ollama_model"] = ollama_model
    if ollama_url:
        CFG["ollama_base_url"] = ollama_url
    if rate is not None:
        CFG["rate_limit"] = rate
    if proxy:
        CFG["proxy"] = proxy
    CFG["stealth"] = stealth
    CFG["agent_streaming"] = stream


@app.command("auth")
def cmd_auth(
    api_key: str = typer.Argument(None, help="Your Groq API key (`gsk_...` -> https://api.groq.com/openai/v1, default model `qwen/qwen3.8-27b`)"),
    provider: str = typer.Option(None, "--provider", "-p", help="Explicit provider override (`groq`, `ollama`, `openai`, `xai`)"),
    model: str = typer.Option(None, "--model", "-m", help="Default model (Groq default: `qwen/qwen3.8-27b`)"),
    base_url: str = typer.Option(None, "--base-url", help="Optional custom OpenAI-compatible base URL"),
    test: bool = typer.Option(False, "--test", help="Send a live test ping to verify your API key right now"),
):
    """Save your Groq API key (`https://api.groq.com/openai/v1`, default `qwen/qwen3.8-27b`) securely to `~/.bugsBounty/config.json`."""
    if api_key or provider or model or base_url:
        configure_api_key(api_key=api_key, provider=provider, model=model, base_url=base_url, persist=True)

    llm = get_llm()
    st = llm.status_summary()
    console.print(Panel.fit(
        f"[bold green]LLM Configuration Ready[/bold green]\n\n"
        f"  [cyan]Provider:[/cyan]    [bold]{st['active_provider']}[/bold]\n"
        f"  [cyan]Model:[/cyan]       {st['active_model']}\n"
        f"  [cyan]Endpoint:[/cyan]    {st['base_url']}\n"
        f"  [cyan]API Key:[/cyan]     {st['api_key_masked']}\n"
        f"  [cyan]Saved To:[/cyan]    {CONFIG_FILE} (mode 0600)",
        title="bugsBounty AI Auth",
        border_style="cyan",
    ))
    if test:
        res = llm.ping()
        if res["ok"]:
            console.print(f"[bold green][✓] Live API Ping Succeeded[/bold green] ({res['latency_ms']} ms): `{res['reply']}`")
        else:
            console.print(f"[bold red][✗] Live API Ping Failed:[/bold red] {res.get('error')}")
            raise typer.Exit(code=1)


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


@app.command("agent")
def cmd_agent(
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Enter the interactive `#basement-ops` agent console"),
    message: str = typer.Option(None, "--message", "-m", help="Send a single message/command to the agent"),
    target: str = typer.Option(None, "--target", "-t", help="Optional target URL for the agent"),
    lab: bool = typer.Option(False, "--lab", help="Automatically spin up the built-in vulnerable target lab"),
):
    """Inspect the single agent, or talk to it (`-i` interactive REPL or `-m` one-shot message)."""
    from agents.agent import AGENT
    from agents.warroom import WarRoomSession, run_interactive_warroom

    if interactive or (lab and not message):
        run_interactive_warroom(target=target, auto_lab=lab)
        return
    if message:
        sess = WarRoomSession(target=target)
        try:
            if lab and not sess.target:
                sess.start_lab()
            sess.handle_message(message)
        finally:
            if sess.lab_server:
                sess.lab_server.stop()
        return

    st = sess_stub()
    tbl = Table(title="bugsBounty Agent (`python bughunter.py warroom` to interact live!)")
    tbl.add_column("#", style="cyan", no_wrap=True)
    tbl.add_column("Stage", style="bold")
    tbl.add_column("What the agent does")
    tbl.add_column("Primary tooling")
    for s in st:
        tbl.add_row(str(s["index"]), s["label"], s["task"], s["tool"])
    console.print(Panel.fit(
        f"[bold cyan]{AGENT.handle}[/bold cyan] — {AGENT.role}\n{AGENT.bio}",
        border_style="cyan",
    ))
    console.print(tbl)


def sess_stub():
    from agents.agent import STAGES

    return [{"index": s.index, "label": s.label, "task": s.task, "tool": s.tool} for s in STAGES]


@app.command("warroom")
def cmd_warroom(
    target: str = typer.Argument(None, help="Optional target URL (or pass `--lab` to spin up built-in target)"),
    lab: bool = typer.Option(False, "--lab", help="Automatically start built-in vulnerable target lab"),
):
    """Drop into the live interactive `#basement-ops` agent console."""
    from agents.warroom import run_interactive_warroom

    run_interactive_warroom(target=target, auto_lab=lab)


@app.command("ui")
def cmd_ui(
    host: str = typer.Option("0.0.0.0", "--host", help="Bind address"),
    port: int = typer.Option(8787, "--port", "-p", help="HTTP port for Web War-Room"),
    target: str = typer.Option(None, "--target", "-t", help="Optional initial target URL"),
    lab: bool = typer.Option(False, "--lab", help="Auto-start local vulnerable target lab"),
    auth_user: str = typer.Option("admin", "--auth-user", help="HTTP Basic Auth username (default: admin)"),
    auth_pass: str = typer.Option("bugsBounty", "--auth-pass", help="HTTP Basic Auth password (default: bugsBounty)"),
    no_auth: bool = typer.Option(False, "--no-auth", help="Disable HTTP Basic Auth protection"),
):
    """Launch the `#basement-ops` Web Command Center (default Basic Auth: `admin:bugsBounty`)."""
    from web.warroom_ui import start_warroom_server

    start_warroom_server(
        host=host,
        port=port,
        target=target,
        auto_lab=lab,
        block=True,
        auth_user=auth_user,
        auth_pass=auth_pass,
        require_auth=not no_auth,
    )


@app.command("lab")
def cmd_lab(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host for vulnerable target server"),
    port: int = typer.Option(8080, "--port", "-p", help="Bind port (0 for random free port)"),
    waf: bool = typer.Option(True, "--waf/--no-waf", help="Enable simulated Cloudflare WAF"),
):
    """Start the built-in safe Vulnerable Target Lab (`VulnCorp Portal`) so you can test scans & the agent live."""
    from http.server import ThreadingHTTPServer
    from tests.vuln_server import VulnLabServer

    srv = VulnLabServer(enable_waf=waf)
    srv.start()
    if (host, port) != ("127.0.0.1", 0):
        handler_cls = srv._server.RequestHandlerClass
        srv.stop()
        ThreadingHTTPServer.allow_reuse_address = True
        srv._server = ThreadingHTTPServer((host, port), handler_cls)
        srv.port = srv._server.server_address[1]
        import threading
        srv._thread = threading.Thread(target=srv._server.serve_forever, daemon=True)
        srv._thread.start()

    target_url = f"http://{host}:{srv.port}"
    console.print(Panel.fit(
        f"[bold green]VulnCorp Target Lab LIVE at {target_url}[/bold green] (Cloudflare WAF={'ON' if waf else 'OFF'})\n\n"
        "[cyan]Genuine Exploitable Endpoints:[/cyan]\n"
        f"  • {target_url}/product?id=1          (SQLite Boolean/UNION SQLi)\n"
        f"  • {target_url}/search?q=router       (Reflected XSS — WAF blocks <script>)\n"
        f"  • {target_url}/webhook?callback=...  (Real SSRF callback)\n"
        f"  • {target_url}/diag?host=127.0.0.1   (Command Injection)\n"
        f"  • {target_url}/download?file=doc.txt (Path Traversal /etc/passwd)\n"
        f"  • {target_url}/render?tpl=welcome    (SSTI algebraic evaluation)\n"
        f"  • {target_url}/admin                 (403 Edge ACL Bypass)\n"
        f"  • {target_url}/.env                  (Exposed Secrets)\n\n"
        "[yellow]Now run in another terminal:[/yellow]\n"
        f"  ./.venv/bin/python bughunter.py autopilot {target_url}\n"
        f"  ./.venv/bin/python bughunter.py warroom {target_url}",
        border_style="green",
    ))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()


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
    """Run the full single-agent pipeline (recon -> hunt -> escalate -> verify -> chains -> report)."""
    from agents.autopilot import run_autopilot

    res = run_autopilot(target, max_pages=max_pages, report_out=out)
    console.print(
        f"\n[bold green]Autopilot Complete![/bold green] Verified={len(res['verified'])} | "
        f"Disproved={len(res['disproved'])} | Chains={len(res['chains'])} | Report={res['report_path']}"
    )


@app.command("recon")
def cmd_recon(target: str = typer.Argument(..., help="Target domain or URL")):
    """Run agent stage 1 — recon pipeline (`subfinder`, `assetfinder`, `dnsx`, `httpx`, `wafw00f`, `katana`, `arjun`, `ffuf`, `gobuster`, `gau`, `waybackurls`, `paramspider`)."""
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
    """Run agent stage 2 — active vulnerability hunting with WAF mutex tamper evasion."""
    from agents.hunter import run_hunter

    findings = run_hunter(target)
    console.print(f"[bold green]Agent found {len(findings)} raw leads.[/bold green]")


@app.command("escalate")
def cmd_escalate(target: str = typer.Argument(..., help="Target host label or URL")):
    """Run agent stage 3 — heavy-tool escalation (`sqlmap`, `dalfox` + BeEF hook, `commix`, `interactsh`/OOB) on stored findings."""
    import urllib.parse
    from agents.escalator import run_escalator

    host = urllib.parse.urlparse(target if "://" in target else f"http://{target}").netloc or target
    store = FindingStore(host)
    updated = run_escalator(target, store.all())
    for f in updated:
        store.add(f)
    console.print(f"[bold magenta]Agent escalated {len(updated)} findings.[/bold magenta]")


@app.command("critic")
@app.command("validate")
@app.command("verify")
def cmd_critic(target: str = typer.Argument(..., help="Target host label or URL")):
    """Run agent stage 4 — 100% deterministic verification (no self-certification)."""
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
    """Run agent stage 5 — build multi-step exploit chains from verified findings."""
    import urllib.parse
    from chains.builder import build_chains

    host = urllib.parse.urlparse(target if "://" in target else f"http://{target}").netloc or target
    store = FindingStore(host)
    chains = build_chains(host, store.all())
    console.print_json(json.dumps(chains, indent=2))


@app.command("triage")
def cmd_triage(target: str = typer.Argument(..., help="Target host label or URL")):
    """Run agent stage 6 — score stored findings with CVSS v3.1."""
    import urllib.parse
    from agents.triage import triage_findings

    host = urllib.parse.urlparse(target if "://" in target else f"http://{target}").netloc or target
    store = FindingStore(host)
    triaged = triage_findings(host, store.all())
    console.print_json(json.dumps(triaged, indent=2))


@app.command("poc")
def cmd_poc(target: str = typer.Argument(..., help="Target host label or URL")):
    """Generate curl/Python/tool PoCs."""
    import urllib.parse
    from agents.poc_generator import generate_pocs

    host = urllib.parse.urlparse(target if "://" in target else f"http://{target}").netloc or target
    store = FindingStore(host)
    pocs = generate_pocs(host, store.all())
    console.print_json(json.dumps(pocs, indent=2))


@app.command("report")
def cmd_report(target: str = typer.Argument(..., help="Target host label or URL"), out: str = typer.Option(None, "--out", "-o")):
    """Generate the final Markdown vulnerability advisory."""
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
