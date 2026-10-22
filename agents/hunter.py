"""Hunter agent: runs vulnerability scanners across recon data (parallel swarm)."""
from core.findings import Finding
from core.memory import log_event, scan_dir
from agents.swarm import run_scanners_parallel
import json

def run(recon_result, use_llm_plan=True):
    domain = recon_result["domain"]
    sd = scan_dir(domain)
    all_findings = []
    hosts = recon_result.get("hosts", [])
    crawled = recon_result.get("crawled", {})

    tasks = []

    # files/headers/cors on root hosts
    from scan.files import scan_base as files_scan
    from scan.headers import scan_url as headers_scan
    from scan.cors import scan_url as cors_scan
    from scan.takeover import scan_hosts
    for h in hosts[:10]:
        tasks.append((files_scan, (h["url"],), None))
        tasks.append((headers_scan, (h["url"],), None))
        tasks.append((cors_scan, (h["url"],), None))
    tasks.append((scan_hosts, ([h["host"] for h in hosts],), None))

    # crawl-derived
    urls_to_scan = set()
    forms_all = []
    for w in recon_result.get("wayback", [])[:15]:
        urls_to_scan.add(w)
    for d in recon_result.get("dirbust", []):
        urls_to_scan.add(d.get("url"))
    for url, c in crawled.items():
        if isinstance(c, dict) and "error" not in c:
            for p in c.get("pages", []):
                urls_to_scan.add(p)
            for e in c.get("endpoints", []):
                urls_to_scan.add(e)
            forms_all.extend(c.get("forms", []))
    urls_to_scan = list(urls_to_scan)[:25]

    from scan.xss import scan_url as xss_scan, scan_forms as xss_forms
    from scan.sqli import scan_url as sqli_scan
    from scan.ssti import scan_url as ssti_scan
    from scan.ssrf import scan_url as ssrf_scan
    from scan.traversal import scan_url as trav_scan
    from scan.redirect import scan_url as redir_scan
    from scan.cmdi import scan_url as cmdi_scan
    from scan.jwt import scan_url as jwt_scan
    from scan.graphql import scan_base as gql_scan
    from scan.nosqli import scan_url as nosqli_scan
    from scan.smuggling import scan_url as smuggle_scan
    from scan.cache_poison import scan_url as cache_scan
    from scan.host_header import scan_url as hosthdr_scan
    from scan.crlf import scan_url as crlf_scan
    from scan.proto_pollution import scan_url as proto_scan
    from scan.xxe import scan_url as xxe_scan
    from scan.deser import scan_url as deser_scan
    from scan.mass_assign import scan_url as mass_scan
    from scan.race import scan_url as race_scan
    from scan.idor import scan_url as idor_scan
    from scan.jwt_deep import scan_url as jwtdeep_scan
    from scan.ai_llm import scan_base as ai_scan
    from scan.waf import scan_url as waf_scan
    from scan.ssti_advanced import scan_url as sstiadv_scan
    from scan.hijack import scan_url as hijack_scan
    from scan.upload import scan_url as upload_scan
    from scan.oauth import scan_url as oauth_scan
    from scan.websocket import scan_url as ws_scan
    from scan.mitb import scan_url as mitb_scan
    from scan.xss_advanced import scan_url as xssadv_scan
    from scan.injection_advanced import scan_url as injadv_scan
    from scan.ssrf_advanced import scan_url as ssrfadv_scan
    from scan.client_side import scan_url as clientside_scan
    from scan.file_polyglot import scan_url as polyglot_scan
    from scan.img_metadata import scan_url as imgmeta_scan
    from scan.archive_attacks import scan_url as archive_scan
    from scan.xml_attacks import scan_url as xmladv_scan
    from cloud.aws_deep import scan_base as awsdeep_scan
    from cicd.github_actions import scan_repo as cicd_scan
    from templates.engine import run_dir as template_scan
    from scan.soap import scan_url as soap_scan
    from scan.grpc import scan_base as grpc_scan
    from scan.mfa_bypass import scan_base as mfa_scan
    from scan.oauth_advanced import scan_url as oauthadv_scan
    from scan.password_spray import scan_base as spray_scan
    from scan.port_scan import scan_base as portscan_scan
    from scan.kerberos import scan_base as kerberos_scan
    from scan.http3 import scan_url as http3_scan
    from scan.service_worker import scan_url as sw_scan
    from scan.webrtc import scan_url as webrtc_scan
    from scan.rfi import scan_url as rfi_scan
    from scan.lfi_advanced import scan_url as lfiadv_scan
    from scan.cmdi_advanced import scan_url as cmdiadv_scan
    from scan.nosql_advanced import scan_url as nosqladv_scan
    from scan.prototype_pollution_advanced import scan_url as ppadv_scan
    from scan.dom_clobbering_advanced import scan_url as domclobberadv_scan
    from scan.postmessage_advanced import scan_url as postmsgadv_scan
    from scan.cors_advanced import scan_url as corsadv_scan
    from scan.csp_bypass_advanced import scan_url as cspbypassadv_scan
    from scan.http2 import scan_url as http2_scan
    from scan.cswsh import scan_url as cswsh_scan
    from scan.graphql_deep import scan_url as gqldeep_scan
    from scan.email_injection import scan_url as emailinj_scan
    from scan.db_exposure import scan_base as dbexp_scan
    from scan.container import scan_base as container_scan
    from scan.tls_audit import scan_url as tls_scan
    from scan.business_logic import scan_url as bizlogic_scan
    from scan.api_discovery import scan_base as apidisc_scan
    from scan.saml_xsw import scan_url as samlxsw_scan
    from scan.csrf import scan_url as csrf_scan
    from scan.cache_deception import scan_url as cachedec_scan
    from scan.default_creds import scan_base as defaultcreds_scan
    from scan.ratelimit import scan_url as ratelimit_scan
    from scan.saml import scan_url as saml_scan
    from fuzz.engine import fuzz_url, differential_scan

    scanner_list = [xss_scan, sqli_scan, ssti_scan, ssrf_scan, trav_scan, redir_scan, cmdi_scan,
                    jwt_scan, nosqli_scan, crlf_scan, proto_scan, xxe_scan, idor_scan, jwtdeep_scan,
                    hosthdr_scan, cache_scan, mass_scan, race_scan, waf_scan, sstiadv_scan, hijack_scan,
                    upload_scan, oauth_scan, ws_scan, mitb_scan, xssadv_scan, injadv_scan,
                    ssrfadv_scan, clientside_scan, csrf_scan, cachedec_scan, ratelimit_scan, saml_scan,
                    polyglot_scan, imgmeta_scan, archive_scan, xmladv_scan,
                    http2_scan, cswsh_scan, gqldeep_scan, emailinj_scan, bizlogic_scan,
                    tls_scan, samlxsw_scan, soap_scan, rfi_scan, lfiadv_scan, cmdiadv_scan,
                    nosqladv_scan, ppadv_scan, domclobberadv_scan, postmsgadv_scan,
                    corsadv_scan, cspbypassadv_scan, http3_scan, sw_scan, webrtc_scan]

    for u in urls_to_scan:
        for fn in scanner_list:
            tasks.append((fn, (u,), None))
        tasks.append((fuzz_url, (u,), None))
        tasks.append((differential_scan, (u,), None))
        tasks.append((smuggle_scan, (u,), None))
        tasks.append((deser_scan, (u,), None))

    for h in hosts[:5]:
        tasks.append((gql_scan, (h["url"],), None))
        tasks.append((ai_scan, (h["url"],), None))
        tasks.append((waf_scan, (h["url"],), None))
        tasks.append((defaultcreds_scan, (h["url"],), None))
        tasks.append((dbexp_scan, (h["url"],), None))
        tasks.append((container_scan, (h["url"],), None))
        tasks.append((apidisc_scan, (h["url"],), None))
        tasks.append((awsdeep_scan, (h["url"],), None))
        tasks.append((cicd_scan, (h["url"],), None))
        tasks.append((grpc_scan, (h["url"],), None))
        tasks.append((mfa_scan, (h["url"],), None))
        tasks.append((oauthadv_scan, (h["url"],), None))
        tasks.append((spray_scan, (h["url"],), None))
        tasks.append((portscan_scan, (h["url"],), None))
        tasks.append((kerberos_scan, (h["url"],), None))

    # run parallel
    all_findings = run_scanners_parallel(tasks, max_workers=12)

    # forms
    try:
        all_findings.extend(xss_forms(forms_all, f"http://{domain}"))
    except Exception:
        pass

    # dedup by id
    seen = set()
    uniq = []
    for f in all_findings:
        if f.id in seen:
            continue
        seen.add(f.id)
        uniq.append(f)

    try:
        from memory.pattern_db import record
        for f in uniq:
            record(domain, f.type, f.url, f.payload)
    except Exception:
        pass
    (sd / "findings_raw.json").write_text(json.dumps([f.to_dict() for f in uniq], indent=2, default=str))
    log_event(domain, "hunt_complete", {"raw_findings": len(uniq)})
    return uniq
