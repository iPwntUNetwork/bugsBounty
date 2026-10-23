"""Live Browser War-Room UI (`web/warroom_ui.py`) for Interactive Crew Command & Target Control.

- Binds `0.0.0.0` by default and accepts any Host/Origin header (Arena Live Preview ready!).
- Uses strictly relative `/api/...` endpoints in browser JS (zero `localhost` client references!).
- Lets the user:
  1. Launch the built-in safe **VulnCorp Target Lab** (`SQLi`, `XSS`, `SSRF`, `CMDi`, `LFI`, `SSTI`, `403`, `.env`, Cloudflare WAF + 6 False-Positive Traps) in 1 click — OR enter any target URL!
  2. Talk directly to **`@CREW`**, **`@GHOST`**, **`@BLITZ`**, **`@SWITCH`**, **`@RAZOR`**, **`@CHAINSAW`**, or **`@FIXER`** in the live `#basement-ops` war-room channel!
  3. Trigger individual phases (`Recon`, `Hunt`, `Escalate`, `RAZOR Audit`, `Chains`, `Report`) or full **6-Agent Autopilot** and inspect verified exploits, binned brown-eye false positives, kill chains, curl PoCs, and all 22 `.bin/` tools live!
"""
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.config import CFG
from tools.registry import ToolRegistry
from agents.warroom import WarRoomSession

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>bugsBounty // #basement-ops War-Room</title>
<style>
  :root {
    --bg: #080b10;
    --panel: #0f141d;
    --panel2: #141b27;
    --border: #233044;
    --fg: #e5edf7;
    --muted: #8b9bb4;
    --cyan: #29d3ff;
    --red: #ff4d6d;
    --green: #2ee59d;
    --yellow: #ffd166;
    --magenta: #c77dff;
    --blue: #5fa8ff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    height: 100vh; display: flex; flex-direction: column; overflow: hidden;
  }
  header {
    padding: 12px 18px; background: var(--panel); border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;
  }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 15px; letter-spacing: .5px; }
  .brand span.tag { background: #192436; color: var(--cyan); border: 1px solid #295070; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
  .target-bar { display: flex; gap: 8px; align-items: center; flex: 1; max-width: 720px; }
  .target-bar input {
    flex: 1; background: #070a0f; border: 1px solid var(--border); color: var(--fg);
    padding: 8px 11px; border-radius: 6px; font-family: inherit; font-size: 12px;
  }
  button {
    background: var(--panel2); color: var(--fg); border: 1px solid var(--border);
    padding: 8px 12px; border-radius: 6px; font-family: inherit; font-size: 12px; cursor: pointer;
    transition: all .14s ease; font-weight: 600;
  }
  button:hover:not(:disabled) { border-color: var(--cyan); color: #fff; transform: translateY(-1px); }
  button:disabled { opacity: .45; cursor: wait; }
  button.primary { background: #10324a; border-color: var(--cyan); color: var(--cyan); }
  button.danger { background: #3b1322; border-color: var(--red); color: #ff8fa3; }
  button.success { background: #0f3628; border-color: var(--green); color: var(--green); }

  main {
    flex: 1; display: grid; grid-template-columns: 270px 1fr 370px; min-height: 0;
  }
  aside, section { display: flex; flex-direction: column; min-height: 0; border-right: 1px solid var(--border); }
  aside:last-child { border-right: none; }
  .pane-head {
    padding: 10px 14px; font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
    color: var(--muted); border-bottom: 1px solid var(--border); background: var(--panel);
    display: flex; justify-content: space-between; align-items: center;
  }
  .scroll { flex: 1; overflow-y: auto; padding: 12px; }

  .crew-card {
    padding: 9px 11px; border: 1px solid var(--border); border-radius: 7px; margin-bottom: 8px;
    background: var(--panel); cursor: pointer; transition: border-color .15s;
  }
  .crew-card.active { border-color: var(--cyan); background: #122030; }
  .crew-card .handle { font-weight: 800; font-size: 13px; display: flex; justify-content: space-between; }
  .crew-card .role { color: var(--muted); font-size: 10.5px; margin-top: 2px; }
  .crew-card .bio { color: #b7c4d8; font-size: 10.5px; margin-top: 5px; line-height: 1.35; }

  .actions-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; padding: 10px 12px; border-top: 1px solid var(--border); background: var(--panel); }
  .actions-grid button.full { grid-column: 1 / -1; }

  .msg {
    padding: 9px 12px; border-radius: 7px; background: var(--panel); border-left: 3px solid var(--border);
    margin-bottom: 9px; font-size: 12.5px; line-height: 1.48; word-break: break-word;
  }
  .msg.cheer { border-left-color: var(--green); background: #0c221b; }
  .msg.browneye { border-left-color: var(--red); background: #261019; }
  .msg.handoff { border-left-color: var(--magenta); }
  .msg.audit { border-left-color: var(--yellow); }
  .msg.operator { border-left-color: var(--cyan); background: #102030; }
  .msg-head { display: flex; gap: 8px; align-items: baseline; margin-bottom: 4px; font-size: 11px; }
  .badge { padding: 1px 6px; border-radius: 4px; font-size: 9.5px; font-weight: 700; text-transform: uppercase; background: #1d283a; color: var(--muted); }
  .cheer .badge { background: #124935; color: var(--green); }
  .browneye .badge { background: #541929; color: #ff8fa3; }

  .composer {
    padding: 10px 12px; background: var(--panel); border-top: 1px solid var(--border);
    display: flex; gap: 8px; align-items: center;
  }
  .composer select {
    background: #070a0f; color: var(--cyan); border: 1px solid var(--border);
    padding: 9px 8px; border-radius: 6px; font-family: inherit; font-weight: 700; font-size: 12px;
  }
  .composer input {
    flex: 1; background: #070a0f; color: var(--fg); border: 1px solid var(--border);
    padding: 9px 12px; border-radius: 6px; font-family: inherit; font-size: 12.5px;
  }

  .tabs { display: flex; border-bottom: 1px solid var(--border); background: var(--panel); }
  .tabs button { flex: 1; border: none; border-radius: 0; border-bottom: 2px solid transparent; padding: 9px 4px; font-size: 11px; background: transparent; }
  .tabs button.active { border-bottom-color: var(--cyan); color: var(--cyan); }
  .finding {
    border: 1px solid var(--border); background: var(--panel); border-radius: 7px; padding: 9px 11px;
    margin-bottom: 8px; font-size: 11.5px;
  }
  .finding.critical { border-left: 3px solid var(--red); }
  .finding.high { border-left: 3px solid var(--yellow); }
  .finding.disproved { border-left: 3px solid #6c757d; opacity: .82; }
  pre.code {
    background: #06080c; border: 1px solid #1d2738; padding: 7px; border-radius: 5px;
    overflow-x: auto; font-size: 10.5px; color: #9be7ff; margin: 6px 0 0;
  }
  .stat-pill { font-size: 11px; color: var(--muted); }
  .stat-pill b { color: var(--fg); }
</style>
</head>
<body>
<header>
  <div class="brand">
    <span>bugsBounty</span>
    <span class="tag">#basement-ops</span>
    <span class="stat-pill" id="statsBar">Connecting...</span>
  </div>
  <div class="target-bar">
    <input id="targetInput" placeholder="https://authorized-target.tld  (or click Launch Target Lab ->)" />
    <button onclick="setTarget()">Set Target</button>
    <button class="success" id="btnLab" onclick="sendCmd('/lab')">Launch Target Lab</button>
    <button class="danger" id="btnAuto" onclick="sendCmd('/autopilot')">Run 6-Agent Autopilot</button>
  </div>
</header>

<main>
  <aside>
    <div class="pane-head"><span>20-Yr War-Room Crew</span><span id="llmBadge"></span></div>
    <div class="scroll" id="crewList"></div>
    <div class="actions-grid">
      <button onclick="sendCmd('/recon')">1. GHOST Recon</button>
      <button onclick="sendCmd('/hunt')">2. BLITZ Hunt</button>
      <button onclick="sendCmd('/escalate')">3. SWITCH Escalate</button>
      <button onclick="sendCmd('/critic')">4. RAZOR Critic</button>
      <button onclick="sendCmd('/chains')">5. CHAINSAW</button>
      <button onclick="sendCmd('/report')">6. FIXER Report</button>
    </div>
  </aside>

  <section>
    <div class="pane-head">
      <span>Live Crew Comms, Handoffs, Cheers &amp; Brown-Eye Roasts</span>
      <span id="busyIndicator" style="color:var(--yellow)"></span>
    </div>
    <div class="scroll" id="chatFeed"></div>
    <form class="composer" onsubmit="onSubmitChat(event)">
      <select id="speakerSelect">
        <option value="">@CREW (All)</option>
        <option value="GHOST">@GHOST</option>
        <option value="BLITZ">@BLITZ</option>
        <option value="SWITCH">@SWITCH</option>
        <option value="RAZOR">@RAZOR</option>
        <option value="CHAINSAW">@CHAINSAW</option>
        <option value="FIXER">@FIXER</option>
      </select>
      <input id="chatInput" autocomplete="off" placeholder="Talk to the crew: e.g. 'spin up the lab and tear it apart' or '@razor audit everything'..." />
      <button class="primary" id="btnSend" type="submit">Send</button>
    </form>
  </section>

  <aside>
    <div class="tabs">
      <button id="tab-verified" class="active" onclick="setTab('verified')">Verified (<span id="cntV">0</span>)</button>
      <button id="tab-disproved" onclick="setTab('disproved')">Binned (<span id="cntD">0</span>)</button>
      <button id="tab-chains" onclick="setTab('chains')">Chains (<span id="cntC">0</span>)</button>
      <button id="tab-tools" onclick="setTab('tools')">.bin/ (<span id="cntT">22</span>)</button>
    </div>
    <div class="scroll" id="rightPane"></div>
  </aside>
</main>

<script>
const COLORS = {
  GHOST: '#29d3ff', BLITZ: '#ff4d6d', SWITCH: '#c77dff',
  RAZOR: '#ffd166', CHAINSAW: '#2ee59d', FIXER: '#5fa8ff', YOU: '#ffffff'
};
let state = null;
let toolsCache = [];
let currentTab = 'verified';
let lastMsgCount = -1;

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  return await r.json();
}

function setBusy(busy, label='') {
  document.getElementById('busyIndicator').textContent = busy ? ('[RUNNING] ' + label) : '';
  for (const b of document.querySelectorAll('button')) b.disabled = busy;
}

async function refreshState() {
  try {
    state = await api('api/state');
    render();
  } catch (e) {}
}

async function loadTools() {
  try {
    const d = await api('api/tools');
    toolsCache = d.tools || [];
    document.getElementById('cntT').textContent = toolsCache.length;
    if (currentTab === 'tools') renderRight();
  } catch (e) {}
}

function selectCrew(handle) {
  document.getElementById('speakerSelect').value = handle;
  document.getElementById('chatInput').focus();
  renderCrew();
}

function renderCrew() {
  if (!state) return;
  const sel = document.getElementById('speakerSelect').value;
  document.getElementById('crewList').innerHTML = state.crew.map(m => `
    <div class="crew-card ${sel === m.handle ? 'active' : ''}" onclick="selectCrew('${m.handle}')">
      <div class="handle"><span style="color:${COLORS[m.handle] || '#fff'}">@${esc(m.handle)}</span><span class="badge">${esc(m.role.split(' ')[0])}</span></div>
      <div class="role">${esc(m.role)}</div>
      <div class="bio">${esc(m.bio)}</div>
    </div>
  `).join('');
}

function renderChat() {
  if (!state) return;
  const msgs = state.transcript || [];
  if (msgs.length === lastMsgCount) return;
  lastMsgCount = msgs.length;
  const feed = document.getElementById('chatFeed');
  feed.innerHTML = msgs.map(m => `
    <div class="msg ${esc(m.kind)}">
      <div class="msg-head">
        <span class="badge">${esc(m.kind)}</span>
        <strong style="color:${COLORS[m.speaker] || '#fff'}">${esc(m.speaker)}</strong>
        ${m.to ? `<span style="color:var(--muted)">-&gt; ${esc(m.to)}</span>` : ''}
      </div>
      <div>${esc(m.text)}</div>
    </div>
  `).join('');
  feed.scrollTop = feed.scrollHeight;
}

function setTab(t) {
  currentTab = t;
  for (const id of ['verified', 'disproved', 'chains', 'tools']) {
    document.getElementById('tab-' + id).classList.toggle('active', id === t);
  }
  renderRight();
}

function renderRight() {
  if (!state) return;
  const pane = document.getElementById('rightPane');
  const pocMap = {};
  for (const p of (state.pocs || [])) pocMap[p.finding_id] = p;

  if (currentTab === 'verified') {
    const items = state.verified || [];
    if (!items.length) {
      pane.innerHTML = '<p style="color:var(--muted);font-size:12px">No RAZOR-verified findings yet. Click <b>Launch Target Lab</b> then <b>Run 6-Agent Autopilot</b>!</p>';
      return;
    }
    pane.innerHTML = items.map(f => {
      const poc = pocMap[f.id] || {};
      return `<div class="finding ${esc(f.severity)}">
        <div><strong>[${esc((f.severity||'').toUpperCase())}] ${esc(f.type)}</strong></div>
        <div style="color:var(--muted);margin-top:3px">${esc(f.url)} (${esc(f.parameter)})</div>
        <div style="margin-top:5px">${esc(f.evidence)}</div>
        <div style="margin-top:4px;color:var(--green);font-size:10.5px">Escalated: ${esc((f.escalated_with||[]).join(', ') || 'direct')} | Critic: ${esc((f.critic_notes||[])[0] || 'verified')}</div>
        ${poc.curl ? `<pre class="code">${esc(poc.curl)}</pre>` : ''}
      </div>`;
    }).join('');
  } else if (currentTab === 'disproved') {
    const items = state.disproved || [];
    pane.innerHTML = items.length ? items.map(f => `
      <div class="finding disproved">
        <div><strong>[BINNED BY RAZOR] ${esc(f.type)}</strong></div>
        <div style="color:var(--muted);margin-top:3px">${esc(f.url)}</div>
        <div style="color:#ff8fa3;margin-top:5px">${esc((f.critic_notes||[]).join(' | '))}</div>
      </div>
    `).join('') : '<p style="color:var(--muted);font-size:12px">No false-positive claims binned yet.</p>';
  } else if (currentTab === 'chains') {
    const items = state.chains || [];
    pane.innerHTML = items.length ? items.map(c => `
      <div class="finding critical">
        <div><strong>[${esc((c.severity||'CRITICAL').toUpperCase())}] ${esc(c.title)}</strong></div>
        <div style="margin-top:6px">${(c.steps||[]).map(s => `<div style="margin-bottom:4px">• ${esc(s)}</div>`).join('')}</div>
      </div>
    `).join('') : '<p style="color:var(--muted);font-size:12px">No attack chains synthesized yet.</p>';
  } else {
    pane.innerHTML = toolsCache.map(t => `
      <div class="finding">
        <div style="display:flex;justify-content:space-between">
          <strong>${esc(t.name)}</strong>
          <span style="color:var(--green)">${esc(t.source)} :: ${esc(t.status)}</span>
        </div>
        <div style="color:var(--muted);font-size:10.5px;margin-top:3px">${esc(t.version)}</div>
      </div>
    `).join('');
  }
}

function render() {
  const st = state.status;
  const ti = document.getElementById('targetInput');
  if (!ti.value && st.target) ti.value = st.target;
  if (st.target && ti !== document.activeElement) ti.value = st.target;
  document.getElementById('statsBar').innerHTML =
    `Target: <b>${esc(st.target || 'none')}</b> &nbsp;|&nbsp; Surface: <b>${st.surface_urls}</b> &nbsp;|&nbsp; Verified: <b style="color:var(--green)">${st.verified_count}</b> &nbsp;|&nbsp; Binned: <b style="color:var(--red)">${st.disproved_count}</b>`;
  document.getElementById('llmBadge').textContent = st.llm.active_provider;
  document.getElementById('cntV').textContent = st.verified_count;
  document.getElementById('cntD').textContent = st.disproved_count;
  document.getElementById('cntC').textContent = st.chains_count;
  renderCrew();
  renderChat();
  renderRight();
}

async function sendCmd(message, speaker='') {
  setBusy(true, message);
  try {
    await api('api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message, speaker})
    });
    await refreshState();
  } finally {
    setBusy(false);
  }
}

async function setTarget() {
  const v = document.getElementById('targetInput').value.trim();
  if (v) await sendCmd('/target ' + v);
}

async function onSubmitChat(ev) {
  ev.preventDefault();
  const inp = document.getElementById('chatInput');
  const speaker = document.getElementById('speakerSelect').value;
  const msg = inp.value.trim();
  if (!msg) return;
  inp.value = '';
  await sendCmd(msg, speaker);
}

refreshState().then(() => {
  if (state && (!state.transcript || !state.transcript.length)) {
    sendCmd('Oi crew, sound off and report station status!');
  }
});
loadTools();
setInterval(refreshState, 2500);
</script>
</body>
</html>
"""


def start_warroom_server(
    host: str = "0.0.0.0",
    port: int = 8787,
    target: str | None = None,
    auto_lab: bool = False,
    block: bool = True,
):
    CFG["crew_banter"] = True
    session = WarRoomSession(target=target)
    if auto_lab and not session.target:
        session.start_lab()
    tools_snapshot = ToolRegistry.audit()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _json(self, status: int, data: dict):
            raw = json.dumps(data, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_OPTIONS(self):
            self._json(200, {"ok": True})

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
            if path in ("/", "/index.html"):
                raw = HTML_PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            if path == "/api/state":
                self._json(200, session.state_snapshot())
                return
            if path == "/api/tools":
                self._json(200, {"tools": tools_snapshot})
                return
            if path == "/health":
                self._json(200, {"ok": True, "status": session.status_dict()})
                return
            self._json(404, {"error": "not found"})

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path.rstrip("/")
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8") or "{}") if length else {}
            if path == "/api/chat":
                out = session.handle_message(body.get("message", ""), speaker_target=body.get("speaker") or None)
                self._json(200, out)
                return
            self._json(404, {"error": "not found"})

    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer((host, port), Handler)
    if block:
        print(f"[bugsBounty] #basement-ops Web War-Room listening on http://{host}:{httpd.server_address[1]}", flush=True)
        httpd.serve_forever()
    else:
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
    return httpd, session
