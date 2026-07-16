'use strict';
/**
 * CFRadar — Cloudflare Worker Edition
 * Runs entirely on Cloudflare Workers (no Node.js needed).
 * Scan is client-side; worker serves static assets + proxy API calls.
 */

const STATIC = {
  '/': { content: INDEX_HTML, type: 'text/html; charset=utf-8' },
  '/index.html': { content: INDEX_HTML, type: 'text/html; charset=utf-8' },
  '/style.css': { content: STYLE_CSS, type: 'text/css; charset=utf-8' },
  '/app.js': { content: APP_JS, type: 'application/javascript; charset=utf-8' },
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    // API: probe a single IP (client offloads scanning to this endpoint)
    if (path === '/api/probe' && request.method === 'GET') {
      return handleProbe(url.searchParams);
    }

    // API: geo lookup
    if (path === '/api/geo' && request.method === 'GET') {
      return handleGeo(url.searchParams, request);
    }

    // Static files
    const asset = STATIC[path];
    if (asset) {
      return new Response(asset.content, {
        headers: {
          'Content-Type': asset.type,
          'Cache-Control': 'public, max-age=300',
        },
      });
    }

    return new Response('Not found', { status: 404 });
  },
};

// ---------------------------------------------------------------------------
// /api/probe — Worker probes an IP via fetch() (TLS + HTTP headers check)
// ---------------------------------------------------------------------------
async function handleProbe(params) {
  const ip = params.get('ip');
  const sni = params.get('sni') || 'speed.cloudflare.com';
  const port = params.get('port') || '443';
  const timeoutMs = parseInt(params.get('timeout') || '2000', 10);

  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    return json({ error: 'invalid ip' }, 400);
  }

  const t0 = Date.now();
  let cfVerified = false;
  let tlsOk = false;
  let httpStatus = null;
  let latencyMs = null;
  let cfRay = null;
  let cfPop = null; // Point of Presence (datacenter code)
  let server = null;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    // Workers can't open raw TCP, but can make HTTPS fetches.
    // We use the IP directly but set the Host header to the SNI domain —
    // this is exactly how domain-fronting / clean-IP proxying works.
    const targetUrl = `https://${ip}:${port}/`;
    const resp = await fetch(targetUrl, {
      method: 'HEAD',
      headers: {
        Host: sni,
        'User-Agent': 'CFRadar/2.0',
      },
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timer);

    latencyMs = Date.now() - t0;
    httpStatus = resp.status;
    tlsOk = true;

    // Check Cloudflare signature headers
    cfRay = resp.headers.get('cf-ray');
    server = resp.headers.get('server');
    cfPop = cfRay ? cfRay.split('-').pop() : null; // e.g. "AMS" from "abc123-AMS"
    cfVerified = !!(cfRay || (server && server.toLowerCase().includes('cloudflare')));
  } catch (e) {
    latencyMs = Date.now() - t0;
    if (latencyMs >= timeoutMs - 50) latencyMs = null; // timed out
  }

  return json({
    ip, sni, port,
    latencyMs,
    tlsOk,
    cfVerified,
    cfRay,
    cfPop,
    server,
    httpStatus,
  });
}

// ---------------------------------------------------------------------------
// /api/geo — IP geolocation using Cloudflare's built-in request metadata
// (when the client asks us to look up an IP, we proxy to ip-api.com)
// ---------------------------------------------------------------------------
async function handleGeo(params, request) {
  const ip = params.get('ip');
  if (!ip) return json({ error: 'missing ip' }, 400);

  try {
    const resp = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp,org,as,lat,lon`, {
      headers: { 'User-Agent': 'CFRadar/2.0' },
      cf: { cacheTtl: 3600, cacheEverything: true },
    });
    const data = await resp.json();
    return json(data);
  } catch {
    return json({ status: 'fail', error: 'geo lookup failed' });
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

// ---------------------------------------------------------------------------
// Inline static files (injected by build script)
// ---------------------------------------------------------------------------
// BUILD_INJECT_START
const INDEX_HTML = `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>CFRadar — Clean Cloudflare IP Scanner</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="style.css" />
</head>
<body>

<div class="scanlines"></div>

<header class="topbar">
  <div class="brand">
    <div class="brand-mark">
      <svg viewBox="0 0 40 40" width="34" height="34">
        <circle cx="20" cy="20" r="18" fill="none" stroke="var(--cyan)" stroke-width="1.5" opacity="0.5"/>
        <circle cx="20" cy="20" r="11" fill="none" stroke="var(--cyan)" stroke-width="1.5" opacity="0.7"/>
        <circle cx="20" cy="20" r="2.4" fill="var(--green)"/>
        <line id="brandSweep" x1="20" y1="20" x2="20" y2="2" stroke="var(--green)" stroke-width="1.6" opacity="0.85"/>
      </svg>
    </div>
    <div class="brand-text">
      <div class="brand-title">CF<span class="accent">Radar</span> <span class="version-badge">v2.0</span></div>
      <div class="brand-sub">Clean Cloudflare IP &amp; domain scanner — built for the Iranian internet</div>
    </div>
  </div>
  <div class="topbar-right">
    <div class="status-pill" id="statusPill">
      <span class="dot" id="statusDot"></span>
      <span id="statusText">Ready</span>
    </div>
  </div>
</header>

<!-- Main nav tabs -->
<nav class="main-nav">
  <button class="main-tab active" data-panel="scan">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="8" stroke="currentColor" stroke-width="2"/><path d="m21 21-4.35-4.35" stroke="currentColor" stroke-width="2"/></svg>
    Scan
  </button>
  <button class="main-tab" data-panel="results">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" stroke="currentColor" stroke-width="2"/></svg>
    Results <span class="nav-badge" id="navResultsBadge"></span>
  </button>
  <button class="main-tab" data-panel="v2ray">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" stroke="currentColor" stroke-width="2"/></svg>
    V2Ray Links <span class="nav-badge green" id="navV2rayBadge"></span>
  </button>
  <button class="main-tab" data-panel="geo">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20" stroke="currentColor" stroke-width="2"/></svg>
    Geo &amp; ASN
  </button>
</nav>

<main class="layout">

  <!-- ===================== SCAN PANEL ===================== -->
  <div class="main-panel active" id="panelScan">
    <div class="scan-layout">

      <!-- Controls -->
      <section class="panel controls">
        <div class="section-title">Scan Configuration</div>

        <div class="tabs">
          <button class="tab active" data-mode="cf">Cloudflare Ranges</button>
          <button class="tab" data-mode="domains">Domain List</button>
        </div>

        <div class="tab-body" id="tabCf">
          <label class="field">
            <span>Number of IPs to sample</span>
            <input type="number" id="cfCount" value="500" min="1" max="20000" />
          </label>
          <label class="field">
            <span>SNI hostname (Cloudflare domain for TLS fronting verification)</span>
            <input type="text" id="cfSni" value="speed.cloudflare.com" />
          </label>
        </div>

        <div class="tab-body hidden" id="tabDomains">
          <label class="field">
            <span>Domain list source (URL or file path)</span>
            <input type="text" id="domainsSource" value="https://raw.githubusercontent.com/hossein-mohseni/CF-Web/refs/heads/main/domains.json" />
          </label>
          <label class="field checkbox">
            <input type="checkbox" id="resolveDns" />
            <span>Force fresh DNS lookup (ignore IPs in JSON)</span>
          </label>
        </div>

        <div class="grid2">
          <label class="field">
            <span>TCP Port</span>
            <select id="port">
              <option value="443" selected>443 (HTTPS)</option>
              <option value="2053">2053</option>
              <option value="2083">2083</option>
              <option value="2087">2087</option>
              <option value="2096">2096</option>
              <option value="80">80 (HTTP)</option>
            </select>
          </label>
          <label class="field">
            <span>Passes per IP</span>
            <input type="number" id="passes" value="3" min="1" max="10" />
          </label>
          <label class="field">
            <span>Timeout (ms)</span>
            <input type="number" id="timeout" value="1200" min="100" max="10000" step="100" />
            <small class="field-hint" id="timeoutHint"></small>
          </label>
          <label class="field">
            <span>Parallel workers</span>
            <input type="number" id="workers" value="250" min="1" max="2000" />
          </label>
        </div>

        <div class="grid2">
          <label class="field">
            <span>Target latency min (ms)</span>
            <input type="number" id="targetMin" placeholder="e.g. 40" min="0" max="5000" />
          </label>
          <label class="field">
            <span>Target latency max (ms)</span>
            <input type="number" id="targetMax" placeholder="e.g. 120" min="0" max="5000" />
          </label>
        </div>
        <small class="field-hint">Leave empty for general "fast" mode. If set, only IPs in this latency band count as Clean.</small>

        <div class="section-title" style="margin-top:16px;">V2Ray Link Builder</div>
        <div class="grid2">
          <label class="field">
            <span>UUID (for vmess/vless)</span>
            <input type="text" id="v2uuid" placeholder="auto-generate" />
          </label>
          <label class="field">
            <span>Protocol</span>
            <select id="v2proto">
              <option value="vless">VLESS</option>
              <option value="vmess">VMess</option>
              <option value="trojan">Trojan</option>
            </select>
          </label>
          <label class="field">
            <span>Path</span>
            <input type="text" id="v2path" value="/" />
          </label>
          <label class="field">
            <span>Network</span>
            <select id="v2net">
              <option value="ws">WebSocket</option>
              <option value="grpc">gRPC</option>
              <option value="h2">HTTP/2</option>
              <option value="tcp">TCP</option>
            </select>
          </label>
        </div>
        <label class="field">
          <span>Host/SNI for V2Ray config</span>
          <input type="text" id="v2sni" value="speed.cloudflare.com" />
        </label>
        <label class="field checkbox">
          <input type="checkbox" id="v2tls" checked />
          <span>TLS enabled</span>
        </label>

        <label class="field checkbox" style="margin-top:8px;">
          <input type="checkbox" id="useIcmp" />
          <span>Real ICMP ping (spawns OS <code>ping</code> — lower workers if enabled)</span>
        </label>

        <div class="btn-row">
          <button class="btn-primary" id="startBtn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M5 3l16 9-16 9V3z" fill="currentColor"/></svg>
            Start Scan
          </button>
          <button class="btn-ghost hidden" id="stopBtn">⏹ Stop</button>
        </div>

        <div class="legend">
          <span class="legend-item"><i class="sw clean"></i>Clean</span>
          <span class="legend-item"><i class="sw warn"></i>Unstable</span>
          <span class="legend-item"><i class="sw dead"></i>Dead</span>
        </div>
      </section>

      <!-- Radar -->
      <section class="panel radar-panel">
        <canvas id="radar" width="520" height="520"></canvas>
        <div class="radar-stats">
          <div class="stat">
            <div class="stat-num" id="statTotal">0</div>
            <div class="stat-label">Checked</div>
          </div>
          <div class="stat clean">
            <div class="stat-num" id="statClean">0</div>
            <div class="stat-label">Clean</div>
          </div>
          <div class="stat dead">
            <div class="stat-num" id="statDead">0</div>
            <div class="stat-label">Dead</div>
          </div>
          <div class="stat">
            <div class="stat-num" id="statAvg">–</div>
            <div class="stat-label">Best ms</div>
          </div>
        </div>
        <div class="progress-wrap">
          <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
          <div class="progress-text" id="progressText">Waiting to start…</div>
        </div>
        <!-- Live feed -->
        <div class="live-feed" id="liveFeed">
          <div class="live-feed-title">Live feed</div>
          <div id="liveFeedBody"></div>
        </div>
      </section>

    </div>
  </div>

  <!-- ===================== RESULTS PANEL ===================== -->
  <div class="main-panel" id="panelResults">
    <section class="panel results">
      <div class="results-head">
        <h2>Scan Results <span class="muted" id="resultsCount">(0)</span></h2>
        <div class="export-group">
          <button class="btn-export" data-fmt="cleanips">⬇ Clean IPs (.txt)</button>
          <button class="btn-export" data-fmt="v2ray">⬇ V2Ray Links</button>
          <button class="btn-export" data-fmt="csv">⬇ CSV</button>
          <button class="btn-export" data-fmt="json">⬇ JSON</button>
          <button class="btn-export" data-fmt="clash">⬇ Clash Proxies</button>
        </div>
      </div>
      <div class="filter-row">
        <label class="field checkbox inline">
          <input type="checkbox" id="filterClean" checked />
          <span>Clean only</span>
        </label>
        <label class="field inline">
          <input type="text" id="filterIp" placeholder="Filter by IP…" style="width:160px" />
        </label>
        <label class="field inline">
          <input type="number" id="filterMaxMs" placeholder="Max ms" style="width:100px" />
        </label>
        <button class="btn-export" id="clearFilter">✕ Clear</button>
      </div>
      <div class="table-wrap">
        <table id="resultsTable">
          <thead>
            <tr>
              <th data-key="rank">#</th>
              <th data-key="ip">IP</th>
              <th data-key="domain">Domain</th>
              <th data-key="avgMs">Avg ms</th>
              <th data-key="medianMs">Median ms</th>
              <th data-key="icmpMs">ICMP ms</th>
              <th data-key="jitterMs">Jitter</th>
              <th data-key="lossPct">Loss%</th>
              <th data-key="cfVerified">CF TLS</th>
              <th data-key="cfPop">PoP</th>
              <th data-key="throughputKbps">Speed KB/s</th>
              <th data-key="status">Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="resultsBody">
            <tr class="empty-row"><td colspan="13">No scan yet — go to the Scan tab.</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <!-- ===================== V2RAY PANEL ===================== -->
  <div class="main-panel" id="panelV2ray">
    <section class="panel">
      <div class="results-head">
        <h2>V2Ray &amp; Xray Links <span class="muted" id="v2Count">(0)</span></h2>
        <div class="export-group">
          <button class="btn-export" id="copyAllV2">⎘ Copy All</button>
          <button class="btn-export" id="downloadV2">⬇ Download .txt</button>
          <button class="btn-export" id="downloadClash">⬇ Clash Config</button>
          <button class="btn-export" id="downloadSingbox">⬇ sing-box Config</button>
        </div>
      </div>
      <div class="v2ray-info">
        <div class="v2ray-info-box">
          <b>How to use:</b> Each link below is a complete proxy config for a clean Cloudflare IP.
          Import directly into v2rayNG, v2rayN, Nekoray, Hiddify, Streisand, or any Xray client.
          The links encode your V2Ray settings from the Scan tab.
        </div>
      </div>
      <div id="v2LinkList" class="v2-link-list">
        <div class="empty-row-plain">Run a scan first. Clean IPs will appear here as ready-to-use V2Ray links.</div>
      </div>
    </section>
  </div>

  <!-- ===================== GEO PANEL ===================== -->
  <div class="main-panel" id="panelGeo">
    <section class="panel">
      <div class="results-head">
        <h2>Geo &amp; ASN Lookup</h2>
      </div>
      <div class="geo-lookup-row">
        <input type="text" id="geoIpInput" placeholder="Enter an IP address…" class="geo-input" />
        <button class="btn-primary" id="geoLookupBtn" style="width:auto;padding:10px 20px;">Lookup</button>
      </div>
      <div id="geoResult" class="geo-result hidden"></div>

      <div class="section-title" style="margin-top:28px;">Clean IP Geo Map</div>
      <div class="geo-summary-info">After a scan, clean IPs are grouped by country and datacenter (PoP) here.</div>
      <div id="geoSummary" class="geo-summary">
        <div class="empty-row-plain">Run a scan to see geo distribution of clean IPs.</div>
      </div>
    </section>
  </div>

</main>

<footer class="footer">CFRadar v2.0 · Cloudflare Workers ready · No npm install required</footer>

<!-- IP detail modal -->
<div class="modal-overlay hidden" id="modalOverlay">
  <div class="modal" id="modalBox">
    <button class="modal-close" id="modalClose">✕</button>
    <div id="modalContent"></div>
  </div>
</div>

<script src="app.js"></script>
</body>
</html>
`;
const STYLE_CSS  = `:root {
  --bg: #0a0d12;
  --panel: #11151c;
  --panel-2: #161b24;
  --border: #232a36;
  --text: #e7ecf2;
  --text-dim: #7c8898;
  --green: #00e68a;
  --amber: #ffb020;
  --red: #ff4d5e;
  --cyan: #4de8ff;
  --mono: 'JetBrains Mono', ui-monospace, monospace;
  --sans: 'Vazirmatn', system-ui, sans-serif;
}

* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: radial-gradient(ellipse 1200px 800px at 50% -10%, #131a24 0%, var(--bg) 55%);
  color: var(--text);
  font-family: var(--sans);
  min-height: 100vh;
}

.scanlines {
  position: fixed; inset: 0; pointer-events: none; z-index: 999;
  background: repeating-linear-gradient(0deg, rgba(255,255,255,0.012) 0px, rgba(255,255,255,0.012) 1px, transparent 1px, transparent 3px);
  mix-blend-mode: overlay;
}

/* ---------------- top bar ---------------- */
.topbar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 18px 28px; border-bottom: 1px solid var(--border);
  background: rgba(10,13,18,0.7); backdrop-filter: blur(6px);
  position: sticky; top: 0; z-index: 10;
}
.brand { display: flex; align-items: center; gap: 12px; }
.brand-title { font-family: var(--mono); font-weight: 700; font-size: 20px; letter-spacing: 0.5px; }
.brand-title .accent { color: var(--green); }
.brand-sub { font-size: 12px; color: var(--text-dim); margin-top: 2px; }

.status-pill {
  display: flex; align-items: center; gap: 8px;
  padding: 7px 14px; border-radius: 999px;
  background: var(--panel); border: 1px solid var(--border);
  font-family: var(--mono); font-size: 12px; color: var(--text-dim);
}
.status-pill .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--text-dim); }
.status-pill.running .dot { background: var(--cyan); box-shadow: 0 0 10px var(--cyan); animation: pulse 1.2s infinite; }
.status-pill.running { color: var(--cyan); }
.status-pill.done .dot { background: var(--green); box-shadow: 0 0 10px var(--green); }
.status-pill.done { color: var(--green); }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }

/* ---------------- layout ---------------- */
.layout {
  display: grid;
  grid-template-columns: 320px 1fr;
  grid-template-rows: auto auto;
  gap: 18px;
  padding: 22px 28px 10px;
  max-width: 1400px; margin: 0 auto;
}
.panel {
  background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 20px;
}
.controls { grid-row: 1 / 3; }
.radar-panel { display: flex; flex-direction: column; align-items: center; }
.results { grid-column: 2; }

@media (max-width: 980px) {
  .layout { grid-template-columns: 1fr; }
  .controls { grid-row: auto; }
  .results { grid-column: 1; }
}

/* ---------------- controls ---------------- */
.tabs { display: flex; gap: 6px; margin-bottom: 18px; background: var(--bg); border-radius: 10px; padding: 4px; }
.tab {
  flex: 1; padding: 9px 10px; border: none; border-radius: 8px; cursor: pointer;
  background: transparent; color: var(--text-dim); font-family: var(--sans); font-weight: 600; font-size: 13px;
  transition: all .15s;
}
.tab.active { background: var(--panel-2); color: var(--text); box-shadow: inset 0 0 0 1px var(--border); }
.tab-body.hidden { display: none; }

.field { display: flex; flex-direction: column; gap: 6px; margin-bottom: 14px; font-size: 12.5px; color: var(--text-dim); }
.field input[type="text"], .field input[type="number"], .field select {
  background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
  padding: 9px 10px; color: var(--text); font-family: var(--mono); font-size: 13px;
  outline: none; transition: border-color .15s;
}
.field input:focus, .field select:focus { border-color: var(--cyan); }
.field.checkbox { flex-direction: row; align-items: center; gap: 8px; }
.field.checkbox input { width: 16px; height: 16px; accent-color: var(--cyan); }

.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 0 12px; }

.btn-primary {
  width: 100%; padding: 12px; margin-top: 6px;
  background: linear-gradient(135deg, var(--green), #00c4ff);
  color: #04201a; border: none; border-radius: 10px;
  font-family: var(--sans); font-weight: 700; font-size: 14px; cursor: pointer;
  display: flex; align-items: center; justify-content: center; gap: 8px;
  transition: transform .12s, box-shadow .12s;
}
.btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(0,230,138,0.25); }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
.btn-ghost {
  width: 100%; margin-top: 8px; padding: 10px;
  background: transparent; border: 1px solid var(--border); color: var(--text-dim);
  border-radius: 10px; cursor: pointer; font-family: var(--sans); font-size: 13px;
}
.hidden { display: none !important; }

.legend { display: flex; gap: 16px; margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border); }
.legend-item { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-dim); }
.sw { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.sw.clean { background: var(--green); box-shadow: 0 0 6px var(--green); }
.sw.warn { background: var(--amber); box-shadow: 0 0 6px var(--amber); }
.sw.dead { background: var(--red); box-shadow: 0 0 6px var(--red); }

/* ---------------- radar ---------------- */
.radar-panel canvas { width: 100%; max-width: 380px; height: auto; }
.radar-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; width: 100%; margin-top: 8px; }
.stat { text-align: center; padding: 10px 4px; background: var(--bg); border-radius: 10px; border: 1px solid var(--border); }
.stat-num { font-family: var(--mono); font-weight: 700; font-size: 20px; }
.stat.clean .stat-num { color: var(--green); }
.stat.dead .stat-num { color: var(--red); }
.stat-label { font-size: 11px; color: var(--text-dim); margin-top: 2px; }

.progress-wrap { width: 100%; margin-top: 16px; }
.progress-bar { height: 8px; border-radius: 6px; background: var(--bg); overflow: hidden; border: 1px solid var(--border); }
.progress-fill { height: 100%; width: 0%; background: linear-gradient(90deg, var(--cyan), var(--green)); transition: width .25s; }
.progress-text { font-family: var(--mono); font-size: 11.5px; color: var(--text-dim); margin-top: 6px; text-align: center; }

/* ---------------- results table ---------------- */
.results-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; flex-wrap: wrap; gap: 10px; }
.results-head h2 { font-size: 16px; margin: 0; font-weight: 700; }
.muted { color: var(--text-dim); font-weight: 400; font-size: 13px; }
.field-hint { display: block; margin-top: 4px; font-size: 12px; min-height: 14px; }
.field-hint.warn { color: #ffb020; }
tr.in-range { background: rgba(0, 230, 138, 0.07); }
tr.out-range { opacity: 0.7; }
.export-group { display: flex; gap: 8px; }
.btn-export {
  background: var(--bg); border: 1px solid var(--border); color: var(--text-dim);
  padding: 7px 12px; border-radius: 8px; font-size: 12px; cursor: pointer; font-family: var(--sans);
  transition: all .15s;
}
.btn-export:hover { color: var(--cyan); border-color: var(--cyan); }

.table-wrap { max-height: 560px; overflow-y: auto; border-radius: 10px; border: 1px solid var(--border); }
table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 13px; }
thead th {
  position: sticky; top: 0; background: var(--panel-2); color: var(--text-dim);
  text-align: right; padding: 10px 12px; font-weight: 600; font-size: 11.5px;
  border-bottom: 1px solid var(--border); cursor: pointer; user-select: none;
}
thead th:hover { color: var(--cyan); }
tbody td { padding: 9px 12px; border-bottom: 1px solid rgba(255,255,255,0.03); }
tbody tr:hover { background: rgba(255,255,255,0.02); }
.empty-row td { text-align: center; color: var(--text-dim); padding: 40px 10px; font-family: var(--sans); }

.tag { display: inline-flex; align-items: center; gap: 6px; padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; }
.tag.clean { color: var(--green); background: rgba(0,230,138,0.1); }
.tag.warn { color: var(--amber); background: rgba(255,176,32,0.1); }
.tag.dead { color: var(--red); background: rgba(255,77,94,0.1); }

.lat-good { color: var(--green); font-weight: 700; }
.lat-mid { color: var(--amber); }
.lat-bad { color: var(--red); }

.footer { text-align: center; color: var(--text-dim); font-size: 11.5px; padding: 26px 0 30px; font-family: var(--mono); }

::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 8px; }
::-webkit-scrollbar-track { background: transparent; }

/* ============================================================
   CFRadar v2.0 — additional styles for new panels & features
   ============================================================ */

/* version badge */
.version-badge {
  font-size: 11px; font-weight: 500; color: var(--text-dim);
  background: var(--panel-2); border: 1px solid var(--border);
  padding: 2px 7px; border-radius: 999px; vertical-align: middle; margin-left: 4px;
}

/* main nav */
.main-nav {
  display: flex; gap: 4px; padding: 10px 28px 0;
  max-width: 1400px; margin: 0 auto;
}
.main-tab {
  display: flex; align-items: center; gap: 7px;
  padding: 9px 18px; border: none; border-radius: 10px 10px 0 0;
  background: var(--panel); border: 1px solid var(--border); border-bottom: none;
  color: var(--text-dim); font-family: var(--sans); font-size: 13px; font-weight: 600;
  cursor: pointer; transition: all .15s; margin-bottom: -1px; position: relative;
}
.main-tab:hover { color: var(--text); }
.main-tab.active { background: var(--panel-2); color: var(--text); border-bottom-color: var(--panel-2); z-index: 1; }
.nav-badge {
  background: var(--cyan); color: #04201a;
  font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 999px; font-family: var(--mono);
}
.nav-badge.green { background: var(--green); }

/* main layout */
.layout { padding: 0 28px 20px; max-width: 1400px; margin: 0 auto; border-top: 1px solid var(--border); }
.main-panel { display: none; padding-top: 20px; }
.main-panel.active { display: block; }

/* scan layout override */
.scan-layout {
  display: grid;
  grid-template-columns: 340px 1fr;
  gap: 18px;
}
@media (max-width: 980px) { .scan-layout { grid-template-columns: 1fr; } }

.section-title {
  font-size: 11px; font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--text-dim);
  margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid var(--border);
}
.btn-row { display: flex; flex-direction: column; gap: 8px; margin-top: 10px; }
.field.inline { display: inline-flex; flex-direction: column; gap: 4px; margin-bottom: 0; }
.filter-row { display: flex; align-items: flex-end; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; }

/* live feed */
.live-feed {
  width: 100%; margin-top: 14px;
  background: var(--bg); border: 1px solid var(--border); border-radius: 10px;
  padding: 10px 14px; max-height: 160px; overflow-y: auto;
}
.live-feed-title { font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-dim); margin-bottom: 8px; }
.feed-item {
  font-family: var(--mono); font-size: 11px; padding: 2px 0;
  border-bottom: 1px solid rgba(255,255,255,0.03); display: flex; gap: 10px; align-items: center;
}
.feed-item .fi-ip { color: var(--cyan); min-width: 115px; }
.feed-item .fi-ms { min-width: 60px; }
.feed-item .fi-status { }

/* results table extras */
.topbar-right { display: flex; align-items: center; gap: 12px; }
th[data-key="cfPop"] { }
.pop-tag {
  font-family: var(--mono); font-size: 11px;
  background: rgba(77,232,255,0.1); color: var(--cyan);
  padding: 2px 7px; border-radius: 4px; border: 1px solid rgba(77,232,255,0.2);
}
.action-btn {
  background: none; border: 1px solid var(--border); color: var(--text-dim);
  padding: 3px 8px; border-radius: 6px; font-size: 11px; cursor: pointer;
  font-family: var(--mono); transition: all .12s;
}
.action-btn:hover { color: var(--cyan); border-color: var(--cyan); }

/* V2Ray panel */
.v2ray-info-box {
  background: rgba(0,230,138,0.05); border: 1px solid rgba(0,230,138,0.2);
  border-radius: 8px; padding: 10px 14px; font-size: 12.5px; margin-bottom: 16px;
  color: var(--text-dim); line-height: 1.6;
}
.v2-link-list { display: flex; flex-direction: column; gap: 10px; }
.v2-link-item {
  background: var(--bg); border: 1px solid var(--border); border-radius: 10px;
  padding: 12px 14px;
}
.v2-link-header {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 8px;
}
.v2-link-meta { font-size: 12px; color: var(--text-dim); font-family: var(--sans); }
.v2-link-meta b { color: var(--text); }
.v2-link-str {
  font-family: var(--mono); font-size: 11px; color: var(--cyan);
  word-break: break-all; background: var(--panel); border-radius: 6px;
  padding: 8px 10px; cursor: pointer; transition: background .12s;
  border: 1px solid var(--border);
}
.v2-link-str:hover { background: var(--panel-2); }
.v2-link-copy-btn {
  background: var(--panel-2); border: 1px solid var(--border);
  color: var(--text-dim); padding: 5px 12px; border-radius: 7px;
  font-size: 12px; cursor: pointer; font-family: var(--sans);
  transition: all .12s; white-space: nowrap;
}
.v2-link-copy-btn:hover { color: var(--green); border-color: var(--green); }
.v2-link-copy-btn.copied { color: var(--green); border-color: var(--green); }
.empty-row-plain { color: var(--text-dim); font-family: var(--sans); font-size: 13px; padding: 30px 10px; text-align: center; }

/* Geo panel */
.geo-lookup-row { display: flex; gap: 10px; margin-bottom: 16px; align-items: flex-end; }
.geo-input {
  flex: 1; background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
  padding: 9px 12px; color: var(--text); font-family: var(--mono); font-size: 13px; outline: none;
  transition: border-color .15s;
}
.geo-input:focus { border-color: var(--cyan); }
.geo-result {
  background: var(--bg); border: 1px solid var(--border); border-radius: 10px;
  padding: 16px; display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px;
}
.geo-field { display: flex; flex-direction: column; gap: 3px; }
.geo-field-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-dim); }
.geo-field-value { font-family: var(--mono); font-size: 13px; color: var(--text); }
.geo-summary-info { font-size: 12.5px; color: var(--text-dim); margin-bottom: 12px; }
.geo-summary { display: flex; flex-wrap: wrap; gap: 10px; }
.geo-country-block {
  background: var(--bg); border: 1px solid var(--border); border-radius: 10px;
  padding: 12px 16px; min-width: 160px;
}
.geo-country-name { font-weight: 700; font-size: 13px; margin-bottom: 8px; }
.geo-pop-list { display: flex; flex-wrap: wrap; gap: 6px; }
.geo-pop-item {
  background: rgba(77,232,255,0.08); color: var(--cyan);
  border: 1px solid rgba(77,232,255,0.2); border-radius: 5px;
  font-family: var(--mono); font-size: 11px; padding: 2px 8px;
}

/* Modal */
.modal-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 100;
  display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px);
}
.modal-overlay.hidden { display: none; }
.modal {
  background: var(--panel); border: 1px solid var(--border); border-radius: 16px;
  padding: 24px; max-width: 560px; width: 90%; position: relative; max-height: 80vh; overflow-y: auto;
}
.modal-close {
  position: absolute; top: 14px; right: 16px;
  background: none; border: none; color: var(--text-dim); font-size: 16px; cursor: pointer;
}
`;
const APP_JS     = `(() => {
  'use strict';

  // ============================================================
  // CFRadar v2.0 — Client-side scanner engine
  // ============================================================

  // ---- state ----
  let mode = 'cf';
  let es = null;
  let results = [];
  let sortKey = 'score';
  let sortDir = 1;
  let currentSid = null;
  let scanRunning = false;
  const blips = [];

  // ---- V2Ray config state ----
  const v2Config = () => ({
    uuid: document.getElementById('v2uuid').value.trim() || generateUUID(),
    proto: document.getElementById('v2proto').value,
    path: document.getElementById('v2path').value || '/',
    net: document.getElementById('v2net').value,
    sni: document.getElementById('v2sni').value || 'speed.cloudflare.com',
    tls: document.getElementById('v2tls').checked,
    port: parseInt(document.getElementById('port').value, 10) || 443,
  });

  // ============================================================
  // UUID generator (RFC 4122 v4)
  // ============================================================
  function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }
  // Pre-fill UUID field once
  document.getElementById('v2uuid').placeholder = generateUUID();

  // ============================================================
  // V2Ray / Xray link builders
  // All these formats are open standards used by Xray-core / v2fly
  // ============================================================

  function buildVlessLink(ip, cfg, remark) {
    // vless://uuid@ip:port?encryption=none&security=tls&sni=...&type=ws&path=...#remark
    const params = new URLSearchParams({
      encryption: 'none',
      security: cfg.tls ? 'tls' : 'none',
      sni: cfg.sni,
      host: cfg.sni,
      type: cfg.net,
      path: cfg.path,
      fp: 'chrome',       // fingerprint — makes it look like real Chrome TLS
      alpn: 'h2,http/1.1',
    });
    if (cfg.net === 'grpc') {
      params.set('serviceName', cfg.path.replace(/^\\//, ''));
      params.delete('path');
    }
    return \`vless://\${cfg.uuid}@\${ip}:\${cfg.port}?\${params.toString()}#\${encodeURIComponent(remark)}\`;
  }

  function buildVmessLink(ip, cfg, remark) {
    // vmess://base64(json)
    const obj = {
      v: '2',
      ps: remark,
      add: ip,
      port: String(cfg.port),
      id: cfg.uuid,
      aid: '0',
      scy: 'auto',
      net: cfg.net,
      type: 'none',
      host: cfg.sni,
      path: cfg.path,
      tls: cfg.tls ? 'tls' : '',
      sni: cfg.sni,
      alpn: 'h2,http/1.1',
      fp: 'chrome',
    };
    return 'vmess://' + btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
  }

  function buildTrojanLink(ip, cfg, remark) {
    // trojan://password@ip:port?sni=...&type=ws&path=...#remark
    // For Trojan, UUID doubles as the password
    const params = new URLSearchParams({
      security: cfg.tls ? 'tls' : 'none',
      sni: cfg.sni,
      host: cfg.sni,
      type: cfg.net,
      path: cfg.path,
      fp: 'chrome',
      alpn: 'h2,http/1.1',
    });
    return \`trojan://\${cfg.uuid}@\${ip}:\${cfg.port}?\${params.toString()}#\${encodeURIComponent(remark)}\`;
  }

  function buildV2Link(ip, cfg, domain, latency) {
    const remark = \`CFRadar | \${domain || ip} | \${latency}ms\`;
    switch (cfg.proto) {
      case 'vmess': return buildVmessLink(ip, cfg, remark);
      case 'trojan': return buildTrojanLink(ip, cfg, remark);
      default: return buildVlessLink(ip, cfg, remark);
    }
  }

  // ============================================================
  // Clash proxy block builder
  // ============================================================
  function buildClashProxy(ip, cfg, domain, idx) {
    const name = \`CFRadar-\${idx + 1}\`;
    const base = {
      name,
      server: ip,
      port: cfg.port,
      'skip-cert-verify': false,
      sni: cfg.sni,
      tls: cfg.tls,
    };
    if (cfg.proto === 'vless') {
      return { ...base, type: 'vless', uuid: cfg.uuid, network: cfg.net,
        'ws-opts': cfg.net === 'ws' ? { path: cfg.path, headers: { Host: cfg.sni } } : undefined };
    }
    if (cfg.proto === 'trojan') {
      return { ...base, type: 'trojan', password: cfg.uuid, network: cfg.net,
        'ws-opts': cfg.net === 'ws' ? { path: cfg.path, headers: { Host: cfg.sni } } : undefined };
    }
    // vmess
    return { ...base, type: 'vmess', uuid: cfg.uuid, alterId: 0,
      cipher: 'auto', network: cfg.net,
      'ws-opts': cfg.net === 'ws' ? { path: cfg.path, headers: { Host: cfg.sni } } : undefined };
  }

  // ============================================================
  // sing-box outbound builder
  // ============================================================
  function buildSingboxOutbound(ip, cfg, domain, idx) {
    const tag = \`cfradar-\${idx + 1}\`;
    const transport = cfg.net === 'ws' ? {
      type: 'ws', path: cfg.path, headers: { Host: cfg.sni },
    } : cfg.net === 'grpc' ? { type: 'grpc', service_name: cfg.path.replace(/^\\//, '') }
      : cfg.net === 'h2' ? { type: 'http', path: cfg.path, host: [cfg.sni] } : undefined;

    const tls = cfg.tls ? {
      enabled: true, server_name: cfg.sni,
      utls: { enabled: true, fingerprint: 'chrome' },
    } : undefined;

    const base = { tag, server: ip, server_port: cfg.port };
    if (transport) base.transport = transport;
    if (tls) base.tls = tls;

    if (cfg.proto === 'vless') return { ...base, type: 'vless', uuid: cfg.uuid, flow: '' };
    if (cfg.proto === 'trojan') return { ...base, type: 'trojan', password: cfg.uuid };
    return { ...base, type: 'vmess', uuid: cfg.uuid, alter_id: 0, security: 'auto' };
  }

  // ============================================================
  // Timeout warning
  // ============================================================
  const timeoutInput = document.getElementById('timeout');
  const timeoutHint = document.getElementById('timeoutHint');
  function checkTimeoutHint() {
    const v = parseInt(timeoutInput.value, 10) || 0;
    if (v < 600) {
      timeoutHint.textContent = \`⚠ \${v}ms is very low — Iran round-trips are often 100–300ms+. Use 1000–1500ms.\`;
      timeoutHint.classList.add('warn');
    } else { timeoutHint.textContent = ''; timeoutHint.classList.remove('warn'); }
  }
  timeoutInput.addEventListener('input', checkTimeoutHint);
  checkTimeoutHint();

  // ============================================================
  // Main nav tabs
  // ============================================================
  document.querySelectorAll('.main-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.main-tab').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.main-panel').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('panel' + capitalize(btn.dataset.panel)).classList.add('active');
    });
  });
  function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  // ============================================================
  // Scan mode tabs
  // ============================================================
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      mode = btn.dataset.mode;
      document.getElementById('tabCf').classList.toggle('hidden', mode !== 'cf');
      document.getElementById('tabDomains').classList.toggle('hidden', mode !== 'domains');
    });
  });

  // ============================================================
  // Radar canvas
  // ============================================================
  const canvas = document.getElementById('radar');
  const ctx = canvas.getContext('2d');
  const brandSweep = document.getElementById('brandSweep');
  let sweepAngle = 0;
  const cx = canvas.width / 2, cy = canvas.height / 2, R = canvas.width / 2 - 14;
  const statusColor = { clean: '#00e68a', warn: '#ffb020', dead: '#ff4d5e' };

  function statusOf(r) {
    if (!r || r.successes === 0) return 'dead';
    if (r.clean) return 'clean';
    return 'warn';
  }

  function addBlip(status) {
    blips.push({ angle: Math.random() * Math.PI * 2, dist: 0.15 + Math.random() * 0.82, status, life: 1 });
    if (blips.length > 220) blips.shift();
  }

  function drawRadar() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.strokeStyle = 'rgba(77,232,255,0.18)'; ctx.lineWidth = 1;
    for (let i = 1; i <= 4; i++) {
      ctx.beginPath(); ctx.arc(cx, cy, (R / 4) * i, 0, Math.PI * 2); ctx.stroke();
    }
    ctx.beginPath();
    ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy);
    ctx.moveTo(cx, cy - R); ctx.lineTo(cx, cy + R);
    ctx.stroke();
    ctx.save(); ctx.beginPath(); ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, R, sweepAngle - 0.5, sweepAngle); ctx.closePath();
    ctx.fillStyle = 'rgba(0,230,138,0.12)'; ctx.fill(); ctx.restore();
    ctx.beginPath(); ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(sweepAngle) * R, cy + Math.sin(sweepAngle) * R);
    ctx.strokeStyle = '#00e68a'; ctx.lineWidth = 2;
    ctx.shadowColor = '#00e68a'; ctx.shadowBlur = 8; ctx.stroke(); ctx.shadowBlur = 0;
    for (let i = blips.length - 1; i >= 0; i--) {
      const b = blips[i];
      const x = cx + Math.cos(b.angle) * b.dist * R;
      const y = cy + Math.sin(b.angle) * b.dist * R;
      ctx.beginPath(); ctx.fillStyle = statusColor[b.status];
      ctx.globalAlpha = Math.max(b.life, 0.12);
      ctx.arc(x, y, b.status === 'clean' ? 3.4 : 2.6, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = 1; b.life -= 0.0035;
      if (b.life <= 0.1 && Math.random() < 0.02) blips.splice(i, 1);
    }
    ctx.beginPath(); ctx.fillStyle = '#4de8ff'; ctx.arc(cx, cy, 4, 0, Math.PI * 2); ctx.fill();
    sweepAngle += 0.018;
    if (sweepAngle > Math.PI * 2) sweepAngle -= Math.PI * 2;
    const bx = 20 + Math.cos(sweepAngle) * 18;
    const by = 20 + Math.sin(sweepAngle) * 18;
    brandSweep.setAttribute('x2', bx.toFixed(1));
    brandSweep.setAttribute('y2', by.toFixed(1));
    requestAnimationFrame(drawRadar);
  }
  requestAnimationFrame(drawRadar);

  // ============================================================
  // Status pill
  // ============================================================
  function setStatus(state, text) {
    const pill = document.getElementById('statusPill');
    pill.classList.remove('running', 'done');
    if (state) pill.classList.add(state);
    document.getElementById('statusText').textContent = text;
  }

  // ============================================================
  // Live feed
  // ============================================================
  const liveFeedBody = document.getElementById('liveFeedBody');
  function addFeedItem(r) {
    const status = statusOf(r);
    const div = document.createElement('div');
    div.className = 'feed-item';
    const msStr = r.medianMs != null ? r.medianMs + 'ms' : '—';
    const col = status === 'clean' ? 'var(--green)' : status === 'warn' ? 'var(--amber)' : 'var(--red)';
    div.innerHTML = \`<span class="fi-ip">\${r.ip}</span>
      <span class="fi-ms" style="color:\${col}">\${msStr}</span>
      <span class="fi-status" style="color:\${col}">\${status}</span>
      \${r.cfPop ? \`<span class="pop-tag">\${r.cfPop}</span>\` : ''}\`;
    liveFeedBody.prepend(div);
    if (liveFeedBody.children.length > 60) liveFeedBody.lastChild.remove();
  }

  // ============================================================
  // Table rendering
  // ============================================================
  let filterClean = true;
  let filterIp = '';
  let filterMaxMs = null;

  function latClass(ms) {
    if (ms === null || ms === undefined) return 'lat-bad';
    if (ms < 150) return 'lat-good';
    if (ms < 400) return 'lat-mid';
    return 'lat-bad';
  }
  function tagHtml(status) {
    if (status === 'clean') return '<span class="tag clean">● Clean</span>';
    if (status === 'warn') return '<span class="tag warn">● Unstable</span>';
    return '<span class="tag dead">● Dead</span>';
  }
  function cfTlsHtml(r) {
    if (r.cfVerified) return '<span class="tag clean">✓ CF verified</span>';
    if (r.tlsOk) return '<span class="tag warn">TLS ok</span>';
    return '<span class="tag dead">—</span>';
  }

  function applyFilters(list) {
    return list.filter((r) => {
      if (filterClean && !r.clean) return false;
      if (filterIp && !r.ip.includes(filterIp)) return false;
      if (filterMaxMs !== null && (r.medianMs == null || r.medianMs > filterMaxMs)) return false;
      return true;
    });
  }

  function renderTable() {
    const body = document.getElementById('resultsBody');
    const filtered = applyFilters(results);
    document.getElementById('resultsCount').textContent = \`(\${filtered.length} / \${results.length})\`;

    if (filtered.length === 0) {
      body.innerHTML = \`<tr class="empty-row"><td colspan="13">\${results.length ? 'No results match current filters.' : 'No scan yet — go to the Scan tab.'}</td></tr>\`;
      return;
    }
    const sorted = [...filtered].sort((a, b) => {
      const map = { rank: 'score', ip: 'ip', domain: 'domain', avgMs: 'avgMs', medianMs: 'medianMs',
        jitterMs: 'jitterMs', lossPct: 'lossPct', status: 'score', cfPop: 'cfPop', throughputKbps: 'throughputKbps' };
      const k = map[sortKey] || sortKey;
      let av = a[k], bv = b[k];
      if (av === null || av === undefined) av = Infinity;
      if (bv === null || bv === undefined) bv = Infinity;
      if (av < bv) return -1 * sortDir;
      if (av > bv) return 1 * sortDir;
      return 0;
    });
    body.innerHTML = sorted.map((r, i) => {
      const status = statusOf(r);
      const rangeClass = r.inTargetRange === true ? 'in-range' : (r.inTargetRange === false ? 'out-range' : '');
      return \`<tr class="\${rangeClass}">
        <td>\${i + 1}</td>
        <td class="lat-good" style="font-family:var(--mono)">\${r.ip}</td>
        <td>\${r.domain || '<span class="muted">—</span>'}</td>
        <td class="\${latClass(r.avgMs)}">\${r.avgMs ?? '—'}</td>
        <td class="\${latClass(r.medianMs)}">\${r.medianMs ?? '—'}</td>
        <td>\${r.icmpMs ?? '<span class="muted">—</span>'}</td>
        <td>\${r.jitterMs}</td>
        <td>\${r.lossPct}</td>
        <td>\${cfTlsHtml(r)}</td>
        <td>\${r.cfPop ? \`<span class="pop-tag">\${r.cfPop}</span>\` : '<span class="muted">—</span>'}</td>
        <td>\${r.throughputKbps != null ? r.throughputKbps : '<span class="muted">—</span>'}</td>
        <td>\${tagHtml(status)}</td>
        <td>
          <button class="action-btn" data-action="v2" data-ip="\${r.ip}" data-domain="\${r.domain || ''}" data-ms="\${r.medianMs || ''}">V2</button>
          <button class="action-btn" data-action="detail" data-idx="\${i}">Info</button>
        </td>
      </tr>\`;
    }).join('');
  }

  document.querySelectorAll('thead th[data-key]').forEach((th) => {
    th.addEventListener('click', () => {
      const k = th.dataset.key;
      if (sortKey === k) sortDir *= -1; else { sortKey = k; sortDir = 1; }
      renderTable();
    });
  });

  // Filter controls
  document.getElementById('filterClean').addEventListener('change', (e) => {
    filterClean = e.target.checked; renderTable();
  });
  document.getElementById('filterIp').addEventListener('input', (e) => {
    filterIp = e.target.value.trim(); renderTable();
  });
  document.getElementById('filterMaxMs').addEventListener('input', (e) => {
    filterMaxMs = e.target.value !== '' ? parseFloat(e.target.value) : null; renderTable();
  });
  document.getElementById('clearFilter').addEventListener('click', () => {
    document.getElementById('filterClean').checked = true; filterClean = true;
    document.getElementById('filterIp').value = ''; filterIp = '';
    document.getElementById('filterMaxMs').value = ''; filterMaxMs = null;
    renderTable();
  });

  // Table row actions (delegated)
  document.getElementById('resultsBody').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    if (btn.dataset.action === 'v2') {
      const ip = btn.dataset.ip;
      const domain = btn.dataset.domain;
      const ms = btn.dataset.ms;
      const cfg = v2Config();
      const link = buildV2Link(ip, cfg, domain, ms);
      showModal(\`
        <div class="section-title">V2Ray Link — \${ip}</div>
        <div class="v2-link-str" id="singleLinkStr">\${link}</div>
        <div style="margin-top:12px;display:flex;gap:8px;">
          <button class="v2-link-copy-btn" id="singleCopyBtn">⎘ Copy Link</button>
        </div>
      \`);
      document.getElementById('singleCopyBtn').addEventListener('click', () => {
        copyText(link);
        document.getElementById('singleCopyBtn').textContent = '✓ Copied!';
        document.getElementById('singleCopyBtn').classList.add('copied');
      });
    }
    if (btn.dataset.action === 'detail') {
      const r = applyFilters(results)[parseInt(btn.dataset.idx)];
      if (!r) return;
      showModal(\`
        <div class="section-title">IP Details — \${r.ip}</div>
        <div class="geo-result" style="margin-top:0;grid-template-columns:1fr 1fr;">
          \${detailField('IP', r.ip)}
          \${detailField('Domain', r.domain || '—')}
          \${detailField('Avg Latency', r.avgMs != null ? r.avgMs + ' ms' : '—')}
          \${detailField('Median Latency', r.medianMs != null ? r.medianMs + ' ms' : '—')}
          \${detailField('ICMP Ping', r.icmpMs != null ? r.icmpMs + ' ms' : '—')}
          \${detailField('Jitter', r.jitterMs + ' ms')}
          \${detailField('Loss %', r.lossPct + '%')}
          \${detailField('Passes', r.successes + ' / ' + r.attempts)}
          \${detailField('TLS OK', r.tlsOk ? '✓ Yes' : '✗ No')}
          \${detailField('CF Verified', r.cfVerified ? '✓ Yes' : '✗ No')}
          \${detailField('CF PoP', r.cfPop || '—')}
          \${detailField('HTTP Status', r.httpStatus || '—')}
          \${detailField('Throughput', r.throughputKbps != null ? r.throughputKbps + ' KB/s' : '—')}
          \${detailField('Status', statusOf(r))}
          \${detailField('Score', Math.round(r.score * 10) / 10)}
        </div>
      \`);
    }
  });

  function detailField(label, value) {
    return \`<div class="geo-field"><div class="geo-field-label">\${label}</div><div class="geo-field-value">\${value}</div></div>\`;
  }

  // ============================================================
  // Stats
  // ============================================================
  function updateStats() {
    document.getElementById('statTotal').textContent = results.length;
    const clean = results.filter((r) => statusOf(r) === 'clean');
    const dead = results.filter((r) => statusOf(r) === 'dead');
    document.getElementById('statClean').textContent = clean.length;
    document.getElementById('statDead').textContent = dead.length;
    if (clean.length) {
      const best = Math.min(...clean.map((r) => r.medianMs ?? Infinity));
      document.getElementById('statAvg').textContent = isFinite(best) ? best.toFixed(0) : '–';
    } else { document.getElementById('statAvg').textContent = '–'; }
    // Update nav badges
    document.getElementById('navResultsBadge').textContent = results.length || '';
    const cleanCount = clean.length;
    document.getElementById('navV2rayBadge').textContent = cleanCount || '';
  }

  // ============================================================
  // V2Ray panel rendering
  // ============================================================
  function renderV2Panel() {
    const cfg = v2Config();
    const cleanIps = results.filter((r) => r.clean);
    const v2List = document.getElementById('v2LinkList');
    document.getElementById('v2Count').textContent = \`(\${cleanIps.length})\`;
    if (cleanIps.length === 0) {
      v2List.innerHTML = '<div class="empty-row-plain">Run a scan first. Clean IPs will appear here as ready-to-use V2Ray links.</div>';
      return;
    }
    v2List.innerHTML = cleanIps.map((r, i) => {
      const link = buildV2Link(r.ip, cfg, r.domain, r.medianMs || '?');
      const pop = r.cfPop ? \`<span class="pop-tag">\${r.cfPop}</span>\` : '';
      return \`<div class="v2-link-item">
        <div class="v2-link-header">
          <div class="v2-link-meta">
            <b>\${r.ip}</b>\${r.domain ? ' · ' + r.domain : ''}
            \${pop}
            · <span style="color:var(--green)">\${r.medianMs ?? '?'}ms</span>
            · \${cfg.proto.toUpperCase()} / \${cfg.net} / port \${cfg.port}
          </div>
          <button class="v2-link-copy-btn" data-link="\${encodeURIComponent(link)}">⎘ Copy</button>
        </div>
        <div class="v2-link-str" data-link="\${encodeURIComponent(link)}">\${link}</div>
      </div>\`;
    }).join('');
  }

  document.getElementById('v2LinkList').addEventListener('click', (e) => {
    const btn = e.target.closest('.v2-link-copy-btn');
    const str = e.target.closest('.v2-link-str');
    if (btn) {
      copyText(decodeURIComponent(btn.dataset.link));
      btn.textContent = '✓ Copied!'; btn.classList.add('copied');
      setTimeout(() => { btn.textContent = '⎘ Copy'; btn.classList.remove('copied'); }, 1800);
    }
    if (str) {
      copyText(decodeURIComponent(str.dataset.link));
    }
  });

  document.getElementById('copyAllV2').addEventListener('click', () => {
    const cfg = v2Config();
    const links = results.filter((r) => r.clean)
      .map((r) => buildV2Link(r.ip, cfg, r.domain, r.medianMs || '?')).join('\\n');
    copyText(links);
    const btn = document.getElementById('copyAllV2');
    btn.textContent = '✓ Copied all!';
    setTimeout(() => { btn.textContent = '⎘ Copy All'; }, 2000);
  });

  document.getElementById('downloadV2').addEventListener('click', () => {
    const cfg = v2Config();
    const links = results.filter((r) => r.clean)
      .map((r) => buildV2Link(r.ip, cfg, r.domain, r.medianMs || '?')).join('\\n');
    downloadFile(links, 'cfradar-v2ray-links.txt', 'text/plain');
  });

  document.getElementById('downloadClash').addEventListener('click', () => {
    const cfg = v2Config();
    const proxies = results.filter((r) => r.clean)
      .map((r, i) => buildClashProxy(r.ip, cfg, r.domain, i));
    const names = proxies.map((p) => p.name);
    const clashConfig = {
      proxies,
      'proxy-groups': [{
        name: 'CFRadar', type: 'url-test', proxies: names,
        url: 'http://www.gstatic.com/generate_204', interval: 300, tolerance: 50,
      }],
      rules: ['MATCH,CFRadar'],
    };
    // Simple YAML serializer (no dependency)
    downloadFile(toYaml(clashConfig), 'cfradar-clash.yaml', 'text/yaml');
  });

  document.getElementById('downloadSingbox').addEventListener('click', () => {
    const cfg = v2Config();
    const outbounds = results.filter((r) => r.clean)
      .map((r, i) => buildSingboxOutbound(r.ip, cfg, r.domain, i));
    const tags = outbounds.map((o) => o.tag);
    const singboxConfig = {
      outbounds: [
        { type: 'urltest', tag: 'auto', outbounds: tags, url: 'https://www.gstatic.com/generate_204', interval: '5m', tolerance: 50 },
        ...outbounds,
        { type: 'direct', tag: 'direct' },
        { type: 'block', tag: 'block' },
      ],
      route: { rules: [{ outbound: 'auto' }], final: 'auto' },
    };
    downloadFile(JSON.stringify(singboxConfig, null, 2), 'cfradar-singbox.json', 'application/json');
  });

  // ============================================================
  // Simple YAML emitter (enough for Clash config)
  // ============================================================
  function toYaml(obj, indent = 0) {
    const pad = '  '.repeat(indent);
    if (Array.isArray(obj)) {
      return obj.map((v) => \`\${pad}- \${toYamlValue(v, indent)}\`).join('\\n');
    }
    return Object.entries(obj).filter(([, v]) => v !== undefined && v !== null)
      .map(([k, v]) => {
        if (typeof v === 'object' && !Array.isArray(v) && v !== null) {
          return \`\${pad}\${k}:\\n\${toYaml(v, indent + 1)}\`;
        }
        if (Array.isArray(v)) {
          return \`\${pad}\${k}:\\n\${v.map((i) => \`\${'  '.repeat(indent + 1)}- \${toYamlValue(i, indent + 1)}\`).join('\\n')}\`;
        }
        return \`\${pad}\${k}: \${toYamlValue(v, indent)}\`;
      }).join('\\n');
  }
  function toYamlValue(v, indent) {
    if (typeof v === 'string') return \`"\${v.replace(/"/g, '\\\\"')}"\`;
    if (typeof v === 'boolean' || typeof v === 'number') return String(v);
    if (typeof v === 'object' && v !== null) return '\\n' + toYaml(v, indent + 1);
    return String(v);
  }

  // ============================================================
  // Geo panel
  // ============================================================
  document.getElementById('geoLookupBtn').addEventListener('click', () => {
    const ip = document.getElementById('geoIpInput').value.trim();
    if (!ip) return;
    doGeoLookup(ip);
  });
  document.getElementById('geoIpInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('geoLookupBtn').click();
  });

  async function doGeoLookup(ip) {
    const resultDiv = document.getElementById('geoResult');
    resultDiv.innerHTML = '<div style="color:var(--text-dim);font-size:12px;">Looking up…</div>';
    resultDiv.classList.remove('hidden');
    try {
      const resp = await fetch(\`http://ip-api.com/json/\${ip}?fields=status,country,countryCode,city,regionName,isp,org,as,lat,lon,timezone\`);
      const data = await resp.json();
      if (data.status !== 'success') throw new Error(data.message || 'lookup failed');
      resultDiv.innerHTML = \`
        \${geoField('IP', ip)}
        \${geoField('Country', \`\${data.country} (\${data.countryCode})\`)}
        \${geoField('City', data.city)}
        \${geoField('Region', data.regionName)}
        \${geoField('ISP', data.isp)}
        \${geoField('Org', data.org)}
        \${geoField('ASN', data.as)}
        \${geoField('Timezone', data.timezone)}
        \${geoField('Coordinates', \`\${data.lat}, \${data.lon}\`)}
      \`;
    } catch (err) {
      resultDiv.innerHTML = \`<div style="color:var(--red);font-size:12px;">Lookup failed: \${err.message}</div>\`;
    }
  }

  function geoField(label, value) {
    return \`<div class="geo-field"><div class="geo-field-label">\${label}</div><div class="geo-field-value">\${value || '—'}</div></div>\`;
  }

  function renderGeoSummary() {
    const clean = results.filter((r) => r.clean && r.cfPop);
    const geoDiv = document.getElementById('geoSummary');
    if (clean.length === 0) {
      geoDiv.innerHTML = '<div class="empty-row-plain">Run a scan to see geo distribution of clean IPs.</div>';
      return;
    }
    const pops = {};
    clean.forEach((r) => {
      const pop = r.cfPop || 'Unknown';
      if (!pops[pop]) pops[pop] = [];
      pops[pop].push(r.ip);
    });
    const sorted = Object.entries(pops).sort((a, b) => b[1].length - a[1].length);
    geoDiv.innerHTML = sorted.map(([pop, ips]) => \`
      <div class="geo-country-block">
        <div class="geo-country-name">\${pop}</div>
        <div style="font-size:11px;color:var(--text-dim);margin-bottom:6px;">\${ips.length} clean IP\${ips.length !== 1 ? 's' : ''}</div>
        <div class="geo-pop-list">
          \${ips.slice(0, 6).map((ip) => \`<span class="geo-pop-item">\${ip}</span>\`).join('')}
          \${ips.length > 6 ? \`<span class="geo-pop-item">+\${ips.length - 6}</span>\` : ''}
        </div>
      </div>
    \`).join('');
  }

  // ============================================================
  // Scan trigger
  // ============================================================
  const startBtn = document.getElementById('startBtn');
  const stopBtn = document.getElementById('stopBtn');

  function buildUrl() {
    currentSid = 'sid-' + Math.random().toString(36).slice(2);
    const params = new URLSearchParams({
      mode,
      port: document.getElementById('port').value,
      passes: document.getElementById('passes').value,
      timeout: document.getElementById('timeout').value,
      workers: document.getElementById('workers').value,
      sid: currentSid,
    });
    const tMin = document.getElementById('targetMin').value;
    const tMax = document.getElementById('targetMax').value;
    if (tMin !== '') params.set('targetMin', tMin);
    if (tMax !== '') params.set('targetMax', tMax);
    params.set('icmp', document.getElementById('useIcmp').checked ? '1' : '0');
    if (mode === 'cf') {
      params.set('count', document.getElementById('cfCount').value);
      params.set('sni', document.getElementById('cfSni').value || 'speed.cloudflare.com');
    } else {
      params.set('source', document.getElementById('domainsSource').value);
      params.set('resolveDns', document.getElementById('resolveDns').checked ? '1' : '0');
      params.set('count', '0');
    }
    return '/api/scan-stream?' + params.toString();
  }

  startBtn.addEventListener('click', () => {
    results = []; blips.length = 0;
    liveFeedBody.innerHTML = '';
    renderTable(); updateStats();
    document.getElementById('progressFill').style.width = '0%';
    document.getElementById('progressText').textContent = 'Preparing…';
    startBtn.disabled = true; scanRunning = true;
    stopBtn.classList.remove('hidden');
    setStatus('running', 'Scanning…');
    let scanFinished = false;
    if (es) es.close();
    es = new EventSource(buildUrl());

    es.addEventListener('info', (e) => {
      const d = JSON.parse(e.data);
      document.getElementById('progressText').textContent = d.message;
    });
    es.addEventListener('resolveProgress', (e) => {
      const d = JSON.parse(e.data);
      const pct = d.total ? (d.done / d.total) * 100 : 0;
      document.getElementById('progressFill').style.width = pct + '%';
      document.getElementById('progressText').textContent = \`Resolving DNS: \${d.done} / \${d.total}\`;
    });
    es.addEventListener('start', (e) => {
      const d = JSON.parse(e.data);
      document.getElementById('progressText').textContent = \`0 / \${d.total}\`;
    });
    es.addEventListener('result', (e) => {
      const r = JSON.parse(e.data);
      results.push(r);
      addBlip(statusOf(r));
      addFeedItem(r);
      updateStats();
      if (results.length % 5 === 0 || results.length < 30) renderTable();
    });
    es.addEventListener('progress', (e) => {
      const d = JSON.parse(e.data);
      const pct = d.total ? (d.done / d.total) * 100 : 0;
      document.getElementById('progressFill').style.width = pct + '%';
      document.getElementById('progressText').textContent = \`\${d.done} / \${d.total}\`;
    });
    es.addEventListener('done', (e) => {
      const d = JSON.parse(e.data);
      scanFinished = true; scanRunning = false;
      renderTable(); renderV2Panel(); renderGeoSummary(); updateStats();
      setStatus('done', \`Done — \${d.clean} clean of \${d.total}\`);
      startBtn.disabled = false; stopBtn.classList.add('hidden'); es.close();
    });
    es.addEventListener('scanerror', (e) => {
      const d = JSON.parse(e.data);
      scanFinished = true; scanRunning = false;
      setStatus(null, \`Scan error: \${d.message}\`);
      startBtn.disabled = false; stopBtn.classList.add('hidden'); es.close();
    });
    es.addEventListener('error', () => {
      if (scanFinished) return;
      setStatus(null, 'Connection error');
      startBtn.disabled = false; stopBtn.classList.add('hidden'); scanRunning = false;
    });
  });

  stopBtn.addEventListener('click', () => {
    if (es) es.close();
    startBtn.disabled = false; stopBtn.classList.add('hidden');
    scanRunning = false; setStatus(null, 'Stopped');
    renderTable(); renderV2Panel(); renderGeoSummary();
  });

  // ============================================================
  // Export
  // ============================================================
  document.querySelectorAll('.btn-export[data-fmt]').forEach((btn) => {
    btn.addEventListener('click', () => {
      if (!currentSid) return;
      const fmt = btn.dataset.fmt;
      if (fmt === 'v2ray') {
        const cfg = v2Config();
        const links = results.filter((r) => r.clean)
          .map((r) => buildV2Link(r.ip, cfg, r.domain, r.medianMs || '?')).join('\\n');
        downloadFile(links, 'cfradar-v2ray-links.txt', 'text/plain');
      } else if (fmt === 'clash') {
        const cfg = v2Config();
        const proxies = results.filter((r) => r.clean).map((r, i) => buildClashProxy(r.ip, cfg, r.domain, i));
        const names = proxies.map((p) => p.name);
        const config = { proxies, 'proxy-groups': [{ name: 'CFRadar', type: 'url-test', proxies: names, url: 'http://www.gstatic.com/generate_204', interval: 300 }], rules: ['MATCH,CFRadar'] };
        downloadFile(toYaml(config), 'cfradar-clash.yaml', 'text/yaml');
      } else {
        window.open(\`/api/export?sid=\${currentSid}&format=\${fmt}\`, '_blank');
      }
    });
  });

  // ============================================================
  // Modal
  // ============================================================
  function showModal(html) {
    document.getElementById('modalContent').innerHTML = html;
    document.getElementById('modalOverlay').classList.remove('hidden');
  }
  document.getElementById('modalClose').addEventListener('click', () => {
    document.getElementById('modalOverlay').classList.add('hidden');
  });
  document.getElementById('modalOverlay').addEventListener('click', (e) => {
    if (e.target === document.getElementById('modalOverlay'))
      document.getElementById('modalOverlay').classList.add('hidden');
  });

  // ============================================================
  // Utilities
  // ============================================================
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
    } else { fallbackCopy(text); }
  }
  function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
  }
  function downloadFile(content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

})();
`;
// BUILD_INJECT_END
