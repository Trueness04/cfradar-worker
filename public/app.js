(() => {
  'use strict';

  // ---------------- state ----------------
  let mode = 'cf';
  let es = null;
  let results = [];
  let sortKey = 'score';
  let sortDir = 1;
  let currentSid = null;
  const blips = []; // {angle, dist, status, life}

  // ---------------- timeout sanity warning ----------------
  // A too-low timeout is the #1 cause of "good IPs showing as Unstable":
  // every TCP/TLS attempt that doesn't make it back within this window
  // counts as a failed pass, which tanks loss% and blocks "clean" even for
  // genuinely good IPs. Warn the user before they waste a whole scan on it.
  const timeoutInput = document.getElementById('timeout');
  const timeoutHint = document.getElementById('timeoutHint');
  function checkTimeoutHint() {
    const v = parseInt(timeoutInput.value, 10) || 0;
    if (v < 600) {
      timeoutHint.textContent = `⚠ ${v}ms is very low — real round-trips from Iran are often 100-300ms+. This will make good IPs look "Unstable" or "Dead" even when they're fine. 1000-1500ms is recommended.`;
      timeoutHint.classList.add('warn');
    } else {
      timeoutHint.textContent = '';
      timeoutHint.classList.remove('warn');
    }
  }
  timeoutInput.addEventListener('input', checkTimeoutHint);
  checkTimeoutHint();

  // ---------------- VPN/proxy gate ----------------
  // Scan results only mean anything if they reflect the real ISP path.
  // If the machine is behind a VPN, or a system-wide proxy, latency and
  // DPI-bypass numbers describe the VPN's network, not the user's.
  let netState = { checked: false, flagged: false };
  async function checkNetwork() {
    const pill = document.getElementById('netPill');
    const dot = document.getElementById('netDot');
    const text = document.getElementById('netText');
    pill.classList.remove('warn', 'bad', 'done');
    text.textContent = 'Checking connection…';
    try {
      const r = await fetch('/api/network-check');
      const d = await r.json();
      netState = d;
      if (!d.ok || !d.checked) {
        pill.classList.add('warn');
        text.textContent = 'Could not verify connection';
        return d;
      }
      if (d.flagged) {
        pill.classList.add('bad');
        text.textContent = `VPN/Proxy detected (${d.isp || d.org || 'unknown'}) — turn it off`;
      } else {
        pill.classList.add('done');
        text.textContent = `Direct connection — ${d.isp || d.country || 'OK'}`;
      }
      return d;
    } catch (_) {
      netState = { checked: false, flagged: false };
      pill.classList.add('warn');
      text.textContent = 'Could not verify connection';
      return netState;
    }
  }
  checkNetwork();

  // ---------------- tab switching ----------------
  const TAB_BODY_IDS = {
    cf: 'tabCf', domains: 'tabDomains', v2ray: 'tabV2ray',
    proxy: 'tabProxy', proxyscrape: 'tabProxyscrape',
  };
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      mode = btn.dataset.mode;
      Object.entries(TAB_BODY_IDS).forEach(([m, id]) => {
        document.getElementById(id).classList.toggle('hidden', mode !== m);
      });
      document.getElementById('top3Box').classList.add('hidden');
    });
  });

  // ---------------- radar canvas ----------------
  const canvas = document.getElementById('radar');
  const ctx = canvas.getContext('2d');
  const brandSweep = document.getElementById('brandSweep');
  let sweepAngle = 0;
  const cx = canvas.width / 2, cy = canvas.height / 2, R = canvas.width / 2 - 14;

  function statusOf(r) {
    if (r.successes === 0) return 'dead';
    if (r.clean) return 'clean';
    return 'warn';
  }
  const statusColor = { clean: '#00e68a', warn: '#ffb020', dead: '#ff4d5e' };

  function addBlip(status) {
    blips.push({
      angle: Math.random() * Math.PI * 2,
      dist: 0.15 + Math.random() * 0.82,
      status,
      life: 1,
    });
    if (blips.length > 220) blips.shift();
  }

  function drawRadar() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // rings
    ctx.strokeStyle = 'rgba(77,232,255,0.18)';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 4; i++) {
      ctx.beginPath();
      ctx.arc(cx, cy, (R / 4) * i, 0, Math.PI * 2);
      ctx.stroke();
    }
    // crosshair
    ctx.beginPath();
    ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy);
    ctx.moveTo(cx, cy - R); ctx.lineTo(cx, cy + R);
    ctx.stroke();

    // sweep gradient
    const grad = ctx.createConicGradient
      ? ctx.createConicGradient(sweepAngle - Math.PI / 2, cx, cy)
      : null;
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, R, sweepAngle - 0.5, sweepAngle);
    ctx.closePath();
    ctx.fillStyle = 'rgba(0,230,138,0.12)';
    ctx.fill();
    ctx.restore();

    // sweep line
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(sweepAngle) * R, cy + Math.sin(sweepAngle) * R);
    ctx.strokeStyle = '#00e68a';
    ctx.lineWidth = 2;
    ctx.shadowColor = '#00e68a';
    ctx.shadowBlur = 8;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // blips
    for (let i = blips.length - 1; i >= 0; i--) {
      const b = blips[i];
      const x = cx + Math.cos(b.angle) * b.dist * R;
      const y = cy + Math.sin(b.angle) * b.dist * R;
      ctx.beginPath();
      ctx.fillStyle = statusColor[b.status];
      ctx.globalAlpha = Math.max(b.life, 0.12);
      ctx.arc(x, y, b.status === 'clean' ? 3.4 : 2.6, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = 1;
      b.life -= 0.0035;
      if (b.life <= 0.1 && Math.random() < 0.02) blips.splice(i, 1);
    }

    // center dot
    ctx.beginPath();
    ctx.fillStyle = '#4de8ff';
    ctx.arc(cx, cy, 4, 0, Math.PI * 2);
    ctx.fill();

    sweepAngle += 0.018;
    if (sweepAngle > Math.PI * 2) sweepAngle -= Math.PI * 2;

    // small brand radar sync
    const bx = 20 + Math.cos(sweepAngle) * 18;
    const by = 20 + Math.sin(sweepAngle) * 18;
    brandSweep.setAttribute('x2', bx.toFixed(1));
    brandSweep.setAttribute('y2', by.toFixed(1));

    requestAnimationFrame(drawRadar);
  }
  requestAnimationFrame(drawRadar);

  // ---------------- status pill ----------------
  function setStatus(state, text) {
    const pill = document.getElementById('statusPill');
    pill.classList.remove('running', 'done');
    if (state) pill.classList.add(state);
    document.getElementById('statusText').textContent = text;
  }

  // ---------------- table rendering ----------------
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
    if (r.cfVerified) return '<span class="tag clean">✓ verified</span>';
    if (r.tlsOk) return '<span class="tag warn">TLS ok, no CF</span>';
    return '<span class="tag dead">—</span>';
  }
  function kindHtml(r) {
    const k = r.kind || (r.domain && r.domain !== r.ip ? 'domain' : 'cf-ip');
    return `<span class="tag kind-${k}">${k}</span>`;
  }
  function dpiHtml(r) {
    if (r.fragTlsOk === null || r.fragTlsOk === undefined) return '<span class="muted">—</span>';
    if (r.dpiBypass) return '<span class="tag warn">⚡ bypass via frag</span>';
    if (r.tlsOk) return '<span class="muted">n/a (direct OK)</span>';
    if (r.fragTlsOk === false) return '<span class="tag dead">blocked both</span>';
    return '<span class="muted">—</span>';
  }

  function renderTable() {
    const body = document.getElementById('resultsBody');
    document.getElementById('resultsCount').textContent = `(${results.length})`;
    if (results.length === 0) {
      body.innerHTML = '<tr class="empty-row"><td colspan="12">No scan has been run yet — start from the panel on the right.</td></tr>';
      return;
    }
    const sorted = [...results].sort((a, b) => {
      let av = a[sortKey], bv = b[sortKey];
      if (av === null || av === undefined) av = Infinity;
      if (bv === null || bv === undefined) bv = Infinity;
      if (av < bv) return -1 * sortDir;
      if (av > bv) return 1 * sortDir;
      return 0;
    });
    body.innerHTML = sorted.map((r, i) => {
      const status = statusOf(r);
      const rangeClass = r.inTargetRange === true ? 'in-range' : (r.inTargetRange === false ? 'out-range' : '');
      return `<tr class="${rangeClass}">
        <td>${i + 1}</td>
        <td>${kindHtml(r)}</td>
        <td>${r.ip}</td>
        <td>${r.domain || '<span class="muted">—</span>'}</td>
        <td class="${latClass(r.avgMs)}">${r.avgMs ?? '—'}</td>
        <td>${r.icmpMs ?? '<span class="muted">—</span>'}</td>
        <td>${r.jitterMs}</td>
        <td>${r.lossPct}</td>
        <td>${cfTlsHtml(r)}</td>
        <td>${dpiHtml(r)}</td>
        <td>${r.throughputKbps != null ? r.throughputKbps : '<span class="muted">—</span>'}</td>
        <td>${tagHtml(status)}</td>
      </tr>`;
    }).join('');

    if (mode === 'v2ray') renderTop3(sorted); else document.getElementById('top3Box').classList.add('hidden');
  }

  function renderTop3(sorted) {
    const box = document.getElementById('top3Box');
    const list = document.getElementById('top3List');
    const top = sorted.filter((r) => r.clean && r.raw).slice(0, 3);
    if (!top.length) { box.classList.add('hidden'); return; }
    box.classList.remove('hidden');
    list.innerHTML = top.map((r, i) => `
      <div class="top3-item">
        <div class="top3-rank">#${i + 1}</div>
        <div class="top3-info">
          <div class="top3-name">${r.domain || r.ip} <span class="muted">(${r.avgMs}ms)</span></div>
          <code class="top3-raw">${r.raw.replace(/</g, '&lt;')}</code>
        </div>
        <button class="btn-ghost btn-copy" data-raw="${encodeURIComponent(r.raw)}">Copy</button>
      </div>`).join('');
    list.querySelectorAll('.btn-copy').forEach((b) => {
      b.addEventListener('click', () => {
        navigator.clipboard.writeText(decodeURIComponent(b.dataset.raw));
        b.textContent = 'Copied ✓';
        setTimeout(() => { b.textContent = 'Copy'; }, 1500);
      });
    });
  }

  document.querySelectorAll('thead th').forEach((th) => {
    th.addEventListener('click', () => {
      const key = th.dataset.key;
      const map = { rank: 'score', kind: 'kind', ip: 'ip', domain: 'domain', avgMs: 'avgMs', jitterMs: 'jitterMs', lossPct: 'lossPct', dpi: 'dpiBypass', status: 'score' };
      const k = map[key] || 'score';
      if (sortKey === k) sortDir *= -1; else { sortKey = k; sortDir = 1; }
      renderTable();
    });
  });

  // ---------------- stats ----------------
  function updateStats() {
    document.getElementById('statTotal').textContent = results.length;
    const clean = results.filter((r) => statusOf(r) === 'clean');
    const dead = results.filter((r) => statusOf(r) === 'dead');
    document.getElementById('statClean').textContent = clean.length;
    document.getElementById('statDead').textContent = dead.length;
    if (clean.length) {
      const best = Math.min(...clean.map((r) => r.avgMs ?? Infinity));
      document.getElementById('statAvg').textContent = isFinite(best) ? best.toFixed(1) : '–';
    }
  }

  // ---------------- scan trigger ----------------
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
    params.set('frag', document.getElementById('fragTest').checked ? '1' : '0');
    if (mode === 'cf') {
      params.set('count', document.getElementById('cfCount').value);
      params.set('sni', document.getElementById('cfSni').value || 'speed.cloudflare.com');
    } else if (mode === 'domains') {
      params.set('source', document.getElementById('domainsSource').value);
      params.set('resolveDns', document.getElementById('resolveDns').checked ? '1' : '0');
      params.set('count', '0');
    } else if (mode === 'v2ray') {
      params.set('v2raySource', document.getElementById('v2raySource').value);
    } else if (mode === 'proxy') {
      params.set('proxyList', document.getElementById('proxyList').value);
    } else if (mode === 'proxyscrape') {
      params.set('scrapeLimit', document.getElementById('scrapeLimit').value);
    }
    return '/api/scan-stream?' + params.toString();
  }

  startBtn.addEventListener('click', async () => {
    startBtn.disabled = true;
    const fresh = await checkNetwork();
    if (fresh && fresh.checked && fresh.flagged) {
      startBtn.disabled = false;
      setStatus('running', 'Blocked: VPN/Proxy is active');
      document.getElementById('progressText').textContent =
        `Scan blocked — a VPN/proxy connection was detected (${fresh.isp || fresh.org || 'unknown provider'}). Turn it off and press Start again; results measured through a VPN don't reflect your real connection.`;
      return;
    }

    results = [];
    blips.length = 0;
    renderTable();
    updateStats();
    document.getElementById('progressFill').style.width = '0%';
    document.getElementById('progressText').textContent = 'Preparing...';
    const scrapeLog = document.getElementById('scrapeLog');
    if (scrapeLog) scrapeLog.innerHTML = '';
    startBtn.disabled = true;
    stopBtn.classList.remove('hidden');
    setStatus('running', 'Scanning...');

    let scanFinished = false;

    if (es) es.close();
    es = new EventSource(buildUrl());

    es.addEventListener('info', (e) => {
      const d = JSON.parse(e.data);
      document.getElementById('progressText').textContent = d.message;
    });

    es.addEventListener('scrapesource', (e) => {
      const d = JSON.parse(e.data);
      const log = document.getElementById('scrapeLog');
      if (!log) return;
      const row = document.createElement('div');
      row.className = 'scrape-row ' + (d.ok ? 'ok' : 'fail');
      row.innerHTML = `<span class="scrape-dot"></span><span class="scrape-proto">${d.protocol}</span><span class="scrape-host">${d.host}</span><span class="scrape-count">${d.ok ? d.count + ' found' : 'unreachable'}</span>`;
      log.appendChild(row);
      log.scrollTop = log.scrollHeight;
    });

    es.addEventListener('resolveProgress', (e) => {
      const d = JSON.parse(e.data);
      const pct = d.total ? (d.done / d.total) * 100 : 0;
      document.getElementById('progressFill').style.width = pct + '%';
      document.getElementById('progressText').textContent = `Resolving DNS: ${d.done} / ${d.total}`;
    });

    es.addEventListener('start', (e) => {
      const d = JSON.parse(e.data);
      document.getElementById('progressText').textContent = `0 / ${d.total}`;
    });

    es.addEventListener('result', (e) => {
      const r = JSON.parse(e.data);
      results.push(r);
      addBlip(statusOf(r));
      updateStats();
      if (results.length % 5 === 0 || results.length < 30) renderTable();
    });

    es.addEventListener('progress', (e) => {
      const d = JSON.parse(e.data);
      const pct = d.total ? (d.done / d.total) * 100 : 0;
      document.getElementById('progressFill').style.width = pct + '%';
      document.getElementById('progressText').textContent = `${d.done} / ${d.total}`;
    });

    es.addEventListener('done', (e) => {
      const d = JSON.parse(e.data);
      scanFinished = true;
      renderTable();
      updateStats();
      setStatus('done', `Done — ${d.clean} clean of ${d.total}`);
      startBtn.disabled = false;
      stopBtn.classList.add('hidden');
      es.close();
    });

    es.addEventListener('scanerror', (e) => {
      const d = JSON.parse(e.data);
      scanFinished = true;
      setStatus(null, `Scan error: ${d.message}`);
      startBtn.disabled = false;
      stopBtn.classList.add('hidden');
      es.close();
    });

    es.addEventListener('error', () => {
      if (scanFinished) return; // connection closed normally after done/scanerror — ignore
      setStatus(null, 'Server connection error');
      startBtn.disabled = false;
      stopBtn.classList.add('hidden');
    });
  });

  stopBtn.addEventListener('click', () => {
    if (es) es.close();
    startBtn.disabled = false;
    stopBtn.classList.add('hidden');
    setStatus(null, 'Stopped');
  });

  // ---------------- export ----------------
  document.querySelectorAll('.btn-export').forEach((btn) => {
    btn.addEventListener('click', () => {
      if (!currentSid) return;
      const fmt = btn.dataset.fmt;
      window.open(`/api/export?sid=${currentSid}&format=${fmt}`, '_blank');
    });
  });
})();
