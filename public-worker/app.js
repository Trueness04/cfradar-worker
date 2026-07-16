(() => {
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
      params.set('serviceName', cfg.path.replace(/^\//, ''));
      params.delete('path');
    }
    return `vless://${cfg.uuid}@${ip}:${cfg.port}?${params.toString()}#${encodeURIComponent(remark)}`;
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
    return `trojan://${cfg.uuid}@${ip}:${cfg.port}?${params.toString()}#${encodeURIComponent(remark)}`;
  }

  function buildV2Link(ip, cfg, domain, latency) {
    const remark = `CFRadar | ${domain || ip} | ${latency}ms`;
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
    const name = `CFRadar-${idx + 1}`;
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
    const tag = `cfradar-${idx + 1}`;
    const transport = cfg.net === 'ws' ? {
      type: 'ws', path: cfg.path, headers: { Host: cfg.sni },
    } : cfg.net === 'grpc' ? { type: 'grpc', service_name: cfg.path.replace(/^\//, '') }
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
      timeoutHint.textContent = `⚠ ${v}ms is very low — Iran round-trips are often 100–300ms+. Use 1000–1500ms.`;
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
    div.innerHTML = `<span class="fi-ip">${r.ip}</span>
      <span class="fi-ms" style="color:${col}">${msStr}</span>
      <span class="fi-status" style="color:${col}">${status}</span>
      ${r.cfPop ? `<span class="pop-tag">${r.cfPop}</span>` : ''}`;
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
    document.getElementById('resultsCount').textContent = `(${filtered.length} / ${results.length})`;

    if (filtered.length === 0) {
      body.innerHTML = `<tr class="empty-row"><td colspan="13">${results.length ? 'No results match current filters.' : 'No scan yet — go to the Scan tab.'}</td></tr>`;
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
      return `<tr class="${rangeClass}">
        <td>${i + 1}</td>
        <td class="lat-good" style="font-family:var(--mono)">${r.ip}</td>
        <td>${r.domain || '<span class="muted">—</span>'}</td>
        <td class="${latClass(r.avgMs)}">${r.avgMs ?? '—'}</td>
        <td class="${latClass(r.medianMs)}">${r.medianMs ?? '—'}</td>
        <td>${r.icmpMs ?? '<span class="muted">—</span>'}</td>
        <td>${r.jitterMs}</td>
        <td>${r.lossPct}</td>
        <td>${cfTlsHtml(r)}</td>
        <td>${r.cfPop ? `<span class="pop-tag">${r.cfPop}</span>` : '<span class="muted">—</span>'}</td>
        <td>${r.throughputKbps != null ? r.throughputKbps : '<span class="muted">—</span>'}</td>
        <td>${tagHtml(status)}</td>
        <td>
          <button class="action-btn" data-action="v2" data-ip="${r.ip}" data-domain="${r.domain || ''}" data-ms="${r.medianMs || ''}">V2</button>
          <button class="action-btn" data-action="detail" data-idx="${i}">Info</button>
        </td>
      </tr>`;
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
      showModal(`
        <div class="section-title">V2Ray Link — ${ip}</div>
        <div class="v2-link-str" id="singleLinkStr">${link}</div>
        <div style="margin-top:12px;display:flex;gap:8px;">
          <button class="v2-link-copy-btn" id="singleCopyBtn">⎘ Copy Link</button>
        </div>
      `);
      document.getElementById('singleCopyBtn').addEventListener('click', () => {
        copyText(link);
        document.getElementById('singleCopyBtn').textContent = '✓ Copied!';
        document.getElementById('singleCopyBtn').classList.add('copied');
      });
    }
    if (btn.dataset.action === 'detail') {
      const r = applyFilters(results)[parseInt(btn.dataset.idx)];
      if (!r) return;
      showModal(`
        <div class="section-title">IP Details — ${r.ip}</div>
        <div class="geo-result" style="margin-top:0;grid-template-columns:1fr 1fr;">
          ${detailField('IP', r.ip)}
          ${detailField('Domain', r.domain || '—')}
          ${detailField('Avg Latency', r.avgMs != null ? r.avgMs + ' ms' : '—')}
          ${detailField('Median Latency', r.medianMs != null ? r.medianMs + ' ms' : '—')}
          ${detailField('ICMP Ping', r.icmpMs != null ? r.icmpMs + ' ms' : '—')}
          ${detailField('Jitter', r.jitterMs + ' ms')}
          ${detailField('Loss %', r.lossPct + '%')}
          ${detailField('Passes', r.successes + ' / ' + r.attempts)}
          ${detailField('TLS OK', r.tlsOk ? '✓ Yes' : '✗ No')}
          ${detailField('CF Verified', r.cfVerified ? '✓ Yes' : '✗ No')}
          ${detailField('CF PoP', r.cfPop || '—')}
          ${detailField('HTTP Status', r.httpStatus || '—')}
          ${detailField('Throughput', r.throughputKbps != null ? r.throughputKbps + ' KB/s' : '—')}
          ${detailField('Status', statusOf(r))}
          ${detailField('Score', Math.round(r.score * 10) / 10)}
        </div>
      `);
    }
  });

  function detailField(label, value) {
    return `<div class="geo-field"><div class="geo-field-label">${label}</div><div class="geo-field-value">${value}</div></div>`;
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
    document.getElementById('v2Count').textContent = `(${cleanIps.length})`;
    if (cleanIps.length === 0) {
      v2List.innerHTML = '<div class="empty-row-plain">Run a scan first. Clean IPs will appear here as ready-to-use V2Ray links.</div>';
      return;
    }
    v2List.innerHTML = cleanIps.map((r, i) => {
      const link = buildV2Link(r.ip, cfg, r.domain, r.medianMs || '?');
      const pop = r.cfPop ? `<span class="pop-tag">${r.cfPop}</span>` : '';
      return `<div class="v2-link-item">
        <div class="v2-link-header">
          <div class="v2-link-meta">
            <b>${r.ip}</b>${r.domain ? ' · ' + r.domain : ''}
            ${pop}
            · <span style="color:var(--green)">${r.medianMs ?? '?'}ms</span>
            · ${cfg.proto.toUpperCase()} / ${cfg.net} / port ${cfg.port}
          </div>
          <button class="v2-link-copy-btn" data-link="${encodeURIComponent(link)}">⎘ Copy</button>
        </div>
        <div class="v2-link-str" data-link="${encodeURIComponent(link)}">${link}</div>
      </div>`;
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
      .map((r) => buildV2Link(r.ip, cfg, r.domain, r.medianMs || '?')).join('\n');
    copyText(links);
    const btn = document.getElementById('copyAllV2');
    btn.textContent = '✓ Copied all!';
    setTimeout(() => { btn.textContent = '⎘ Copy All'; }, 2000);
  });

  document.getElementById('downloadV2').addEventListener('click', () => {
    const cfg = v2Config();
    const links = results.filter((r) => r.clean)
      .map((r) => buildV2Link(r.ip, cfg, r.domain, r.medianMs || '?')).join('\n');
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
      return obj.map((v) => `${pad}- ${toYamlValue(v, indent)}`).join('\n');
    }
    return Object.entries(obj).filter(([, v]) => v !== undefined && v !== null)
      .map(([k, v]) => {
        if (typeof v === 'object' && !Array.isArray(v) && v !== null) {
          return `${pad}${k}:\n${toYaml(v, indent + 1)}`;
        }
        if (Array.isArray(v)) {
          return `${pad}${k}:\n${v.map((i) => `${'  '.repeat(indent + 1)}- ${toYamlValue(i, indent + 1)}`).join('\n')}`;
        }
        return `${pad}${k}: ${toYamlValue(v, indent)}`;
      }).join('\n');
  }
  function toYamlValue(v, indent) {
    if (typeof v === 'string') return `"${v.replace(/"/g, '\\"')}"`;
    if (typeof v === 'boolean' || typeof v === 'number') return String(v);
    if (typeof v === 'object' && v !== null) return '\n' + toYaml(v, indent + 1);
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
      const resp = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,regionName,isp,org,as,lat,lon,timezone`);
      const data = await resp.json();
      if (data.status !== 'success') throw new Error(data.message || 'lookup failed');
      resultDiv.innerHTML = `
        ${geoField('IP', ip)}
        ${geoField('Country', `${data.country} (${data.countryCode})`)}
        ${geoField('City', data.city)}
        ${geoField('Region', data.regionName)}
        ${geoField('ISP', data.isp)}
        ${geoField('Org', data.org)}
        ${geoField('ASN', data.as)}
        ${geoField('Timezone', data.timezone)}
        ${geoField('Coordinates', `${data.lat}, ${data.lon}`)}
      `;
    } catch (err) {
      resultDiv.innerHTML = `<div style="color:var(--red);font-size:12px;">Lookup failed: ${err.message}</div>`;
    }
  }

  function geoField(label, value) {
    return `<div class="geo-field"><div class="geo-field-label">${label}</div><div class="geo-field-value">${value || '—'}</div></div>`;
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
    geoDiv.innerHTML = sorted.map(([pop, ips]) => `
      <div class="geo-country-block">
        <div class="geo-country-name">${pop}</div>
        <div style="font-size:11px;color:var(--text-dim);margin-bottom:6px;">${ips.length} clean IP${ips.length !== 1 ? 's' : ''}</div>
        <div class="geo-pop-list">
          ${ips.slice(0, 6).map((ip) => `<span class="geo-pop-item">${ip}</span>`).join('')}
          ${ips.length > 6 ? `<span class="geo-pop-item">+${ips.length - 6}</span>` : ''}
        </div>
      </div>
    `).join('');
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
      addFeedItem(r);
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
      scanFinished = true; scanRunning = false;
      renderTable(); renderV2Panel(); renderGeoSummary(); updateStats();
      setStatus('done', `Done — ${d.clean} clean of ${d.total}`);
      startBtn.disabled = false; stopBtn.classList.add('hidden'); es.close();
    });
    es.addEventListener('scanerror', (e) => {
      const d = JSON.parse(e.data);
      scanFinished = true; scanRunning = false;
      setStatus(null, `Scan error: ${d.message}`);
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
          .map((r) => buildV2Link(r.ip, cfg, r.domain, r.medianMs || '?')).join('\n');
        downloadFile(links, 'cfradar-v2ray-links.txt', 'text/plain');
      } else if (fmt === 'clash') {
        const cfg = v2Config();
        const proxies = results.filter((r) => r.clean).map((r, i) => buildClashProxy(r.ip, cfg, r.domain, i));
        const names = proxies.map((p) => p.name);
        const config = { proxies, 'proxy-groups': [{ name: 'CFRadar', type: 'url-test', proxies: names, url: 'http://www.gstatic.com/generate_204', interval: 300 }], rules: ['MATCH,CFRadar'] };
        downloadFile(toYaml(config), 'cfradar-clash.yaml', 'text/yaml');
      } else {
        window.open(`/api/export?sid=${currentSid}&format=${fmt}`, '_blank');
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
