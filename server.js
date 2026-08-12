'use strict';
/**
 * CFRadar — Clean Cloudflare IP & Domain Scanner
 * Backend: pure Node.js built-ins only (http, net, https, dns, fs, crypto).
 * No npm install required — just `node server.js`.
 */

const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { execFile } = require('child_process');

const PORT = process.env.PORT || 7777;
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------------------------------------------------------------------------
// Official Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4)
// ---------------------------------------------------------------------------
const CF_RANGES = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
];

// ---------------------------------------------------------------------------
// CIDR helpers
// ---------------------------------------------------------------------------
function ipToInt(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}
function intToIp(int) {
  return [24, 16, 8, 0].map((shift) => (int >>> shift) & 255).join('.');
}
function parseCidr(cidr) {
  const [base, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const baseInt = ipToInt(base);
  const hostBits = 32 - bits;
  const size = hostBits >= 32 ? 0xFFFFFFFF : (1 << hostBits) >>> 0;
  const network = baseInt & (~(size) >>> 0);
  return { network, size: hostBits >= 32 ? 4294967296 : size };
}

function sampleIpsFromRanges(ranges, count) {
  const nets = ranges.map(parseCidr);
  // weight bigger ranges slightly more, but not linearly (avoid huge /13 dominating)
  const weighted = [];
  nets.forEach((n) => {
    const w = Math.max(1, Math.round(Math.pow(n.size, 0.15)));
    for (let i = 0; i < w; i++) weighted.push(n);
  });
  const chosen = new Set();
  let attempts = 0;
  const maxAttempts = count * 20 + 1000;
  while (chosen.size < count && attempts < maxAttempts) {
    attempts++;
    const net_ = weighted[Math.floor(Math.random() * weighted.length)];
    const hostCount = net_.size;
    let ipInt;
    if (hostCount <= 2) {
      ipInt = net_.network;
    } else {
      const offset = 1 + Math.floor(Math.random() * (hostCount - 2));
      ipInt = (net_.network + offset) >>> 0;
    }
    chosen.add(intToIp(ipInt));
  }
  return Array.from(chosen);
}

// ---------------------------------------------------------------------------
// Phase 2: real TLS handshake against the IP + an HTTPS request to check
// for genuine Cloudflare response headers (cf-ray / server: cloudflare).
// This is what actually proves the IP works for domain-fronting / proxy use,
// as opposed to phase 1 which only proves the TCP port is open.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Real ICMP ping via the OS `ping` binary. TCP-handshake timing (used
// elsewhere) is a fine proxy for reachability, but people comparing numbers
// against what they see in cmd/terminal expect real ICMP ping — and ICMP
// vs TCP can behave differently under DPI/filtering, so this is also a
// genuinely independent signal, not just cosmetic.
// ---------------------------------------------------------------------------
function icmpPing(ip, count, timeoutMs) {
  return new Promise((resolve) => {
    const isWin = os.platform() === 'win32';
    const args = isWin
      ? ['-n', String(count), '-w', String(timeoutMs), ip]
      : ['-c', String(count), '-W', String(Math.max(1, Math.round(timeoutMs / 1000))), ip];
    execFile('ping', args, { timeout: timeoutMs * count + 2000 }, (err, stdout) => {
      if (!stdout) { resolve({ avgMs: null, lossPct: 100 }); return; }
      // Windows: "Average = 23ms"
      let m = stdout.match(/Average\s*=\s*(\d+)\s*ms/i);
      if (m) {
        const lossM = stdout.match(/\((\d+)%\s*loss\)/i);
        resolve({ avgMs: parseFloat(m[1]), lossPct: lossM ? parseFloat(lossM[1]) : 0 });
        return;
      }
      // Linux/macOS: "rtt min/avg/max/mdev = 10.123/15.456/20.789/2.345 ms"
      m = stdout.match(/=\s*[\d.]+\/([\d.]+)\/[\d.]+\/[\d.]+\s*ms/i);
      if (m) {
        const lossM = stdout.match(/([\d.]+)%\s*packet loss/i);
        resolve({ avgMs: parseFloat(m[1]), lossPct: lossM ? parseFloat(lossM[1]) : 0 });
        return;
      }
      resolve({ avgMs: null, lossPct: 100 });
    });
  });
}

// ---------------------------------------------------------------------------
// Phase 4 (optional): SNI fragmentation DPI-bypass probe.
// Most DPI boxes doing SNI-based blocking inspect a single TCP packet for
// the plaintext hostname inside the TLS ClientHello. This builds a real,
// minimal, spec-valid TLS 1.2 ClientHello by hand (not via Node's tls
// module, which won't let us control write boundaries), then sends it in
// two separate socket writes with a small gap between them, split right
// in the middle of the SNI hostname bytes — the same principle used by
// tools like GoodbyeDPI/zapret. If tlsCloudflareProbe (single write) fails
// but this succeeds, that IP is specifically blocked by single-packet SNI
// inspection, not actually unreachable — a genuinely different, actionable
// signal most scanners don't surface at all.
// ---------------------------------------------------------------------------
// Pre-allocate reusable buffers for TLS handshake to avoid GC pressure
const TLS_VERSION_BUF = Buffer.from([0x03, 0x03]);
const TLS_SESSION_EMPTY = Buffer.from([0x00]);
const TLS_COMPRESSION_NULL = Buffer.from([0x01, 0x00]);
// Pre-allocated TLS cipher suite buffers (reused across all handshakes)
const CIPHER_BUFS = [Buffer.from([0xc0,0x2f]),Buffer.from([0xc0,0x30]),Buffer.from([0xc0,0x2b]),Buffer.from([0xc0,0x2c]),Buffer.from([0x00,0x9c]),Buffer.from([0x00,0x2f]),Buffer.from([0x00,0x35])];
const CIPHER_SECTION_LEN = CIPHER_BUFS.reduce((n,b)=>n+b.length,0);

function u16(n) { const b = Buffer.allocUnsafe(2); b.writeUInt16BE(n, 0); return b; }
function u24(n) { const b = Buffer.allocUnsafe(3); b.writeUIntBE(n, 0, 3); return b; }

function buildTls12ClientHello(sniHost) {
  const hostBuf = Buffer.from(sniHost, 'utf8');

  const sniEntry = Buffer.concat([Buffer.from([0x00]), u16(hostBuf.length), hostBuf]);
  const sniList = Buffer.concat([u16(sniEntry.length), sniEntry]);
  const sniExt = Buffer.concat([u16(0x0000), u16(sniList.length), sniList]);

  const ecPointsBody = Buffer.from([0x01, 0x00]);
  const ecPointsExt = Buffer.concat([u16(0x000b), u16(ecPointsBody.length), ecPointsBody]);

  const groups = Buffer.concat([u16(0x001d), u16(0x0017), u16(0x0018)]);
  const groupsBody = Buffer.concat([u16(groups.length), groups]);
  const groupsExt = Buffer.concat([u16(0x000a), u16(groupsBody.length), groupsBody]);

  const sigAlgos = Buffer.concat([u16(0x0401), u16(0x0403), u16(0x0501), u16(0x0201)]);
  const sigAlgosBody = Buffer.concat([u16(sigAlgos.length), sigAlgos]);
  const sigAlgosExt = Buffer.concat([u16(0x000d), u16(sigAlgosBody.length), sigAlgosBody]);

  const extensions = Buffer.concat([sniExt, ecPointsExt, groupsExt, sigAlgosExt]);
  const extensionsSection = Buffer.concat([u16(extensions.length), extensions]);

  const cipherSection = Buffer.concat([u16(CIPHER_SECTION_LEN), ...CIPHER_BUFS]);

  const body = Buffer.concat([
    TLS_VERSION_BUF,
    crypto.randomBytes(32),
    TLS_SESSION_EMPTY,
    cipherSection,
    TLS_COMPRESSION_NULL,
    extensionsSection,
  ]);
  const handshakeMsg = Buffer.concat([Buffer.from([0x01]), u24(body.length), body]);
  const record = Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), u16(handshakeMsg.length), handshakeMsg]);

  return { buffer: record, hostBuf };
}

function fragmentedTlsProbe(ip, port, sniHost, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    let sock;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      try { sock && sock.destroy(); } catch (_) {}
      resolve(ok);
    };

    let built;
    try { built = buildTls12ClientHello(sniHost); } catch (_) { resolve(false); return; }
    const { buffer, hostBuf } = built;
    let splitPoint = buffer.indexOf(hostBuf);
    splitPoint = splitPoint >= 0 ? splitPoint + Math.floor(hostBuf.length / 2) : Math.floor(buffer.length / 2);
    if (splitPoint <= 0 || splitPoint >= buffer.length) splitPoint = Math.floor(buffer.length / 2);
    const part1 = buffer.subarray(0, splitPoint);
    const part2 = buffer.subarray(splitPoint);

    try {
      sock = new net.Socket();
    } catch (_) { resolve(false); return; }
    sock.setTimeout(timeoutMs);
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.once('close', () => finish(false));
    sock.once('data', () => finish(true));
    sock.connect(port, ip, () => {
      sock.setNoDelay(true);
      sock.write(part1, () => {
        setTimeout(() => {
          try { sock.write(part2); } catch (_) { finish(false); }
        }, 15);
      });
    });
  });
}

function tlsCloudflareProbe(ip, sniHost, port, timeoutMs) {
  const probe = new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    let socket;
    try {
      socket = tls.connect({
        host: ip,
        port,
        servername: sniHost,
        rejectUnauthorized: true,
        checkServerIdentity: (_host, cert) => tls.checkServerIdentity(sniHost, cert),
      });
      socket.setTimeout(timeoutMs);
    } catch (_) {
      finish({ tlsOk: false, cfVerified: false, httpStatus: null });
      return;
    }

    socket.once('timeout', () => { try { socket.destroy(); } catch (_) {} finish({ tlsOk: false, cfVerified: false, httpStatus: null }); });
    socket.once('error', () => { try { socket.destroy(); } catch (_) {} finish({ tlsOk: false, cfVerified: false, httpStatus: null }); });

    socket.once('secureConnect', () => {
      const req = `HEAD / HTTP/1.1\r\nHost: ${sniHost}\r\nUser-Agent: CFRadar/1.0\r\nConnection: close\r\n\r\n`;
      socket.write(req);
      let buf = '';
      socket.on('data', (chunk) => {
        buf += chunk.toString('utf-8');
        if (buf.includes('\r\n\r\n') || buf.length > 8192) {
          try { socket.destroy(); } catch (_) {}
          const headerBlock = buf.split('\r\n\r\n')[0].toLowerCase();
          const statusMatch = buf.match(/^HTTP\/[\d.]+\s+(\d+)/);
          const httpStatus = statusMatch ? parseInt(statusMatch[1], 10) : null;
          const cfVerified = headerBlock.includes('server: cloudflare') || /cf-ray:/i.test(headerBlock);
          finish({ tlsOk: true, cfVerified, httpStatus });
        }
      });
      socket.once('end', () => finish({ tlsOk: true, cfVerified: false, httpStatus: null }));
    });
  });

  // Hard safety net: no matter what the socket does, never hang past 2x the
  // requested timeout. This is what was causing the UI to appear "frozen"
  // partway through a scan when a probe got stuck in a weird state.
  const hardTimeout = new Promise((resolve) => {
    setTimeout(() => resolve({ tlsOk: false, cfVerified: false, httpStatus: null }), timeoutMs * 2 + 1000);
  });

  return Promise.race([probe, hardTimeout]);
}

// ---------------------------------------------------------------------------
// Phase 3: real throughput probe — download a small chunk over a verified
// TLS connection and measure actual KB/s. Latency alone doesn't tell you if
// an IP can sustain real traffic; this does.
// ---------------------------------------------------------------------------
function throughputProbe(ip, sniHost, port, timeoutMs) {
  const probe = new Promise((resolve) => {
    let settled = false;
    const finish = (kbps) => { if (!settled) { settled = true; resolve(kbps); } };
    let socket;
    try {
      socket = tls.connect({ host: ip, port, servername: sniHost, rejectUnauthorized: true });
      socket.setTimeout(timeoutMs);
    } catch (_) { finish(null); return; }

    socket.once('timeout', () => { try { socket.destroy(); } catch (_) {} finish(null); });
    socket.once('error', () => { try { socket.destroy(); } catch (_) {} finish(null); });

    socket.once('secureConnect', () => {
      const bytesWanted = 262144; // 256KB sample
      const reqPath = `/__down?bytes=${bytesWanted}`;
      const req = `GET ${reqPath} HTTP/1.1\r\nHost: ${sniHost}\r\nUser-Agent: CFRadar/1.0\r\nConnection: close\r\n\r\n`;
      let received = 0;
      const t0 = process.hrtime.bigint();
      socket.write(req);
      socket.on('data', (chunk) => { received += chunk.length; });
      socket.once('end', () => {
        const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
        if (received <= 0 || elapsedMs <= 0) { finish(null); return; }
        finish(Math.round((received / 1024) / (elapsedMs / 1000)));
      });
    });
  });
  const hardTimeout = new Promise((resolve) => setTimeout(() => resolve(null), timeoutMs * 2 + 1000));
  return Promise.race([probe, hardTimeout]);
}

// ---------------------------------------------------------------------------
// TCP probe: a single handshake attempt, returns latency ms or null
// ---------------------------------------------------------------------------
function tcpProbeOnce(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    let settled = false;
    const sock = new net.Socket();
    const finish = (ms) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch (_) {}
      resolve(ms);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => {
      const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
      finish(elapsed);
    });
    sock.once('timeout', () => finish(null));
    sock.once('error', () => finish(null));
    try {
      sock.connect(port, ip);
    } catch (_) {
      finish(null);
    }
  });
}

async function scanTarget(target, ip, port, timeoutMs, passes, sniHost, opts) {
  opts = opts || {};
  const useIcmp = !!opts.useIcmp;
  const targetMin = opts.targetMin; // number|undefined
  const targetMax = opts.targetMax; // number|undefined

  // Warm-up probe: the very first TCP connection to a fresh IP is often
  // slower (route lookup, no cached path) and unfairly drags down the
  // average/loss numbers. Run one throwaway probe first and ignore it
  // completely before the passes that actually count.
  await tcpProbeOnce(ip, port, timeoutMs);

  const latencies = [];
  let successes = 0;
  let sumLatency = 0;
  for (let i = 0; i < passes; i++) {
    const ms = await tcpProbeOnce(ip, port, timeoutMs);
    if (ms !== null) {
      latencies.push(ms);
      sumLatency += ms;
      successes++;
    }
  }
  const sortedLat = latencies.slice().sort((a, b) => a - b);
  const avg = latencies.length ? sumLatency / latencies.length : Infinity;
  // Median is more robust than mean against the occasional spike Iran's
  // network throws in, so it's what we actually rank/score on.
  const median = sortedLat.length
    ? (sortedLat.length % 2 === 1
        ? sortedLat[(sortedLat.length - 1) / 2]
        : (sortedLat[sortedLat.length / 2 - 1] + sortedLat[sortedLat.length / 2]) / 2)
    : Infinity;
  const jitter = latencies.length > 1
    ? Math.sqrt(latencies.reduce((s, v) => s + Math.pow(v - avg, 2), 0) / latencies.length)
    : 0;
  const lossPct = Math.round(((passes - successes) / passes) * 1000) / 10;

  // Optional real ICMP ping — independent of the TCP timing above, and
  // what most people actually mean when they say "ping". Only worth
  // running if the TCP phase showed the host is alive at all.
  let icmpMs = null;
  let icmpLossPct = null;
  if (useIcmp && successes > 0) {
    const icmpResult = await icmpPing(ip, Math.max(passes, 3), timeoutMs);
    icmpMs = icmpResult.avgMs;
    icmpLossPct = icmpResult.lossPct;
  }
  // Whichever latency number we actually judge "ping" by: ICMP if it was
  // requested and succeeded, otherwise the TCP median.
  const effectiveMs = (useIcmp && icmpMs !== null) ? icmpMs : median;

  // Phase 2: only worth doing a real TLS+HTTP check if the TCP port is
  // actually reachable. This is what verifies the IP genuinely fronts
  // through Cloudflare, not just that *something* is listening on the port.
  // Run it TWICE independently — a single flaky probe shouldn't decide
  // "clean" either way — and require both to agree.
  let tlsOk = false;
  let cfVerified = false;
  let httpStatus = null;
  const cfPorts = [443, 2053, 2083, 2087, 2096];
  if (successes > 0 && cfPorts.includes(port)) {
    const tlsTimeout = Math.max(timeoutMs, 1500);
    const [r1, r2] = await Promise.all([
      tlsCloudflareProbe(ip, sniHost, port, tlsTimeout),
      tlsCloudflareProbe(ip, sniHost, port, tlsTimeout),
    ]);
    tlsOk = r1.tlsOk || r2.tlsOk;
    cfVerified = (r1.cfVerified ? 1 : 0) + (r2.cfVerified ? 1 : 0) >= 2;
    httpStatus = r1.httpStatus ?? r2.httpStatus;
  }

  // Phase 4: optional SNI-fragmentation DPI-bypass probe. Only worth
  // running against reachable hosts, and only when explicitly requested
  // since it adds a real extra round-trip per IP.
  let fragTlsOk = null;
  let dpiBypass = null;
  if (opts.fragTest && successes > 0 && cfPorts.includes(port)) {
    fragTlsOk = await fragmentedTlsProbe(ip, port, sniHost, Math.max(timeoutMs, 1500));
    dpiBypass = !tlsOk && fragTlsOk;
  }

  // Phase 3: real throughput. Only meaningful against the dedicated
  // Cloudflare speed-test endpoint (arbitrary sites don't expose /__down),
  // so it only runs when the SNI host is that test domain and CF was
  // already verified — no point measuring speed on something fake.
  let throughputKbps = null;
  if (cfVerified && sniHost === 'speed.cloudflare.com') {
    throughputKbps = await throughputProbe(ip, sniHost, port, Math.max(timeoutMs, 2000));
  }

  // Optional target ping range: if the user wants IPs specifically in
  // e.g. the 40-50ms band, that becomes part of what "clean" even means —
  // a 5ms IP and a 600ms IP are BOTH wrong answers to that request.
  const hasTargetRange = typeof targetMin === 'number' && typeof targetMax === 'number';
  const inTargetRange = hasTargetRange
    ? (effectiveMs >= targetMin && effectiveMs <= targetMax)
    : null;

  const latencyOk = hasTargetRange ? !!inTargetRange : effectiveMs < 1500;

  // "clean" requires every TCP attempt to succeed, latency within bounds
  // (either the generic <1500ms sanity check, or the user's target range),
  // AND a TLS/HTTP-verified Cloudflare match from two independent probes.
  const clean = successes === passes && latencyOk && cfVerified;

  // Scoring: when a target range is set, rank by closeness to the CENTER
  // of that range (not just "lower is better") — a 45ms result should
  // outrank a 41ms result if the user asked for 40-50.
  let latencyScore;
  if (hasTargetRange) {
    const center = (targetMin + targetMax) / 2;
    latencyScore = Math.abs(effectiveMs - center) * (inTargetRange ? 1 : 20);
  } else {
    latencyScore = effectiveMs;
  }
  const score = successes === 0
    ? Infinity
    : latencyScore + jitter * 2 + (passes - successes) * 5000
      + (cfVerified ? 0 : 3000)
      - (throughputKbps ? Math.min(throughputKbps, 5000) / 10 : 0);

  return {
    target, ip, domain: target !== ip ? target : null,
    avgMs: latencies.length ? Math.round(avg * 10) / 10 : null,
    medianMs: latencies.length ? Math.round(median * 10) / 10 : null,
    icmpMs: icmpMs !== null ? Math.round(icmpMs * 10) / 10 : null,
    icmpLossPct,
    jitterMs: Math.round(jitter * 10) / 10,
    lossPct, successes, attempts: passes,
    tlsOk, cfVerified, httpStatus, throughputKbps,
    fragTlsOk, dpiBypass,
    inTargetRange,
    clean, score,
  };
}

// ---------------------------------------------------------------------------
// Simple async worker pool with concurrency limit
// ---------------------------------------------------------------------------
async function runPool(items, workerCount, worker, onProgress) {
  const results = [];
  let idx = 0;
  let done = 0;
  const total = items.length;
  async function runner() {
    while (idx < items.length) {
      const myIdx = idx++;
      const item = items[myIdx];
      try {
        const r = await worker(item);
        if (r) results.push(r);
      } catch (_) { /* ignore */ }
      done++;
      if (onProgress) onProgress(done, total, results[results.length - 1]);
    }
  }
  const runners = Array.from({ length: Math.min(workerCount, items.length || 1) }, runner);
  await Promise.all(runners);
  return results;
}

// ---------------------------------------------------------------------------
// Domain list loader — supports remote/local JSON ({"data":[{domain,ipv4}]})
// or plain text (one domain per line)
// ---------------------------------------------------------------------------
function fetchUrl(target) {
  return new Promise((resolve, reject) => {
    const lib = target.startsWith('https') ? https : http;
    const req = lib.get(target, { headers: { 'User-Agent': 'CFRadar/1.0' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        resolve(fetchUrl(res.headers.location));
        return;
      }
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.setTimeout(20000, () => req.destroy(new Error('timeout')));
  });
}

async function loadDomainsSource(source) {
  if (!source) return [];
  let raw;
  if (source.startsWith('http://') || source.startsWith('https://')) {
    raw = await fetchUrl(source);
  } else {
    raw = fs.readFileSync(source, 'utf-8');
  }
  const trimmed = raw.trim();
  const items = [];
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const data = JSON.parse(trimmed);
      const entries = Array.isArray(data) ? data : data.data;
      if (Array.isArray(entries)) {
        for (const e of entries) {
          if (typeof e === 'string') items.push({ domain: e.trim(), ip: null });
          else if (e && e.domain) items.push({ domain: e.domain.trim(), ip: e.ipv4 ? e.ipv4.trim() : null });
        }
        return items;
      }
    } catch (_) { /* fall through to line parsing */ }
  }
  raw.split(/\r?\n/).forEach((line) => {
    const l = line.trim();
    if (l && !l.startsWith('#')) items.push({ domain: l, ip: null });
  });
  return items;
}

function resolveDomain(domain, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => { if (!done) { done = true; resolve(null); } }, timeoutMs);
    dns.lookup(domain, { family: 4 }, (err, address) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(err ? null : address);
    });
  });
}

// ---------------------------------------------------------------------------
// V2Ray / VLESS / VMess / Trojan / Shadowsocks config parsing + testing
// ---------------------------------------------------------------------------
function safeB64Decode(str) {
  try {
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Buffer.from(s, 'base64').toString('utf-8');
  } catch (_) { return null; }
}

function parseOneV2rayLink(line) {
  const raw = line.trim();
  if (!raw) return null;
  try {
    if (raw.startsWith('vmess://')) {
      const decoded = safeB64Decode(raw.slice(8));
      if (!decoded) return null;
      const j = JSON.parse(decoded);
      const host = j.add;
      const port = parseInt(j.port, 10);
      if (!host || !port) return null;
      const tls = (j.tls || '').toLowerCase() === 'tls';
      const sni = j.sni || j.host || host;
      return { name: j.ps || `${host}:${port}`, protocol: 'vmess', host, port, sni, tls, raw };
    }
    if (raw.startsWith('vless://') || raw.startsWith('trojan://')) {
      const protocol = raw.startsWith('vless://') ? 'vless' : 'trojan';
      const u = new URL(raw);
      const host = u.hostname;
      const port = parseInt(u.port, 10) || 443;
      if (!host || !port) return null;
      const params = u.searchParams;
      const security = (params.get('security') || '').toLowerCase();
      const tls = security === 'tls' || security === 'reality' || protocol === 'trojan';
      const sni = params.get('sni') || params.get('host') || params.get('peer') || host;
      const name = decodeURIComponent(u.hash ? u.hash.slice(1) : '') || `${host}:${port}`;
      return { name, protocol, host, port, sni, tls, raw };
    }
    if (raw.startsWith('ss://')) {
      let body = raw.slice(5);
      const hashIdx = body.indexOf('#');
      let name = null;
      if (hashIdx !== -1) { name = decodeURIComponent(body.slice(hashIdx + 1)); body = body.slice(0, hashIdx); }
      let host, port;
      if (body.includes('@')) {
        const at = body.lastIndexOf('@');
        const hostPart = body.slice(at + 1);
        const [h, p] = hostPart.split(':');
        host = h; port = parseInt(p, 10);
      } else {
        const decoded = safeB64Decode(body) || '';
        const m = decoded.match(/@([^:]+):(\d+)/);
        if (m) { host = m[1]; port = parseInt(m[2], 10); }
      }
      if (!host || !port) return null;
      return { name: name || `${host}:${port}`, protocol: 'ss', host, port, sni: host, tls: false, raw };
    }
  } catch (_) { return null; }
  return null;
}

async function parseV2raySource(source) {
  let text = source.trim();
  if (text.startsWith('http://') || text.startsWith('https://')) {
    text = await fetchUrl(text);
  }
  text = text.trim();
  if (!/^(vmess|vless|trojan|ss):\/\//m.test(text)) {
    const decoded = safeB64Decode(text.replace(/\s+/g, ''));
    if (decoded && /^(vmess|vless|trojan|ss):\/\//m.test(decoded)) text = decoded;
  }
  const items = [];
  text.split(/\r?\n/).forEach((line) => {
    const parsed = parseOneV2rayLink(line);
    if (parsed) items.push(parsed);
  });
  return items;
}

async function scanV2rayItem(item, timeoutMs, passes) {
  await tcpProbeOnce(item.host, item.port, timeoutMs);
  const latencies = [];
  let successes = 0;
  for (let i = 0; i < passes; i++) {
    const ms = await tcpProbeOnce(item.host, item.port, timeoutMs);
    if (ms !== null) { latencies.push(ms); successes++; }
  }
  const avg = latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : Infinity;
  const jitter = latencies.length > 1
    ? Math.sqrt(latencies.reduce((s, v) => s + Math.pow(v - avg, 2), 0) / latencies.length) : 0;
  const lossPct = Math.round(((passes - successes) / passes) * 1000) / 10;

  let tlsOk = false;
  if (successes > 0 && item.tls) {
    const r = await tlsCloudflareProbe(item.host, item.sni, item.port, Math.max(timeoutMs, 1500));
    tlsOk = r.tlsOk;
  }
  const handshakeOk = successes === passes && (item.tls ? tlsOk : true);
  const clean = handshakeOk && avg < 1500;
  const score = successes === 0
    ? Infinity
    : avg + jitter * 2 + (passes - successes) * 5000 + (item.tls && !tlsOk ? 3000 : 0);

  return {
    target: item.name, ip: `${item.host}:${item.port}`, domain: item.name,
    kind: item.protocol, raw: item.raw,
    avgMs: latencies.length ? Math.round(avg * 10) / 10 : null,
    medianMs: null, icmpMs: null, jitterMs: Math.round(jitter * 10) / 10, lossPct,
    successes, attempts: passes,
    tlsOk, cfVerified: handshakeOk, httpStatus: null, throughputKbps: null,
    clean, score,
  };
}

// ---------------------------------------------------------------------------
// SOCKS5 / HTTP proxy parsing + testing
// ---------------------------------------------------------------------------
const PROXY_TEST_HOST = 'www.cloudflare.com';
const PROXY_TEST_PORT = 443;

function parseProxyLine(line) {
  const l = line.trim();
  if (!l || l.startsWith('#')) return null;
  const m = l.match(/^(?:(https?|socks5?):\/\/)?(?:[^:@\/]+:[^:@\/]+@)?([\w.\-]+):(\d{2,5})$/i);
  if (!m) return null;
  let protocol = (m[1] || 'http').toLowerCase();
  if (protocol === 'socks') protocol = 'socks5';
  return { protocol, host: m[2], port: parseInt(m[3], 10) };
}

function parseProxyList(raw) {
  const items = [];
  raw.split(/\r?\n/).forEach((line) => {
    const p = parseProxyLine(line);
    if (p) items.push(p);
  });
  return items;
}

function httpProxyProbeOnce(proxyHost, proxyPort, timeoutMs) {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    let settled = false;
    const sock = new net.Socket();
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch (_) {}
      resolve(ok ? Number(process.hrtime.bigint() - start) / 1e6 : null);
    };
    sock.setTimeout(timeoutMs);
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.once('connect', () => {
      sock.write(`CONNECT ${PROXY_TEST_HOST}:${PROXY_TEST_PORT} HTTP/1.1\r\nHost: ${PROXY_TEST_HOST}:${PROXY_TEST_PORT}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });
    let buf = '';
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf-8');
      if (buf.includes('\r\n\r\n') || buf.length > 1024) {
        finish(/^HTTP\/1\.[01]\s+200/.test(buf));
      }
    });
    try { sock.connect(proxyPort, proxyHost); } catch (_) { finish(false); }
  });
}

function socks5ProxyProbeOnce(proxyHost, proxyPort, timeoutMs) {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    let settled = false;
    const sock = new net.Socket();
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch (_) {}
      resolve(ok ? Number(process.hrtime.bigint() - start) / 1e6 : null);
    };
    sock.setTimeout(timeoutMs);
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    let stage = 0;
    sock.once('connect', () => sock.write(Buffer.from([0x05, 0x01, 0x00])));
    sock.on('data', (chunk) => {
      if (stage === 0) {
        if (chunk.length >= 2 && chunk[0] === 0x05 && chunk[1] === 0x00) {
          stage = 1;
          const hostBuf = Buffer.from(PROXY_TEST_HOST, 'utf-8');
          const req = Buffer.concat([
            Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
            hostBuf,
            Buffer.from([(PROXY_TEST_PORT >> 8) & 0xff, PROXY_TEST_PORT & 0xff]),
          ]);
          sock.write(req);
        } else {
          finish(false);
        }
      } else if (stage === 1) {
        finish(chunk.length >= 2 && chunk[0] === 0x05 && chunk[1] === 0x00);
      }
    });
    try { sock.connect(proxyPort, proxyHost); } catch (_) { finish(false); }
  });
}

async function scanProxyItem(item, timeoutMs, passes) {
  // Public proxies do an extra hop (us -> proxy -> target) on top of the
  // proxy's own dial time, so the flat timeout that's fine for a direct
  // ping is too tight here and was silently failing working proxies.
  const effTimeout = Math.max(timeoutMs, 3000);
  const probeOnce = item.protocol === 'socks5' ? socks5ProxyProbeOnce : httpProxyProbeOnce;
  const latencies = [];
  let successes = 0;
  for (let i = 0; i < passes; i++) {
    const ms = await probeOnce(item.host, item.port, effTimeout);
    if (ms !== null) { latencies.push(ms); successes++; }
  }
  const avg = latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : Infinity;
  const jitter = latencies.length > 1
    ? Math.sqrt(latencies.reduce((s, v) => s + Math.pow(v - avg, 2), 0) / latencies.length) : 0;
  const lossPct = Math.round(((passes - successes) / passes) * 1000) / 10;
  // Free/scraped proxies flap constantly — requiring every single pass to
  // succeed (the old rule) marked a proxy that's genuinely usable "dead"
  // over one blip. Majority success is a fairer bar for this pool.
  const clean = successes > 0 && successes >= Math.ceil(passes / 2) && avg < 2500;
  const score = successes === 0 ? Infinity : avg + jitter * 2 + (passes - successes) * 5000;
  const label = `${item.host}:${item.port}`;
  return {
    target: label, ip: label, domain: label,
    kind: item.protocol,
    avgMs: latencies.length ? Math.round(avg * 10) / 10 : null,
    medianMs: null, icmpMs: null, jitterMs: Math.round(jitter * 10) / 10, lossPct,
    successes, attempts: passes,
    tlsOk: clean, cfVerified: clean, httpStatus: null, throughputKbps: null,
    clean, score,
  };
}

// --- CHANGE (proxyscrape.com fix) --------------------------------------
// api.proxyscrape.com's old `/v2/?request=get&...` endpoint is EOL: the
// legacy "Services API" (auth-less /v2 query-string form) was retired in
// favor of a versioned "v4" free-proxy-list endpoint. Hitting the old /v2
// URL now returns an error page (not a proxy list), which is exactly the
// "unreachable" symptom reported — it's a URL/API-version problem, not
// SSL or rate limiting. Fixed by pointing at the current v4 endpoint with
// `proxy_format=ipport`, which keeps the plain `ip:port` per line format
// the existing parser below already expects (no parser changes needed
// for this one). Source: https://docs.proxyscrape.com/api-overview and
// https://proxyscrape.com/free-proxy-list ("How do I download the full
// list via the API?").
//
// --- CHANGE (new sources) ------------------------------------------------
// Added ProxyScrape's own official GitHub-mirror dataset (served off the
// jsDelivr CDN, refreshed independently of the live API every 5 minutes)
// as an extra, infrastructurally-separate fallback for both protocols.
// That mirror emits `protocol://ip:port` rather than bare `ip:port`, so
// scrapeProxies() below now strips a leading "scheme://" before matching
// (see CHANGE comment there) — that's the only parsing change required to
// support it.
const PROXY_SCRAPE_SOURCES = {
  http: [
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt',
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt',
    // CHANGE: replaces the dead /v2 proxyscrape.com URL with the current v4 API.
    'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=ipport&format=text&timeout=10000',
    // CHANGE: new source — ProxyScrape's official GitHub mirror via jsDelivr (independent refresh cadence/infra from the live API above).
    'https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/http/data.txt',
  ],
  socks5: [
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt',
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt',
    'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt',
    // CHANGE: replaces the dead /v2 proxyscrape.com URL with the current v4 API.
    'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&proxy_format=ipport&format=text&timeout=10000',
    // CHANGE: new source — ProxyScrape's official GitHub mirror via jsDelivr (independent refresh cadence/infra from the live API above).
    'https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/socks5/data.txt',
  ],
};

// CHANGE: retry-with-backoff wrapper for scrape-source fetches. Free proxy
// sources (proxyscrape.com in particular) can transiently reset/refuse a
// connection — e.g. brief IP-based rate limiting — which previously showed
// up as a permanent "unreachable" for that source even though a second
// attempt moments later would have succeeded. This gives every source one
// retry after a short delay before being marked failed. Only touches the
// scrape path; fetchUrl() itself and its callers elsewhere are untouched.
function fetchUrlWithRetry(url, attempts = 2, delayMs = 2500) {
  return fetchUrl(url).catch((err) => {
    if (attempts <= 1) throw err;
    return new Promise((resolve) => setTimeout(resolve, delayMs)).then(() =>
      fetchUrlWithRetry(url, attempts - 1, delayMs)
    );
  });
}

async function scrapeProxies(limitPerProtocol, onSourceDone) {
  const out = [];
  const seen = new Set();
  for (const protocol of Object.keys(PROXY_SCRAPE_SOURCES)) {
    const found = [];
    const results = await Promise.allSettled(
      PROXY_SCRAPE_SOURCES[protocol].map((url) => fetchUrlWithRetry(url).then((raw) => ({ url, raw })))
    );
    results.forEach((r, i) => {
      const url = PROXY_SCRAPE_SOURCES[protocol][i];
      if (r.status !== 'fulfilled') {
        if (onSourceDone) onSourceDone({ protocol, url, ok: false, count: 0 });
        return;
      }
      let count = 0;
      r.value.raw.split(/\r?\n/).forEach((line) => {
        // CHANGE: strip an optional "scheme://" prefix before matching.
        // Needed for the new jsDelivr GitHub-mirror source, which emits
        // lines like "socks5://1.2.3.4:1080" instead of bare "ip:port".
        // Existing sources (which already emit bare ip:port) are
        // unaffected since there's nothing to strip.
        const l = line.trim().replace(/^[a-z0-9]+:\/\//i, '');
        if (/^\d{1,3}(\.\d{1,3}){3}:\d{2,5}$/.test(l)) {
          const key = protocol + l;
          if (!seen.has(key)) {
            seen.add(key);
            const [host, portStr] = l.split(':');
            found.push({ protocol, host, port: parseInt(portStr, 10) });
            count++;
          }
        }
      });
      if (onSourceDone) onSourceDone({ protocol, url, ok: true, count });
    });
    for (let i = found.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [found[i], found[j]] = [found[j], found[i]];
    }
    out.push(...(limitPerProtocol ? found.slice(0, limitPerProtocol) : found));
  }
  return out;
}

// ---------------------------------------------------------------------------
// HTTP + SSE server
// ---------------------------------------------------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function serveStatic(req, res, pathname) {
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// in-memory store of last results per session for CSV/JSON export
const lastResults = new Map();

function sseSend(res, event, payload) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

async function handleScanStream(req, res, query) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });
  res.flushHeaders && res.flushHeaders();

  const mode = query.mode || 'cf'; // 'cf' | 'domains'
  const port = parseInt(query.port || '443', 10);
  const timeout = parseInt(query.timeout || '1200', 10);
  const passes = parseInt(query.passes || '3', 10);
  const workers = parseInt(query.workers || '250', 10);
  const count = parseInt(query.count || '500', 10);
  const sessionId = query.sid || crypto.randomUUID();
  const defaultSni = (query.sni && query.sni.trim()) || 'speed.cloudflare.com';
  const useIcmp = query.icmp === '1';
  const fragTest = query.frag === '1';
  const targetMin = query.targetMin !== undefined && query.targetMin !== '' ? parseFloat(query.targetMin) : undefined;
  const targetMax = query.targetMax !== undefined && query.targetMax !== '' ? parseFloat(query.targetMax) : undefined;
  const scanOpts = { useIcmp, targetMin, targetMax, fragTest };

  const keepAlive = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => clearInterval(keepAlive));

  try {
    let items = [];
    let scanFn = null;

    if (mode === 'cf') {
      const ips = sampleIpsFromRanges(CF_RANGES, count);
      items = ips.map((ip) => ({ target: ip, ip, sni: defaultSni }));
      scanFn = (item) => scanTarget(item.target, item.ip, port, timeout, passes, item.sni, scanOpts);
      sseSend(res, 'info', { message: `${ips.length} IPs sampled from Cloudflare ranges`, total: items.length });
    } else if (mode === 'domains') {
      const source = query.source || '';
      const resolveDns = query.resolveDns === '1';
      sseSend(res, 'info', { message: 'Loading domain list...', total: 0 });
      const domainItems = await loadDomainsSource(source);
      let resolvedCount = 0;
      const resolveWorkers = Math.min(workers, 100, domainItems.length || 1);
      sseSend(res, 'info', { message: `Resolving ${domainItems.length} domains...`, total: domainItems.length });
      const resolved = await runPool(domainItems, resolveWorkers, async (di) => {
        let ip = di.ip;
        if (resolveDns || !ip) {
          const r = await resolveDomain(di.domain, 2500);
          ip = r || ip;
        }
        resolvedCount++;
        sseSend(res, 'resolveProgress', { done: resolvedCount, total: domainItems.length });
        if (!ip) return null;
        return { target: di.domain, ip, sni: di.domain };
      });
      const skipped = domainItems.length - resolved.length;
      items = resolved;
      scanFn = (item) => scanTarget(item.target, item.ip, port, timeout, passes, item.sni, scanOpts);
      sseSend(res, 'info', {
        message: `${items.length} domains ready to scan (${skipped} skipped due to failed resolve)`,
        total: items.length,
      });
    } else if (mode === 'v2ray') {
      const source = query.v2raySource || '';
      sseSend(res, 'info', { message: 'Parsing V2Ray/VLESS/Trojan/SS configs...', total: 0 });
      items = await parseV2raySource(source);
      scanFn = (item) => scanV2rayItem(item, timeout, passes);
      sseSend(res, 'info', { message: `${items.length} configs parsed and ready to test`, total: items.length });
    } else if (mode === 'proxy') {
      const raw = query.proxyList || '';
      items = parseProxyList(raw);
      scanFn = (item) => scanProxyItem(item, timeout, passes);
      sseSend(res, 'info', { message: `${items.length} proxies parsed and ready to test`, total: items.length });
    } else if (mode === 'proxyscrape') {
      const limit = parseInt(query.scrapeLimit || '150', 10);
      const totalSources = Object.values(PROXY_SCRAPE_SOURCES).reduce((n, arr) => n + arr.length, 0);
      sseSend(res, 'info', { message: `Scraping ${totalSources} public proxy sources...`, total: 0 });
      items = await scrapeProxies(limit, (s) => {
        const host = s.url.replace(/^https?:\/\//, '').split('/')[0];
        sseSend(res, 'scrapesource', {
          protocol: s.protocol, host, ok: s.ok, count: s.count,
        });
      });
      scanFn = (item) => scanProxyItem(item, timeout, passes);
      sseSend(res, 'info', { message: `${items.length} unique proxies scraped, ready to test`, total: items.length });
    }

    sseSend(res, 'start', { total: items.length, mode });

    const results = await runPool(items, workers, async (item) => {
      const r = await scanFn(item);
      sseSend(res, 'result', r);
      return r;
    }, (done, total) => {
      sseSend(res, 'progress', { done, total });
    });

    results.sort((a, b) => a.score - b.score);
    lastResults.set(sessionId, results);

    const cleanCount = results.filter((r) => r.clean).length;
    sseSend(res, 'done', {
      total: results.length,
      clean: cleanCount,
      sessionId,
    });
  } catch (err) {
    sseSend(res, 'scanerror', { message: String(err && err.message ? err.message : err) });
  } finally {
    clearInterval(keepAlive);
    res.end();
  }
}

function handleExport(req, res, query) {
  const sessionId = query.sid;
  const format = query.format || 'json';
  const results = lastResults.get(sessionId) || [];
  if (format === 'csv') {
    const lines = ['rank,type,ip,domain,avg_ms,median_ms,icmp_ms,jitter_ms,loss_pct,successes,attempts,tls_ok,verified,throughput_kbps,frag_tls_ok,dpi_bypass,clean,score'];
    results.forEach((r, i) => {
      lines.push([i + 1, r.kind || '', r.ip, r.domain || '', r.avgMs ?? '', r.medianMs ?? '', r.icmpMs ?? '', r.jitterMs, r.lossPct, r.successes, r.attempts, r.tlsOk, r.cfVerified, r.throughputKbps ?? '', r.fragTlsOk ?? '', r.dpiBypass ?? '', r.clean, Math.round(r.score * 10) / 10].join(','));
    });
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="cfradar_results.csv"',
    });
    res.end(lines.join('\n'));
  } else if (format === 'cleanips') {
    // For domain-mode results, output "domain,ip" so the domain isn't lost
    // (needed for SNI/Host when actually using the IP). Pure-IP (cf-range)
    // results stay as plain IPs.
    const lines = results
      .filter((r) => r.clean)
      .map((r) => (r.raw ? r.raw : (r.domain ? `${r.domain},${r.ip}` : r.ip)));
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': 'attachment; filename="clean_ips.txt"',
    });
    res.end(lines.join('\n'));
  } else {
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': 'attachment; filename="cfradar_results.json"',
    });
    res.end(JSON.stringify(results, null, 2));
  }
}

// ---------------------------------------------------------------------------
// VPN/proxy detection for the machine running this server. Scan results
// only mean something if they reflect the user's real ISP path — if a VPN
// or system-wide proxy is active, every latency/DPI-bypass number measured
// is about the VPN's network, not the user's actual connection. This asks
// a public IP-intelligence API, which sees whatever the current outbound
// path actually is (VPN or not), the same as any other traffic would.
// ---------------------------------------------------------------------------
function handleNetworkCheck(req, res) {
  const apiUrl = 'http://ip-api.com/json/?fields=status,message,query,isp,org,as,proxy,hosting,mobile,country,city';
  fetchUrl(apiUrl).then((raw) => {
    let data;
    try { data = JSON.parse(raw); } catch (_) { data = null; }
    if (!data || data.status !== 'success') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, checked: false, reason: 'lookup_failed' }));
      return;
    }
    const flagged = !!(data.proxy || data.hosting);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true, checked: true, flagged,
      ip: data.query, isp: data.isp, org: data.org, asn: data.as,
      country: data.country, city: data.city, mobile: !!data.mobile,
    }));
  }).catch(() => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, checked: false, reason: 'network_error' }));
  });
}

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const query = Object.fromEntries(parsedUrl.searchParams.entries());

  if (pathname === '/api/scan-stream') {
    handleScanStream(req, res, query);
    return;
  }
  if (pathname === '/api/export') {
    handleExport(req, res, query);
    return;
  }
  if (pathname === '/api/network-check') {
    handleNetworkCheck(req, res);
    return;
  }
  serveStatic(req, res, pathname);
});

server.listen(PORT, () => {
  console.log(`\n  CFRadar is running →  http://localhost:${PORT}\n`);
});
