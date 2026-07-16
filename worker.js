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
const INDEX_HTML = `__INDEX_HTML__`;
const STYLE_CSS = `__STYLE_CSS__`;
const APP_JS = `__APP_JS__`;
// BUILD_INJECT_END
