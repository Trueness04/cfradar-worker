#!/usr/bin/env node
/**
 * CFRadar — Cloudflare Workers Deploy Script
 * Usage: node deploy.js --token CF_API_TOKEN --account ACCOUNT_ID [--name cfradar]
 *
 * No npm install needed — uses only Node.js built-ins.
 * Get your API token: https://dash.cloudflare.com/profile/api-tokens
 *   → Create Token → "Edit Cloudflare Workers" template
 * Get your Account ID: Cloudflare dashboard → right sidebar on any domain
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const https = require('https');

// ── parse CLI args ─────────────────────────────────────────────────────────
const args = {};
process.argv.slice(2).forEach((a, i, arr) => {
  if (a.startsWith('--')) args[a.slice(2)] = arr[i + 1] || true;
});

const TOKEN      = args.token   || process.env.CF_API_TOKEN;
const ACCOUNT_ID = args.account || process.env.CF_ACCOUNT_ID;
const WORKER_NAME = args.name  || 'cfradar';
const BUNDLE_PATH = path.join(__dirname, 'worker-bundle.js');

// ── validate ───────────────────────────────────────────────────────────────
if (!TOKEN) {
  console.error('❌  Missing --token or CF_API_TOKEN env var');
  console.error('   Get it at: https://dash.cloudflare.com/profile/api-tokens');
  process.exit(1);
}
if (!ACCOUNT_ID) {
  console.error('❌  Missing --account or CF_ACCOUNT_ID env var');
  console.error('   Find it in: Cloudflare dashboard → right sidebar');
  process.exit(1);
}
if (!fs.existsSync(BUNDLE_PATH)) {
  console.error('❌  worker-bundle.js not found. Run `node build.js` first.');
  process.exit(1);
}

// ── helpers ────────────────────────────────────────────────────────────────
function cfRequest(method, endpoint, body, contentType) {
  return new Promise((resolve, reject) => {
    const url = new URL(`https://api.cloudflare.com/client/v4${endpoint}`);
    const bodyBuf = body ? Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)) : null;

    const req = https.request({
      hostname: url.hostname,
      path: url.pathname + url.search,
      method,
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'Content-Type': contentType || 'application/json',
        ...(bodyBuf ? { 'Content-Length': bodyBuf.length } : {}),
      },
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

// Multipart form upload (required for Workers script upload)
function uploadWorker(scriptContent) {
  return new Promise((resolve, reject) => {
    const boundary = '----CFRadarDeploy' + Date.now();
    const scriptBuf = Buffer.from(scriptContent, 'utf-8');

    // metadata part
    const meta = JSON.stringify({
      main_module: 'worker-bundle.js',
      bindings: [],
      compatibility_date: '2024-01-01',
      compatibility_flags: ['nodejs_compat'],
    });

    const metaPart = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="metadata"\r\n` +
      `Content-Type: application/json\r\n\r\n` +
      `${meta}\r\n`
    );
    const scriptPart = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="worker-bundle.js"; filename="worker-bundle.js"\r\n` +
      `Content-Type: application/javascript+module\r\n\r\n`
    );
    const ending = Buffer.from(`\r\n--${boundary}--\r\n`);

    const body = Buffer.concat([metaPart, scriptPart, scriptBuf, ending]);

    const req = https.request({
      hostname: 'api.cloudflare.com',
      path: `/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}`,
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': body.length,
      },
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── main ───────────────────────────────────────────────────────────────────
async function main() {
  console.log('');
  console.log('🚀  CFRadar — Cloudflare Workers Deploy');
  console.log(`    Worker name : ${WORKER_NAME}`);
  console.log(`    Account ID  : ${ACCOUNT_ID}`);
  console.log('');

  // Step 1: verify token
  process.stdout.write('🔑  Verifying API token… ');
  const tokenCheck = await cfRequest('GET', '/user/tokens/verify');
  if (!tokenCheck.body.success) {
    console.error('\n❌  Invalid token:', JSON.stringify(tokenCheck.body.errors));
    process.exit(1);
  }
  console.log('✓');

  // Step 2: read bundle
  process.stdout.write('📦  Reading worker-bundle.js… ');
  const script = fs.readFileSync(BUNDLE_PATH, 'utf-8');
  const sizeKb = Math.round(Buffer.byteLength(script) / 1024);
  console.log(`${sizeKb} KB`);

  if (sizeKb > 1024) {
    console.warn('⚠   Bundle is >1MB — Workers free plan limit is 1MB. Consider compressing.');
  }

  // Step 3: upload worker script
  process.stdout.write(`📤  Uploading script to Workers (name: "${WORKER_NAME}")… `);
  const upload = await uploadWorker(script);
  if (!upload.body.success) {
    console.error('\n❌  Upload failed:');
    console.error(JSON.stringify(upload.body.errors || upload.body, null, 2));
    process.exit(1);
  }
  console.log('✓');

  // Step 4: enable Workers.dev subdomain (so it's accessible without a custom domain)
  process.stdout.write('🌐  Enabling workers.dev subdomain… ');
  const subdomain = await cfRequest(
    'POST',
    `/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}/subdomain`,
    { enabled: true }
  );
  if (!subdomain.body.success) {
    // Non-fatal — might already be enabled
    console.log('(already enabled or skipped)');
  } else {
    console.log('✓');
  }

  // Step 5: get the workers.dev URL
  let workerUrl = `https://${WORKER_NAME}.${ACCOUNT_ID.slice(0, 8)}.workers.dev`;
  try {
    const subInfo = await cfRequest('GET', `/accounts/${ACCOUNT_ID}/workers/subdomain`);
    if (subInfo.body.success && subInfo.body.result && subInfo.body.result.subdomain) {
      workerUrl = `https://${WORKER_NAME}.${subInfo.body.result.subdomain}.workers.dev`;
    }
  } catch (_) { /* use fallback URL */ }

  console.log('');
  console.log('✅  Deploy complete!');
  console.log('');
  console.log(`   🔗  Your CFRadar URL:`);
  console.log(`       ${workerUrl}`);
  console.log('');
  console.log('   ℹ️   If the URL doesn\'t work immediately, wait ~30 seconds for propagation.');
  console.log('   ℹ️   To use a custom domain, add a route in the Cloudflare dashboard.');
  console.log('');
}

main().catch((err) => {
  console.error('❌  Unexpected error:', err.message || err);
  process.exit(1);
});
