#!/usr/bin/env node
/**
 * CFRadar Build Script
 * Bundles public/index.html, public/style.css, public/app.js
 * into a single worker-bundle.js ready for Cloudflare Workers deployment.
 */
'use strict';

const fs = require('fs');
const path = require('path');

// NOTE: the Cloudflare Worker build intentionally uses public-worker/, not
// public/. public/ is the full local-only UI (V2Ray + SOCKS/HTTP proxy
// scanning, scraping) which needs raw TCP/SOCKS handshakes that only the
// local Node server (server.js, with real `net`/`tls` sockets) can do.
// Workers can't fan out hundreds of raw TCP connections per request the
// same way, so the deployed edge version stays on the proven CF-range +
// domain scanner that already deploys and runs cleanly.
const PUBLIC = path.join(__dirname, 'public-worker');
const WORKER_SRC = path.join(__dirname, 'worker.js');
const WORKER_OUT = path.join(__dirname, 'worker-bundle.js');

function readFile(name) {
  return fs.readFileSync(path.join(PUBLIC, name), 'utf-8');
}

function escapeTemplateLiteral(str) {
  // Escape backticks and ${} so the string is safe inside a JS template literal
  return str.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
}

console.log('📦  Reading source files…');
const indexHtml = readFile('index.html');
const styleCss  = readFile('style.css');
const appJs     = readFile('app.js');

console.log('📝  Reading worker template…');
let worker = fs.readFileSync(WORKER_SRC, 'utf-8');

// Inject static files between the BUILD_INJECT markers
const inject = `// BUILD_INJECT_START
const INDEX_HTML = \`${escapeTemplateLiteral(indexHtml)}\`;
const STYLE_CSS  = \`${escapeTemplateLiteral(styleCss)}\`;
const APP_JS     = \`${escapeTemplateLiteral(appJs)}\`;
// BUILD_INJECT_END`;

worker = worker.replace(
  /\/\/ BUILD_INJECT_START[\s\S]*?\/\/ BUILD_INJECT_END/,
  inject
);

fs.writeFileSync(WORKER_OUT, worker, 'utf-8');
const sizeKb = Math.round(fs.statSync(WORKER_OUT).size / 1024);
console.log(`✅  worker-bundle.js written (${sizeKb} KB) — ready to deploy.`);
console.log('');
console.log('   Deploy with:  node deploy.js --token YOUR_API_TOKEN --account YOUR_ACCOUNT_ID');
console.log('   Or with wrangler: npx wrangler deploy --name cfradar');
