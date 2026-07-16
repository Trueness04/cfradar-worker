# CFRadar Ultimate — Cloudflare IP / Domain / V2Ray / Proxy Scanner

Real Node.js backend, no `npm install` needed. Five scan modes, all ranked by
RANK + LATENCY, all in one dashboard.

## Run locally (full feature set)

```bash
node server.js
```

Open `http://localhost:7777`. Tabs are now a **vertical sidebar** on the left
(design untouched otherwise):

1. **Cloudflare Range** — samples IPs from Cloudflare's official ranges, real
   TCP + TLS + throughput probes, ICMP option, target-latency band.
2. **Domain List** — same probes against a domain list (JSON or plain text).
3. **V2Ray Configs** *(new)* — paste a subscription URL or raw
   `vmess://` / `vless://` / `trojan://` / `ss://` links (one per line).
   Every config gets a real TCP handshake (+ TLS probe if it uses TLS).
   Ranked by latency; the **3 fastest** show up in a "Top 3" box below the
   table with one-click copy of the original config string.
4. **Proxy List (SOCKS/HTTP)** *(new)* — paste `ip:port`, `http://ip:port` or
   `socks5://ip:port`, one per line. HTTP proxies are tested with a real
   `CONNECT` tunnel; SOCKS5 with a real SOCKS5 handshake — both against a live
   Cloudflare endpoint, so "alive" actually means "can tunnel real traffic."
5. **Scrape & Scan Proxies** *(new)* — pulls fresh HTTP + SOCKS5 proxy lists
   from public sources, dedupes, and runs them through the same real
   handshake test automatically. No list to paste.

Every mode's results table now has a **RANK** column (`#`) and a **Type**
column, and is always sorted by score (which is driven primarily by
**LATENCY**). Export buttons (Clean list / CSV / JSON) work for all five modes
— for V2Ray mode, the "clean" export gives you the original config strings,
ready to paste into your client.

## Deploy to Cloudflare (no token needed — opens in your browser)

```bash
node build.js
npx wrangler deploy --name cfradar
```

`wrangler` will open `dash.cloudflare.com` in your browser for OAuth login —
exactly like last time, no manual token required. This is the same flow that
already worked for you.

### Important honesty note about what gets deployed

The **deployed Cloudflare Worker only serves modes 1 and 2** (Cloudflare
Range + Domain List) — the same ones that already deployed successfully
before. It does **not** include the new V2Ray/Proxy/Scrape tabs.

Why: Workers can't open hundreds of raw parallel TCP/SOCKS5 connections to
arbitrary hosts the way a local Node process can (`net`/`tls` sockets aren't
available there the same way, and Workers' CPU-time budget per request isn't
built for that kind of fan-out). The old CF-range scanner works on Workers
because it's clever about it — it uses `fetch()` with a spoofed `Host` header
instead of a raw socket. Porting real SOCKS5 handshakes and V2Ray probing to
Workers is possible via the `cloudflare:sockets` API, but it's a genuinely
different, riskier piece of work that I can't verify without an actual
deploy — and given the last few rounds, I'd rather tell you that up front
than hand you something that silently breaks again.

**So: run `node server.js` locally for the full 5-mode "ultimate" scanner.
The deployed edge version is the reliable subset.** If you want, I can take
a shot at the Workers `cloudflare:sockets` port next as a separate step.

## Files

```
cfradar-worker/
├── server.js          ← full local scanner, all 5 modes (Node built-ins only)
├── public/             ← UI for server.js (full feature set)
│   ├── index.html
│   ├── style.css
│   └── app.js
├── public-worker/       ← UI for the deployed Worker (CF range + domains only)
├── worker.js           ← Cloudflare Worker source
├── build.js            ← bundles public-worker/ + worker.js → worker-bundle.js
├── deploy.js           ← optional token-based deploy (fallback)
└── wrangler.toml
```
