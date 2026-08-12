# راهنمای پیاده‌سازی ۴ قابلیت کلیدی برای CFRadar

## نمای کلی پروژه
- **زبان**: JavaScript (Node.js >= 18)
- **وابستگی‌ها**: هیچ - فقط ماژول‌های داخلی Node.js
- **ساختار**: 
  - `server.js`: هسته اصلی اسکنر و API
  - `public/app.js`: رابط کاربری فرانت‌اند
  - `public/index.html`: صفحه HTML

---

## ۱. توسعه دامنه اسکن: دامنه‌های خارجی پشت کلادفلر

### گام ۱: اضافه کردن لیست دامنه‌های خارجی پرتکرار

در `server.js`، بعد از `CF_RANGES`، یک ساختار جدید برای دامنه‌ها اضافه کنید:

```javascript
// ---------------------------------------------------------------------------
// Domain lists: Iranian + International Cloudflare-backed domains
// ---------------------------------------------------------------------------
const IRANIAN_DOMAINS = [
  'digikala.com', 'torob.com', 'emalls.ir', 'divar.ir',
  'sheypoor.com', 'bazzar.ir', 'chocobar.ir', // ... add more
];

const INTERNATIONAL_DOMAINS = [
  'cdnjs.cloudflare.com', 'jsdelivr.net', 'unpkg.com',
  'stackpath.bootstrapcdn.com', 'fonts.googleapis.com',
  'fonts.gstatic.com', 'assets.github.com', // ... add more
];

const DOMAIN_LISTS = {
  iranian: IRANIAN_DOMAINS,
  international: INTERNATIONAL_DOMAINS,
  combined: [...IRANIAN_DOMAINS, ...INTERNATIONAL_DOMAINS],
};
```

### گام ۲: به‌روزرسانی `loadDomainsSource()`

تابع فعلی را طوری تغییر دهید که از پارامتر `region` پشتیبانی کند:

```javascript
async function loadDomainsSource(source, region = 'combined') {
  if (source && source !== 'default') {
    // Custom list from user
    return source.split(/[\n,]+/).map(s => s.trim()).filter(s => s).map(domain => ({ domain }));
  }
  
  // Use predefined lists
  const list = DOMAIN_LISTS[region] || DOMAIN_LISTS.combined;
  return list.map(domain => ({ domain }));
}
```

### گام ۳: اضافه کردن پارامتر `region` به API

در `handleScanStream()`، پارامتر جدیدی اضافه کنید:

```javascript
const region = query.region || 'combined'; // 'iranian' | 'international' | 'combined'

// در بخش domains mode:
} else if (mode === 'domains') {
  const source = query.source || '';
  const resolveDns = query.resolveDns === '1';
  // ...
  const domainItems = await loadDomainsSource(source, region);
  // ...
}
```

### گام ۴: به‌روزرسانی UI

در `public/index.html`، تب Domains را به‌روزرسانی کنید:

```html
<!-- در تب domains -->
<div class="form-group">
  <label>Region:</label>
  <select id="domainRegion">
    <option value="combined">Both (Iranian + International)</option>
    <option value="iranian">Iranian Only</option>
    <option value="international">International Only</option>
  </select>
</div>

<div class="form-group">
  <label>Custom Domain List (optional):</label>
  <textarea id="customDomains" placeholder="example.com&#10;test.org"></textarea>
</div>
```

در `public/app.js`، تابع `buildUrl()` را به‌روزرسانی کنید:

```javascript
} else if (mode === 'domains') {
  params.set('source', document.getElementById('domainsSource').value);
  params.set('region', document.getElementById('domainRegion').value);
  params.set('resolveDns', document.getElementById('resolveDns').checked ? '1' : '0');
  params.set('count', '0');
}
```

### گام ۵: فیلتر و گزارش‌گیری مجزا

در `handleExport()`، امکان فیلتر بر اساس منطقه را اضافه کنید:

```javascript
function handleExport(req, res, query) {
  const sessionId = query.sid;
  const format = query.format || 'json';
  const regionFilter = query.region; // optional filter
  
  let results = lastResults.get(sessionId) || [];
  
  if (regionFilter && regionFilter !== 'combined') {
    results = results.filter(r => {
      if (regionFilter === 'iranian') {
        return IRANIAN_DOMAINS.includes(r.domain);
      } else if (regionFilter === 'international') {
        return INTERNATIONAL_DOMAINS.includes(r.domain);
      }
      return true;
    });
  }
  
  // ادامه کد export...
}
```

---

## ۲. یکپارچه‌سازی دیتابیس سبک (SQLite)

### گام ۱: نصب better-sqlite3

```bash
npm install better-sqlite3 --save
```

یا برای حفظ سبک‌بودن، از JSON استفاده کنید (بدون نیاز به نصب).

### گزینه A: SQLite (توصیه شده)

### گام ۲: ایجاد ماژول دیتابیس

فایل جدید `db.js` ایجاد کنید:

```javascript
'use strict';
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, 'cfradar.db');
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS cloudflare_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    port INTEGER DEFAULT 443,
    avg_ms REAL,
    median_ms REAL,
    icmp_ms REAL,
    jitter_ms REAL,
    loss_pct REAL,
    successes INTEGER,
    attempts INTEGER,
    tls_ok INTEGER,
    cf_verified INTEGER,
    throughput_kbps INTEGER,
    clean INTEGER,
    score REAL,
    country_code TEXT,
    country_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    ip TEXT,
    region TEXT, -- 'iranian' or 'international'
    avg_ms REAL,
    score REAL,
    clean INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT, -- 'http' or 'socks5'
    avg_ms REAL,
    loss_pct REAL,
    clean INTEGER,
    score REAL,
    country_code TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host, port, protocol)
  );
  
  CREATE TABLE IF NOT EXISTS v2ray_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_hash TEXT UNIQUE NOT NULL,
    config_raw TEXT,
    type TEXT, -- 'vless', 'vmess', 'trojan', 'ss'
    avg_ms REAL,
    clean INTEGER,
    score REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS score_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_type TEXT NOT NULL, -- 'ip', 'domain', 'proxy', 'v2ray'
    item_id TEXT NOT NULL,
    score REAL,
    avg_ms REAL,
    clean INTEGER,
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE INDEX IF NOT EXISTS idx_ips_score ON cloudflare_ips(score);
  CREATE INDEX IF NOT EXISTS idx_ips_clean ON cloudflare_ips(clean);
  CREATE INDEX IF NOT EXISTS idx_domains_region ON domains(region);
  CREATE INDEX IF NOT EXISTS idx_proxies_score ON proxies(score);
  CREATE INDEX IF NOT EXISTS idx_history_item ON score_history(item_type, item_id);
`);

// Cache layer to avoid repeated queries
const cache = new Map();
const CACHE_TTL = 60000; // 1 minute

function getWithCache(key, queryFn) {
  const cached = cache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  const data = queryFn();
  cache.set(key, { data, timestamp: Date.now() });
  return data;
}

module.exports = {
  db,
  
  // Cloudflare IPs
  saveIp(result) {
    const stmt = db.prepare(`
      INSERT INTO cloudflare_ips 
        (ip, port, avg_ms, median_ms, icmp_ms, jitter_ms, loss_pct, 
         successes, attempts, tls_ok, cf_verified, throughput_kbps, 
         clean, score, country_code, country_name)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(ip) DO UPDATE SET
        port = excluded.port,
        avg_ms = excluded.avg_ms,
        median_ms = excluded.median_ms,
        icmp_ms = excluded.icmp_ms,
        jitter_ms = excluded.jitter_ms,
        loss_pct = excluded.loss_pct,
        successes = excluded.successes,
        attempts = excluded.attempts,
        tls_ok = excluded.tls_ok,
        cf_verified = excluded.cf_verified,
        throughput_kbps = excluded.throughput_kbps,
        clean = excluded.clean,
        score = excluded.score,
        country_code = excluded.country_code,
        country_name = excluded.country_name,
        updated_at = CURRENT_TIMESTAMP
    `);
    
    stmt.run(
      result.ip, result.port || 443, result.avgMs, result.medianMs,
      result.icmpMs, result.jitterMs, result.lossPct,
      result.successes, result.attempts, result.tlsOk ? 1 : 0,
      result.cfVerified ? 1 : 0, result.throughputKbps,
      result.clean ? 1 : 0, result.score,
      result.countryCode || null, result.countryName || null
    );
    
    // Save score history
    if (result.score !== undefined) {
      db.prepare(`
        INSERT INTO score_history (item_type, item_id, score, avg_ms, clean)
        VALUES ('ip', ?, ?, ?, ?)
      `).run(result.ip, result.score, result.avgMs, result.clean ? 1 : 0);
    }
  },
  
  getTopIps(limit = 100) {
    return getWithCache('top_ips_' + limit, () => 
      db.prepare(`SELECT * FROM cloudflare_ips WHERE clean = 1 ORDER BY score ASC LIMIT ?`).all(limit)
    );
  },
  
  // Domains
  saveDomain(domain, result, region) {
    const stmt = db.prepare(`
      INSERT INTO domains (domain, ip, region, avg_ms, score, clean)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(domain) DO UPDATE SET
        ip = excluded.ip,
        region = excluded.region,
        avg_ms = excluded.avg_ms,
        score = excluded.score,
        clean = excluded.clean,
        updated_at = CURRENT_TIMESTAMP
    `);
    stmt.run(domain, result.ip, region, result.avgMs, result.score, result.clean ? 1 : 0);
  },
  
  // Proxies
  saveProxy(result) {
    const stmt = db.prepare(`
      INSERT INTO proxies (host, port, protocol, avg_ms, loss_pct, clean, score, country_code)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(host, port, protocol) DO UPDATE SET
        avg_ms = excluded.avg_ms,
        loss_pct = excluded.loss_pct,
        clean = excluded.clean,
        score = excluded.score,
        country_code = excluded.country_code,
        updated_at = CURRENT_TIMESTAMP
    `);
    
    const [host, port] = result.target.split(':');
    stmt.run(host, port, result.kind, result.avgMs, result.lossPct, 
             result.clean ? 1 : 0, result.score, result.countryCode || null);
  },
  
  // Export functions
  exportToCSV(table) {
    const rows = db.prepare(`SELECT * FROM ${table}`).all();
    if (rows.length === 0) return '';
    
    const headers = Object.keys(rows[0]).join(',');
    const data = rows.map(r => Object.values(r).map(v => 
      typeof v === 'string' ? `"${v.replace(/"/g, '""')}"` : v
    ).join(',')).join('\n');
    
    return headers + '\n' + data;
  },
  
  exportToJson(table) {
    return JSON.stringify(db.prepare(`SELECT * FROM ${table}`).all(), null, 2);
  },
  
  // Backup
  backupDatabase(backupPath) {
    const backup = new Database(backupPath);
    db.backup(backup);
    backup.close();
  },
  
  // Cleanup old entries
  cleanupOldEntries(days = 30) {
    db.prepare(`DELETE FROM score_history WHERE recorded_at < datetime('now', '-' || ? || ' days')`).run(days);
  }
};
```

### گام ۳: یکپارچه‌سازی با `server.js`

در ابتدای `server.js`:

```javascript
const db = require('./db');
```

در `handleScanStream()`، هر نتیجه را ذخیره کنید:

```javascript
es.addEventListener('result', (e) => {
  const r = JSON.parse(e.data);
  results.push(r);
  
  // Save to database
  if (mode === 'cf') {
    db.saveIp(r);
  } else if (mode === 'domains') {
    db.saveDomain(r.domain, r, region);
  } else if (mode === 'proxy' || mode === 'proxyscrape') {
    db.saveProxy(r);
  }
  
  addBlip(statusOf(r));
  // ...
});
```

### گزینه B: JSON (بدون وابستگی)

اگر نمی‌خواهید وابستگی اضافه کنید، از ساختار JSON استفاده کنید:

```javascript
// db-json.js
const fs = require('fs');
const path = require('path');

const DB_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR);

const DB_FILES = {
  ips: path.join(DB_DIR, 'ips.json'),
  domains: path.join(DB_DIR, 'domains.json'),
  proxies: path.join(DB_DIR, 'proxies.json'),
  history: path.join(DB_DIR, 'score_history.json'),
};

function loadDb(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
}

function saveDb(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

module.exports = {
  saveIp(result) {
    const ips = loadDb(DB_FILES.ips);
    const idx = ips.findIndex(i => i.ip === result.ip);
    if (idx >= 0) {
      ips[idx] = { ...ips[idx], ...result, updatedAt: new Date().toISOString() };
    } else {
      ips.push({ ...result, createdAt: new Date().toISOString() });
    }
    saveDb(DB_FILES.ips, ips);
  },
  // ... سایر متدها مشابه
};
```

---

## ۳. سیستم رنکینگ و امتیازدهی

### گام ۱: تعریف وزن‌ها و پارامترها

در `server.js`، ثابت‌های جدید اضافه کنید:

```javascript
// ---------------------------------------------------------------------------
// Scoring System Configuration
// ---------------------------------------------------------------------------
const SCORING_WEIGHTS = {
  ping: 0.40,        // 40% weight for latency
  speed: 0.35,       // 35% weight for throughput
  stability: 0.25,   // 25% weight for packet loss/jitter
};

const SCORING_THRESHOLDS = {
  excellent: 20,     // ms - excellent ping
  good: 50,          // ms - good ping
  acceptable: 150,   // ms - acceptable ping
};

const SPEED_THRESHOLDS = {
  excellent: 500,    // KB/s
  good: 200,         // KB/s
  acceptable: 50,    // KB/s
};

function calculateScore(result, weights = SCORING_WEIGHTS) {
  // Normalize each component to 0-100 scale
  let pingScore = 100;
  if (result.avgMs !== null && result.avgMs !== undefined) {
    if (result.avgMs <= SCORING_THRESHOLDS.excellent) pingScore = 100;
    else if (result.avgMs <= SCORING_THRESHOLDS.good) {
      pingScore = 100 - ((result.avgMs - SCORING_THRESHOLDS.excellent) / 
                        (SCORING_THRESHOLDS.good - SCORING_THRESHOLDS.excellent)) * 30;
    } else if (result.avgMs <= SCORING_THRESHOLDS.acceptable) {
      pingScore = 70 - ((result.avgMs - SCORING_THRESHOLDS.good) / 
                       (SCORING_THRESHOLDS.acceptable - SCORING_THRESHOLDS.good)) * 40;
    } else {
      pingScore = Math.max(0, 30 - (result.avgMs - SCORING_THRESHOLDS.acceptable) / 10);
    }
  }
  
  let speedScore = 100;
  if (result.throughputKbps !== null && result.throughputKbps !== undefined) {
    if (result.throughputKbps >= SPEED_THRESHOLDS.excellent) speedScore = 100;
    else if (result.throughputKbps >= SPEED_THRESHOLDS.good) {
      speedScore = 70 + ((result.throughputKbps - SPEED_THRESHOLDS.good) / 
                        (SPEED_THRESHOLDS.excellent - SPEED_THRESHOLDS.good)) * 30;
    } else if (result.throughputKbps >= SPEED_THRESHOLDS.acceptable) {
      speedScore = 30 + ((result.throughputKbps - SPEED_THRESHOLDS.acceptable) / 
                        (SPEED_THRESHOLDS.good - SPEED_THRESHOLDS.acceptable)) * 40;
    } else {
      speedScore = (result.throughputKbps / SPEED_THRESHOLDS.acceptable) * 30;
    }
  }
  
  let stabilityScore = 100;
  if (result.lossPct !== null && result.lossPct !== undefined) {
    stabilityScore = Math.max(0, 100 - result.lossPct * 2);
  }
  if (result.jitterMs !== null && result.jitterMs !== undefined) {
    stabilityScore = Math.min(stabilityScore, Math.max(0, 100 - result.jitterMs));
  }
  
  // Weighted average
  const finalScore = (
    pingScore * weights.ping +
    speedScore * weights.speed +
    stabilityScore * weights.stability
  );
  
  return Math.round(finalScore * 10) / 10;
}

function getRating(score) {
  if (score >= 85) return { stars: 5, color: '#00e68a', label: 'Excellent' };
  if (score >= 70) return { stars: 4, color: '#4de8ff', label: 'Good' };
  if (score >= 50) return { stars: 3, color: '#ffb020', label: 'Fair' };
  if (score >= 30) return { stars: 2, color: '#ff9f43', label: 'Poor' };
  return { stars: 1, color: '#ff4d5e', label: 'Very Poor' };
}
```

### گام ۲: اجرای تست‌های چندمرحله‌ای

تابع `scanTarget()` را به‌روزرسانی کنید تا چندین بار تست بگیرد:

```javascript
async function scanTargetWithRetries(target, ip, port, timeoutMs, passes, sniHost, opts, retries = 3) {
  const allResults = [];
  
  for (let i = 0; i < retries; i++) {
    const result = await scanTarget(target, ip, port, timeoutMs, passes, sniHost, opts);
    allResults.push(result);
    
    if (i < retries - 1) {
      // Wait between tests (1-3 seconds random)
      await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
    }
  }
  
  // Average the results
  const avgResult = {
    ...allResults[0],
    avgMs: allResults.reduce((sum, r) => sum + (r.avgMs || 0), 0) / retries,
    medianMs: allResults.reduce((sum, r) => sum + (r.medianMs || 0), 0) / retries,
    jitterMs: allResults.reduce((sum, r) => sum + (r.jitterMs || 0), 0) / retries,
    lossPct: allResults.reduce((sum, r) => sum + (r.lossPct || 0), 0) / retries,
    throughputKbps: allResults.reduce((sum, r) => sum + (r.throughputKbps || 0), 0) / retries,
  };
  
  // Calculate final score
  avgResult.score = calculateScore(avgResult);
  avgResult.rating = getRating(avgResult.score);
  
  return avgResult;
}
```

### گام ۳: نمایش امتیاز در UI

در `public/app.js`، تابع `renderTable()` را به‌روزرسانی کنید:

```javascript
function ratingStarsHtml(rating) {
  const stars = '★'.repeat(rating.stars) + '☆'.repeat(5 - rating.stars);
  return `<span style="color: ${rating.color}">${stars}</span>`;
}

function scoreHtml(r) {
  if (r.score === undefined) return '<span class="muted">—</span>';
  const rating = r.rating || getRating(r.score);
  return `<span style="color: ${rating.color}; font-weight: bold">${r.score}</span><br>${ratingStarsHtml(rating)}`;
}

// در renderTable():
body.innerHTML = sorted.map((r, i) => {
  const status = statusOf(r);
  return `<tr>
    <td>${i + 1}</td>
    <td>${kindHtml(r)}</td>
    <td>${r.ip}</td>
    <td>${r.domain || '<span class="muted">—</span>'}</td>
    <td class="${latClass(r.avgMs)}">${r.avgMs ?? '—'}</td>
    <td>${scoreHtml(r)}</td>
    <td>${tagHtml(status)}</td>
  </tr>`;
}).join('');
```

### گام ۴: هشدار خودکار برای سقوط امتیاز

در `db.js` یا ماژول دیتابیس:

```javascript
function checkScoreDrop(itemType, itemId, currentScore, threshold = 30) {
  const history = db.prepare(`
    SELECT score, recorded_at FROM score_history 
    WHERE item_type = ? AND item_id = ? 
    ORDER BY recorded_at DESC LIMIT 2
  `).all(itemType, itemId);
  
  if (history.length < 2) return null;
  
  const prevScore = history[1].score;
  const drop = prevScore - currentScore;
  
  if (drop >= threshold) {
    return {
      itemType,
      itemId,
      previousScore: prevScore,
      currentScore,
      drop,
      timestamp: new Date().toISOString(),
    };
  }
  
  return null;
}

// هنگام ذخیره نتیجه:
const alert = checkScoreDrop('ip', result.ip, result.score, 30);
if (alert) {
  console.warn(`⚠️ Score drop alert: ${alert.itemId} dropped from ${alert.previousScore} to ${alert.currentScore}`);
  // می‌توانید ایمیل، webhook، یا لاگ ارسال کنید
}
```

---

## ۴. تجهیز به GeoIP

### گام ۱: دانلود دیتابیس GeoLite2

از MaxMind GeoLite2 استفاده کنید (رایگان):

```bash
# دانلود دستی
curl -L https://gitlab.com/maxmind-geoip/geo-lite/-/raw/master/GeoLite2-Country.mmdb.gz \
  | gunzip > geo/GeoLite2-Country.mmdb
```

یا از کتابخانه `maxmind` استفاده کنید:

```bash
npm install maxmind --save
```

### گام ۲: ایجاد ماژول GeoIP

فایل جدید `geoip.js` ایجاد کنید:

```javascript
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Simple MMDB reader (no external dependencies)
// For production, use: npm install maxmind
class GeoIPReader {
  constructor(dbPath) {
    this.dbPath = dbPath;
    this.db = null;
    this.loadError = null;
    
    try {
      if (fs.existsSync(dbPath)) {
        // For now, return null - will fallback to API
        // In production, initialize maxmind library here
        this.db = null;
      } else {
        this.loadError = 'Database not found';
      }
    } catch (err) {
      this.loadError = err.message;
    }
  }
  
  lookup(ip) {
    if (this.db) {
      return this.db.get(ip);
    }
    return null;
  }
  
  async updateDatabase() {
    // Implement auto-update logic
    // Download from MaxMind or GeoLite endpoint
  }
}

// Fallback to free API (rate-limited)
async function lookupViaApi(ip) {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=country,countryCode`);
    const data = await response.json();
    if (data.status === 'success') {
      return {
        country_code: data.countryCode,
        country_name: data.country,
        flag: countryCodeToFlag(data.countryCode),
      };
    }
  } catch {}
  return null;
}

function countryCodeToFlag(code) {
  if (!code || code.length !== 2) return '';
  const codePoints = code.toUpperCase().split('').map(c => 127397 + c.charCodeAt());
  return String.fromCodePoint(...codePoints);
}

// Pre-computed flags for common countries
const FLAG_CACHE = new Map();
function getFlag(code) {
  if (!FLAG_CACHE.has(code)) {
    FLAG_CACHE.set(code, countryCodeToFlag(code));
  }
  return FLAG_CACHE.get(code);
}

module.exports = {
  GeoIPReader,
  lookupViaApi,
  countryCodeToFlag,
  getFlag,
  
  // Convenience function with fallback
  async lookup(ip, reader = null) {
    // Try offline database first
    if (reader && reader.db) {
      const result = reader.lookup(ip);
      if (result) {
        return {
          country_code: result.country?.iso_code || null,
          country_name: result.country?.names?.en || null,
          flag: getFlag(result.country?.iso_code),
          source: 'database',
        };
      }
    }
    
    // Fallback to API
    const apiResult = await lookupViaApi(ip);
    if (apiResult) {
      apiResult.source = 'api';
    }
    return apiResult;
  },
};
```

### گام ۳: یکپارچه‌سازی با اسکنر

در `server.js`:

```javascript
const geoip = require('./geoip');

// Initialize GeoIP reader
const GEO_DB_PATH = path.join(__dirname, 'geo', 'GeoLite2-Country.mmdb');
const geoReader = new geoip.GeoIPReader(GEO_DB_PATH);

// در scanTarget یا scanTargetWithRetries:
async function scanTarget(/* ... */) {
  // ... existing scan logic ...
  
  const result = { /* ... */ };
  
  // Add GeoIP info
  const geoInfo = await geoip.lookup(ip, geoReader);
  if (geoInfo) {
    result.countryCode = geoInfo.country_code;
    result.countryName = geoInfo.country_name;
    result.flag = geoInfo.flag;
  }
  
  return result;
}
```

### گام ۴: نمایش پرچم در UI

در `public/app.js`:

```javascript
function flagHtml(r) {
  if (!r.flag) return '<span class="muted">—</span>';
  return `<span title="${r.countryName || r.countryCode || ''}">${r.flag}</span>`;
}

// در renderTable() ستون جدید اضافه کنید:
return `<tr>
  <td>${i + 1}</td>
  <td>${flagHtml(r)}</td>
  <td>${r.countryCode || '—'}</td>
  <td>${kindHtml(r)}</td>
  // ...
</tr>`;
```

### گام ۵: فیلتر بر اساس کشور

در UI، یک dropdown برای فیلتر کشور اضافه کنید:

```html
<div class="form-group">
  <label>Filter by Country:</label>
  <select id="countryFilter">
    <option value="">All Countries</option>
    <option value="DE">🇩🇪 Germany</option>
    <option value="NL">🇳🇱 Netherlands</option>
    <option value="FR">🇫🇷 France</option>
    <option value="FI">🇫🇮 Finland</option>
    <!-- Add more as needed -->
  </select>
</div>
```

در `app.js`:

```javascript
let countryFilter = '';

document.getElementById('countryFilter').addEventListener('change', (e) => {
  countryFilter = e.target.value;
  renderTable();
});

function renderTable() {
  let filtered = results;
  if (countryFilter) {
    filtered = results.filter(r => r.countryCode === countryFilter);
  }
  
  const sorted = [...filtered].sort(/* ... */);
  // ... render
}
```

### گام ۶: به‌روزرسانی دوره‌ای دیتابیس

اسکریپت `update-geoip.js` ایجاد کنید:

```javascript
#!/usr/bin/env node
'use strict';
const https = require('https');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const GEO_DIR = path.join(__dirname, 'geo');
const DB_PATH = path.join(GEO_DIR, 'GeoLite2-Country.mmdb');
const URL = 'https://gitlab.com/maxmind-geoip/geo-lite/-/raw/master/GeoLite2-Country.mmdb.gz';

if (!fs.existsSync(GEO_DIR)) {
  fs.mkdirSync(GEO_DIR, { recursive: true });
}

console.log('Downloading GeoIP database...');

https.get(URL, (res) => {
  if (res.statusCode !== 200) {
    console.error('Failed to download:', res.statusCode);
    process.exit(1);
  }
  
  const chunks = [];
  res.on('data', chunk => chunks.push(chunk));
  res.on('end', () => {
    const gzipped = Buffer.concat(chunks);
    zlib.gunzip(gzipped, (err, decompressed) => {
      if (err) {
        console.error('Decompression failed:', err.message);
        process.exit(1);
      }
      
      fs.writeFileSync(DB_PATH, decompressed);
      console.log('Database updated successfully:', DB_PATH);
    });
  });
}).on('error', (err) => {
  console.error('Download error:', err.message);
  process.exit(1);
});
```

در `package.json` اضافه کنید:

```json
{
  "scripts": {
    "start": "node server.js",
    "update-geoip": "node update-geoip.js",
    "build": "node build.js",
    "deploy": "node build.js && node deploy.js"
  }
}
```

---

## یکپارچه‌سازی بدون اختلال

### استراتژی‌های کلیدی:

1. **ماژولار بودن**: هر قابلیت را در فایل جداگانه (`db.js`, `geoip.js`, `scoring.js`) قرار دهید
2. **Feature Flags**: قابلیت‌ها را با فلگ فعال/غیرفعال کنید
3. **Backward Compatibility**: تغییرات API را additive نگه دارید
4. **Graceful Degradation**: اگر دیتابیس یا GeoIP در دسترس نبود، برنامه همچنان کار کند

### مثال Feature Flag:

```javascript
const FEATURES = {
  ENABLE_DATABASE: process.env.ENABLE_DATABASE === '1',
  ENABLE_GEOIP: process.env.ENABLE_GEOIP === '1',
  ENABLE_SCORING: process.env.ENABLE_SCORING === '1',
};

// در کد:
if (FEATURES.ENABLE_DATABASE) {
  db.saveIp(result);
}

if (FEATURES.ENABLE_GEOIP) {
  const geoInfo = await geoip.lookup(ip, geoReader);
  // ...
}
```

---

## خلاصه نهایی

| قابلیت | فایل‌های مورد نیاز | وابستگی‌ها | زمان تخمینی |
|--------|-------------------|------------|-------------|
| ۱. دامنه‌های خارجی | `server.js`, `public/app.js`, `public/index.html` | none | ۲-۳ ساعت |
| ۲. دیتابیس SQLite | `db.js`, تغییرات `server.js` | `better-sqlite3` | ۴-۵ ساعت |
| ۳. سیستم رنکینگ | `server.js` (بخش scoring), `public/app.js` | none | ۳-۴ ساعت |
| ۴. GeoIP | `geoip.js`, `update-geoip.js`, تغییرات `server.js` | `maxmind` (اختیاری) | ۳-۴ ساعت |

**کل زمان تخمینی**: ۱۲-۱۶ ساعت کاری

---

## نکات امنیتی

1. **Rate Limiting**: برای APIهای GeoIP و scrape پروکسی محدودیت نرخ اعمال کنید
2. **Input Validation**: تمام ورودی‌های کاربر (دامنه‌ها، لیست پروکسی) را اعتبارسنجی کنید
3. **Database Sanitization**: از prepared statements استفاده کنید (در کد SQLite بالا رعایت شده)
4. **Secure Defaults**: timeoutها و limits را محافظه‌کارانه تنظیم کنید

## بهینه‌سازی عملکرد

1. **Connection Pooling**: برای دیتابیس از pooling استفاده کنید
2. **Caching**: نتایج GeoIP و کوئری‌ها را کش کنید
3. **Batch Operations**: ذخیره‌سازی نتایج را batch کنید (هر ۱۰۰ نتیجه یکبار)
4. **Worker Threads**: برای عملیات سنگین از worker threads استفاده کنید
