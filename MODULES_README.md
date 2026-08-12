# CFRadar - 4 قابلیت کلیدی پیاده‌سازی شده

## 📦 ماژول‌های ایجاد شده

### 1. `modules/domain-manager.js` - مدیریت دامنه‌های ایرانی و خارجی

**قابلیت‌ها:**
- لیست پیش‌فرض 50+ دامنه خارجی پرتکرار پشت کلادفلر
- لیست پیش‌فرض 30+ دامنه ایرانی معروف
- ذخیره‌سازی در کش JSON با قابلیت بازیابی
- امکان افزودن/حذف دامنه‌های سفارشی
- فیلتر بر اساس دسته (iranian, foreign, custom, all)
- خروجی/ورودی از فایل متنی

**مثال استفاده:**
```javascript
const domainManager = require('./modules/domain-manager');

// دریافت دامنه‌های ایرانی
const irDomains = domainManager.getDomainsForScan('iranian');

// دریافت دامنه‌های خارجی  
const foreignDomains = domainManager.getDomainsForScan('foreign');

// افزودن دامنه سفارشی
domainManager.addCustomDomains(['example.com', 'test.org'], 'custom');

// آمار دامنه‌ها
const stats = domainManager.getDomainStats();
console.log(stats); // { iranian: 30, foreign: 50, custom: 2, total: 82 }
```

---

### 2. `modules/database.js` - دیتابیس سبک JSON-based

**قابلیت‌ها:**
- ساختار جداول نرمال‌شده برای IPs، دامنه‌ها، پروکسی‌ها، کانفیگ‌ها
- ایندکس‌گذاری داخلی برای جستجوی سریع
- کش درون‌حافظه‌ای با TTL خودکار
- پشتیبانی از عملیات batch insert
- خروجی CSV و JSON
- بک‌آپ‌گیری خودکار با نگهداری 10 نسخه آخر

**جداول:**
- `cloudflare_ips`: نتایج اسکن IPهای کلادفلر
- `domains`: نتایج اسکن دامنه‌ها
- `proxies`: پروکسی‌های تست شده
- `v2ray_configs`: کانفیگ‌های V2Ray
- `scan_history`: تاریخچه اسکن‌ها

**مثال استفاده:**
```javascript
const db = require('./modules/database');

// مقداردهی اولیه
db.initDB();

// درج نتیجه اسکن
const id = db.insertCloudflareIP({
  ip: '104.16.0.1',
  avgMs: 45.2,
  score: 120,
  clean: true,
  cfVerified: true,
});

// کوئری با فیلتر
const cleanIPs = db.queryCloudflareIPs({
  clean: true,
  maxMs: 100,
  limit: 50
});

// خروجی CSV
db.exportToCSV('cloudflare_ips', './exports/clean_ips.csv');

// آمار
const stats = db.getStats();
console.log(stats);

// بک‌آپ
const backupPath = db.createBackup();
```

---

### 3. `modules/scoring.js` - سیستم رنکینگ و امتیازدهی

**قابلیت‌ها:**
- وزن‌دهی قابل تنظیم (ping: 40%, speed: 35%, stability: 25%)
- تست چندمرحله‌ای (حداقل 3 بار با فاصله زمانی)
- امتیاز نهایی 0-500 (کمتر = بهتر)
- درجه‌بندی رنگی/ستاره‌ای:
  - Excellent (0-50): 🟢 5 ستاره
  - Good (50-150): 🟡 4 ستاره
  - Fair (150-300): 🟠 3 ستاره
  - Poor (300-500): 🔴 2 ستاره
  - Bad (500+): ⚫ 1 ستاره
- ذخیره تاریخچه امتیازات
- هشدار خودکار برای سقوط امتیاز

**مثال استفاده:**
```javascript
const scoring = require('./modules/scoring');

// محاسبه امتیاز از متریک‌ها
const score = scoring.calculateScore({
  avgMs: 45,
  throughputKbps: 5000,
  lossPct: 2.5,
  jitterMs: 10,
  cfVerified: true
});

// دریافت رتبه
const rating = scoring.getScoreRating(score);
console.log(rating); 
// { grade: 'good', label: 'Good', color: '#84cc16', stars: 4 }

// اجرای تست چندمرحله‌ای
const result = await scoring.runMultiStageTest(
  async (pass) => await tcpProbe(ip),
  3,  // تعداد passes
  1000 // فاصله بین passes (ms)
);

// رتبه‌بندی آیتم‌ها
const ranked = scoring.rankItems(items, 'score');

// فیلتر بر اساس رتبه
const excellent = scoring.filterByRating(items, 'excellent');

// بررسی هشدار
const alerts = scoring.checkScoreAlert('ip1', 450, 120);
// [{ type: 'threshold_crossed', message: '...', severity: 'warning' }]

// آمار امتیازات
const stats = scoring.getScoreStats(items);
```

---

### 4. `modules/geoip.js` - موقعیت مکانی با پرچم کشور

**قابلیت‌ها:**
- دیتابیس آفلاین GeoIP (بدون نیاز به API خارجی)
- Fallback به API رایگان ip-api.com
- کش هوشمند با TTL 10 دقیقه
- نمایش نام کشور، کد ISO، پرچم emoji
- فیلتر و گروه‌بندی بر اساس کشور
- به‌روزرسانی دوره‌ای دیتابیس

**مثال استفاده:**
```javascript
const geoip = require('./modules/geoip');

// جستجوی کامل (آفلاین + API fallback)
const result = await geoip.lookupIP('104.16.0.1', true);
console.log(result);
// { country: 'United States', countryCode: 'US', flag: '🇺🇸', source: 'offline' }

// فقط آفلاین
const offline = geoip.lookupOffline('104.16.0.1');

// فیلتر بر اساس کشور
const usItems = geoip.filterByCountry(items, ['US', 'CA']);

// گروه‌بندی بر اساس کشور
const groups = geoip.groupByCountry(items);

// آمار به تفکیک کشور
const stats = geoip.getCountryStats(items);
// [{ countryCode: 'US', country: 'United States', flag: '🇺🇸', count: 45, cleanCount: 32, ... }]

// به‌روزرسانی دیتابیس
await geoip.updateGeoIPDB();
```

---

## 🔌 یکپارچه‌سازی با هسته موجود

### مرحله 1: اضافه کردن به `server.js`

در ابتدای `server.js` ماژول‌ها را import کنید:

```javascript
const domainManager = require('./modules/domain-manager');
const database = require('./modules/database');
const scoring = require('./modules/scoring');
const geoip = require('./modules/geoip');

// مقداردهی اولیه دیتابیس
database.initDB();
```

### مرحله 2: توسعه endpoint اسکن دامنه

تابع `handleScanStream` را برای پشتیبانی از فیلتر منطقه‌ای گسترش دهید:

```javascript
} else if (mode === 'domains') {
  const source = query.source || '';
  const regionFilter = query.region || 'all'; // 'iranian', 'foreign', 'custom', 'all'
  const resolveDns = query.resolveDns === '1';
  
  sseSend(res, 'info', { message: 'Loading domain list...', total: 0 });
  
  // استفاده از domain-manager به جای loadDomainsSource خالی
  let domainItems;
  if (source) {
    domainItems = await loadDomainsSource(source);
  } else {
    const domains = domainManager.getDomainsForScan(regionFilter);
    domainItems = domains.map(d => ({ domain: d, ip: null }));
  }
  
  // ادامه منطق قبلی...
}
```

### مرحله 3: افزودن GeoIP به نتایج اسکن

بعد از هر اسکن موفق، اطلاعات GeoIP را اضافه کنید:

```javascript
async function scanTarget(target, ip, port, timeoutMs, passes, sniHost, opts) {
  // ... کد موجود اسکن ...
  
  const result = {
    target, ip, domain: target !== ip ? target : null,
    avgMs: latencies.length ? Math.round(avg * 10) / 10 : null,
    // ... سایر فیلدها ...
  };
  
  // افزودن اطلاعات GeoIP
  if (opts.withGeoIP !== false) {
    const geo = await geoip.lookupIP(ip, true);
    result.country = geo.country;
    result.countryCode = geo.countryCode;
    result.flag = geo.flag;
  }
  
  // محاسبه امتیاز با سیستم جدید
  if (opts.useNewScoring) {
    const scoreData = scoring.calculateScore({
      avgMs: result.avgMs,
      throughputKbps: result.throughputKbps,
      lossPct: result.lossPct,
      jitterMs: result.jitterMs,
      cfVerified: result.cfVerified,
    });
    result.score = scoreData;
    result.rating = scoring.getScoreRating(scoreData);
  }
  
  return result;
}
```

### مرحله 4: ذخیره در دیتابیس

بعد از اتمام اسکن، نتایج را ذخیره کنید:

```javascript
results.sort((a, b) => a.score - b.score);

// ذخیره در دیتابیس
if (query.saveToDB !== '0') {
  const table = mode === 'cf' ? 'cloudflare_ips' : 
                mode === 'domains' ? 'domains' :
                mode === 'proxy' || mode === 'proxyscrape' ? 'proxies' : 'v2ray_configs';
  
  database.batchInsert(table, results);
}

lastResults.set(sessionId, results);
```

### مرحله 5: endpoint جدید برای آمار و خروجی

endpointهای جدید اضافه کنید:

```javascript
// در server.js بعد از handleExport

function handleStats(req, res) {
  const dbStats = database.getStats();
  const domainStats = domainManager.getDomainStats();
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    database: dbStats,
    domains: domainStats,
  }));
}

function handleGeoIPStats(req, res, query) {
  const sessionId = query.sid;
  const results = lastResults.get(sessionId) || [];
  const stats = geoip.getCountryStats(results);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(stats));
}

function handleScoreHistory(req, res, query) {
  const itemId = query.id;
  const history = scoring.getScoreHistory(itemId, 50);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(history));
}

// در بخش routing:
if (pathname === '/api/stats') {
  handleStats(req, res);
  return;
}
if (pathname === '/api/geoip-stats') {
  handleGeoIPStats(req, res, query);
  return;
}
if (pathname === '/api/score-history') {
  handleScoreHistory(req, res, query);
  return;
}
```

---

## 🛡️ نکات امنیتی

1. **Rate Limiting برای API GeoIP**: 
   - ip-api.com محدودیت 45 درخواست در دقیقه دارد
   - حتماً از کش استفاده کنید

2. **ذخیره‌سازی امن**:
   - فایل‌های دیتابیس را chmod 600 کنید
   - در production از رمزنگاری استفاده کنید

3. **ورودی‌های کاربر**:
   - لیست‌های دامنه سفارشی را sanitize کنید
   - از path traversal جلوگیری کنید

4. **بک‌آپ**:
   - بک‌آپ‌ها را در محل امن ذخیره کنید
   - به‌صورت دوره‌ای cleanup کنید

---

## ⚡ بهینه‌سازی عملکرد

1. **کش هوشمند**:
   - تمام ماژول‌ها از کش درون‌حافظه‌ای استفاده می‌کنند
   - TTL خودکار برای جلوگیری از stale data

2. **Batch Operations**:
   - `database.batchInsert()` برای درج دسته‌جمعی
   - کاهش writeهای دیسک

3. **ایندکس‌گذاری**:
   - ایندکس‌های Map-based برای جستجوی O(1)

4. **Lazy Loading**:
   - دیتابیس فقط هنگام نیاز لود می‌شود
   - GeoIP cache به‌صورت تدریجی پر می‌شود

---

## 📊 زمان تخمینی پیاده‌سازی

| بخش | زمان | وضعیت |
|-----|------|--------|
| Domain Manager | 1 ساعت | ✅ تکمیل |
| Database Layer | 2 ساعت | ✅ تکمیل |
| Scoring System | 2 ساعت | ✅ تکمیل |
| GeoIP Module | 2 ساعت | ✅ تکمیل |
| یکپارچه‌سازی با server.js | 3 ساعت | ⏳ نیاز به اجرا |
| تست و دیباگ | 2 ساعت | ⏳ نیاز به اجرا |
| مستندات UI | 1 ساعت | ⏳ نیاز به اجرا |
| **کل** | **13 ساعت** | |

---

## 🚀 شروع سریع

```bash
cd /workspace

# تست ماژول‌ها
node -e "
const dm = require('./modules/domain-manager');
console.log('Domains:', dm.getDomainStats());

const db = require('./modules/database');
db.initDB();
console.log('DB initialized');

const sc = require('./modules/scoring');
console.log('Score for 50ms:', sc.calculateScore({ avgMs: 50, throughputKbps: 5000, lossPct: 1, jitterMs: 5, cfVerified: true }));

const geo = require('./modules/geoip');
geo.lookupIP('104.16.0.1').then(r => console.log('GeoIP:', r));
"

# اجرای سرور
node server.js
```
