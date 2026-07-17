'use strict';
/**
 * Module 4: GeoIP Lookup (Offline + API Fallback)
 * Extract location data for IPs with country flag emojis
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const DATA_DIR = path.join(__dirname, '..', 'data');
const GEOIP_DB_FILE = path.join(DATA_DIR, 'geoip.json');
const GEOIP_CACHE_FILE = path.join(DATA_DIR, 'geoip-cache.json');

// Country code to emoji flag mapping
const FLAGS = {
  AD: '🇦🇩', AE: '🇦🇪', AF: '🇦🇫', AG: '🇦🇬', AI: '🇦🇮', AL: '🇦🇱', AM: '🇦🇲', AO: '🇦🇴', AQ: '🇦🇶', AR: '🇦🇷',
  AS: '🇦🇸', AT: '🇦🇹', AU: '🇦🇺', AW: '🇦🇼', AX: '🇦🇽', AZ: '🇦🇿', BA: '🇧🇦', BB: '🇧🇧', BD: '🇧🇩', BE: '🇧🇪',
  BF: '🇧🇫', BG: '🇧🇬', BH: '🇧🇭', BI: '🇧🇮', BJ: '🇧🇯', BL: '🇧🇱', BM: '🇧🇲', BN: '🇧🇳', BO: '🇧🇴', BQ: '🇧🇶',
  BR: '🇧🇷', BS: '🇧🇸', BT: '🇧🇹', BV: '🇧🇻', BW: '🇧🇼', BY: '🇧🇾', BZ: '🇧🇿', CA: '🇨🇦', CC: '🇨🇨', CD: '🇨🇩',
  CF: '🇨🇫', CG: '🇨🇬', CH: '🇨🇭', CI: '🇨🇮', CK: '🇨🇰', CL: '🇨🇱', CM: '🇨🇲', CN: '🇨🇳', CO: '🇨🇴', CR: '🇨🇷',
  CU: '🇨🇺', CV: '🇨🇻', CW: '🇨🇼', CX: '🇨🇽', CY: '🇨🇾', CZ: '🇨🇿', DE: '🇩🇪', DJ: '🇩🇯', DK: '🇩🇰', DM: '🇩🇲',
  DO: '🇩🇴', DZ: '🇩🇿', EC: '🇪🇨', EE: '🇪🇪', EG: '🇪🇬', EH: '🇪🇭', ER: '🇪🇷', ES: '🇪🇸', ET: '🇪🇹', FI: '🇫🇮',
  FJ: '🇫🇯', FK: '🇫🇰', FM: '🇫🇲', FO: '🇫🇴', FR: '🇫🇷', GA: '🇬🇦', GB: '🇬🇧', GD: '🇬🇩', GE: '🇬🇪', GF: '🇬🇫',
  GG: '🇬🇬', GH: '🇬🇭', GI: '🇬🇮', GL: '🇬🇱', GM: '🇬🇲', GN: '🇬🇳', GP: '🇬🇵', GQ: '🇬🇶', GR: '🇬🇷', GS: '🇬🇸',
  GT: '🇬🇹', GU: '🇬🇺', GW: '🇬🇼', GY: '🇬🇾', HK: '🇭🇰', HM: '🇭🇲', HN: '🇭🇳', HR: '🇭🇷', HT: '🇭🇹', HU: '🇭🇺',
  ID: '🇮🇩', IE: '🇮🇪', IL: '🇮🇱', IM: '🇮🇲', IN: '🇮🇳', IO: '🇮🇴', IQ: '🇮🇶', IR: '🇮🇷', IS: '🇮🇸', IT: '🇮🇹',
  JE: '🇯🇪', JM: '🇯🇲', JO: '🇯🇴', JP: '🇯🇵', KE: '🇰🇪', KG: '🇰🇬', KH: '🇰🇭', KI: '🇰🇮', KM: '🇰🇲', KN: '🇰🇳',
  KP: '🇰🇵', KR: '🇰🇷', KW: '🇰🇼', KY: '🇰🇾', KZ: '🇰🇿', LA: '🇱🇦', LB: '🇱🇧', LC: '🇱🇨', LI: '🇱🇮', LK: '🇱🇰',
  LR: '🇱🇷', LS: '🇱🇸', LT: '🇱🇹', LU: '🇱🇺', LV: '🇱🇻', LY: '🇱🇾', MA: '🇲🇦', MC: '🇲🇨', MD: '🇲🇩', ME: '🇲🇪',
  MF: '🇲🇫', MG: '🇲🇬', MH: '🇲🇭', MK: '🇲🇰', ML: '🇲🇱', MM: '🇲🇲', MN: '🇲🇳', MO: '🇲🇴', MP: '🇲🇵', MQ: '🇲🇶',
  MR: '🇲🇷', MS: '🇲🇸', MT: '🇲🇹', MU: '🇲🇺', MV: '🇲🇻', MW: '🇲🇼', MX: '🇲🇽', MY: '🇲🇾', MZ: '🇲🇿', NA: '🇳🇦',
  NC: '🇳🇨', NE: '🇳🇪', NF: '🇳🇫', NG: '🇳🇬', NI: '🇳🇮', NL: '🇳🇱', NO: '🇳🇴', NP: '🇳🇵', NR: '🇳🇷', NU: '🇳🇺',
  NZ: '🇳🇿', OM: '🇴🇲', PA: '🇵🇦', PE: '🇵🇪', PF: '🇵🇫', PG: '🇵🇬', PH: '🇵🇭', PK: '🇵🇰', PL: '🇵🇱', PM: '🇵🇲',
  PN: '🇵🇳', PR: '🇵🇷', PS: '🇵🇸', PT: '🇵🇹', PW: '🇵🇼', PY: '🇵🇾', QA: '🇶🇦', RE: '🇷🇪', RO: '🇷🇴', RS: '🇷🇸',
  RU: '🇷🇺', RW: '🇷🇼', SA: '🇸🇦', SB: '🇸🇧', SC: '🇸🇨', SD: '🇸🇩', SE: '🇸🇪', SG: '🇸🇬', SH: '🇸🇭', SI: '🇸🇮',
  SJ: '🇸🇯', SK: '🇸🇰', SL: '🇸🇱', SM: '🇸🇲', SN: '🇸🇳', SO: '🇸🇴', SR: '🇸🇷', SS: '🇸🇸', ST: '🇸🇹', SV: '🇸🇻',
  SX: '🇸🇽', SY: '🇸🇾', SZ: '🇸🇿', TC: '🇹🇨', TD: '🇹🇩', TF: '🇹🇫', TG: '🇹🇬', TH: '🇹🇭', TJ: '🇹🇯', TK: '🇹🇰',
  TL: '🇹🇱', TM: '🇹🇲', TN: '🇹🇳', TO: '🇹🇴', TR: '🇹🇷', TT: '🇹🇹', TV: '🇹🇻', TW: '🇹🇼', TZ: '🇹🇿', UA: '🇺🇦',
  UG: '🇺🇬', UM: '🇺🇲', US: '🇺🇸', UY: '🇺🇾', UZ: '🇺🇿', VA: '🇻🇦', VC: '🇻🇨', VE: '🇻🇪', VG: '🇻🇬', VI: '🇻🇮',
  VN: '🇻🇳', VU: '🇻🇺', WF: '🇼🇫', WS: '🇼🇸', YE: '🇾🇪', YT: '🇾🇹', ZA: '🇿🇦', ZM: '🇿🇲', ZW: '🇿🇼',
};

// Simplified GeoIP database (Cloudflare IP ranges → Country)
// In production, this would be populated from MaxMind GeoLite2
const CLOUDFLARE_RANGES = {
  // US ranges
  '173.245.48.0/20': 'US',
  '103.21.244.0/22': 'US',
  '103.22.200.0/22': 'US',
  '103.31.4.0/22': 'US',
  '141.101.64.0/18': 'US',
  '108.162.192.0/18': 'US',
  '190.93.240.0/20': 'US',
  '188.114.96.0/20': 'US',
  '197.234.240.0/22': 'US',
  '198.41.128.0/17': 'US',
  '162.158.0.0/15': 'US',
  '104.16.0.0/13': 'US',
  '104.24.0.0/14': 'US',
  '172.64.0.0/13': 'US',
  '131.0.72.0/22': 'US',
  // EU ranges (simplified - actual assignment varies)
  '103.21.244.0/22': 'DE',
  '103.22.200.0/22': 'GB',
  '103.31.4.0/22': 'NL',
  // Add more specific ranges as needed
};

// In-memory cache
const geoipCache = new Map();
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/**
 * Convert IP to integer
 */
function ipToInt(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

/**
 * Parse CIDR notation
 */
function parseCidr(cidr) {
  const [base, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const baseInt = ipToInt(base);
  const hostBits = 32 - bits;
  const size = hostBits >= 32 ? 0xFFFFFFFF : (1 << hostBits) >>> 0;
  const network = baseInt & (~(size) >>> 0);
  return { network, broadcast: network + size - 1 };
}

/**
 * Check if IP is in CIDR range
 */
function ipInCidr(ip, cidr) {
  const ipInt = ipToInt(ip);
  const { network, broadcast } = parseCidr(cidr);
  return ipInt >= network && ipInt <= broadcast;
}

/**
 * Load local GeoIP database
 */
function loadGeoIPDB() {
  try {
    if (fs.existsSync(GEOIP_DB_FILE)) {
      return JSON.parse(fs.readFileSync(GEOIP_DB_FILE, 'utf-8'));
    }
  } catch (_) {}
  
  // Return default Cloudflare ranges
  return { ranges: CLOUDFLARE_RANGES, lastUpdated: Date.now() };
}

/**
 * Save GeoIP database
 */
function saveGeoIPDB(db) {
  fs.writeFileSync(GEOIP_DB_FILE, JSON.stringify(db, null, 2));
}

/**
 * Load GeoIP cache
 */
function loadCache() {
  try {
    if (fs.existsSync(GEOIP_CACHE_FILE)) {
      const data = JSON.parse(fs.readFileSync(GEOIP_CACHE_FILE, 'utf-8'));
      // Restore Map from serialized format
      Object.entries(data).forEach(([key, value]) => {
        if (Date.now() - value.timestamp < CACHE_TTL) {
          geoipCache.set(key, value.data);
        }
      });
    }
  } catch (_) {}
}

/**
 * Save GeoIP cache
 */
function saveCache() {
  const serializable = {};
  geoipCache.forEach((value, key) => {
    serializable[key] = {
      data: value,
      timestamp: Date.now(),
    };
  });
  fs.writeFileSync(GEOIP_CACHE_FILE, JSON.stringify(serializable, null, 2));
}

/**
 * Get country from cached result
 */
function getCached(ip) {
  const item = geoipCache.get(ip);
  if (!item) return null;
  if (Date.now() - item.timestamp > CACHE_TTL) {
    geoipCache.delete(ip);
    return null;
  }
  return item.data;
}

/**
 * Set cache entry
 */
function setCache(ip, data) {
  geoipCache.set(ip, { data, timestamp: Date.now() });
  // Periodically save cache to disk
  if (geoipCache.size % 100 === 0) {
    saveCache();
  }
}

/**
 * Lookup IP in local database (offline)
 */
function lookupOffline(ip) {
  const db = loadGeoIPDB();
  
  for (const [cidr, countryCode] of Object.entries(db.ranges)) {
    if (ipInCidr(ip, cidr)) {
      return {
        country: getCountryName(countryCode),
        countryCode,
        flag: getFlag(countryCode),
        source: 'offline',
      };
    }
  }
  
  return null;
}

/**
 * Lookup IP via API (fallback)
 */
async function lookupAPI(ip) {
  return new Promise((resolve) => {
    const url = `http://ip-api.com/json/${ip}?fields=country,countryCode,status,message`;
    
    const lib = url.startsWith('https') ? https : http;
    lib.get(url, { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const result = JSON.parse(data);
          if (result.status === 'success') {
            resolve({
              country: result.country,
              countryCode: result.countryCode,
              flag: getFlag(result.countryCode),
              source: 'api',
            });
          } else {
            resolve(null);
          }
        } catch (_) {
          resolve(null);
        }
      });
    }).on('error', () => resolve(null));
  });
}

/**
 * Main lookup function (offline first, then API fallback)
 */
async function lookupIP(ip, useAPI = true) {
  // Check cache first
  const cached = getCached(ip);
  if (cached) {
    return { ...cached, cached: true };
  }
  
  // Try offline database
  let result = lookupOffline(ip);
  
  // Fallback to API if enabled and offline failed
  if (!result && useAPI) {
    result = await lookupAPI(ip);
  }
  
  // Default if all methods fail
  if (!result) {
    result = {
      country: 'Unknown',
      countryCode: 'XX',
      flag: '🌐',
      source: 'unknown',
    };
  }
  
  // Cache the result
  setCache(ip, result);
  
  return { ...result, cached: false };
}

/**
 * Get country name from code
 */
function getCountryName(code) {
  const names = {
    US: 'United States', GB: 'United Kingdom', DE: 'Germany', FR: 'France',
    NL: 'Netherlands', CA: 'Canada', AU: 'Australia', JP: 'Japan',
    CN: 'China', RU: 'Russia', IR: 'Iran', TR: 'Turkey', AE: 'UAE',
    SG: 'Singapore', IN: 'India', BR: 'Brazil', IT: 'Italy', ES: 'Spain',
  };
  return names[code] || code;
}

/**
 * Get flag emoji from country code
 */
function getFlag(countryCode) {
  return FLAGS[countryCode] || '🌐';
}

/**
 * Filter items by country/region
 */
function filterByCountry(items, countries) {
  const countrySet = new Set(countries.map(c => c.toUpperCase()));
  return items.filter(item => 
    item.countryCode && countrySet.has(item.countryCode)
  );
}

/**
 * Group items by country
 */
function groupByCountry(items) {
  const groups = {};
  items.forEach(item => {
    const code = item.countryCode || 'XX';
    if (!groups[code]) {
      groups[code] = {
        countryCode: code,
        country: item.country || getCountryName(code),
        flag: getFlag(code),
        items: [],
        count: 0,
      };
    }
    groups[code].items.push(item);
    groups[code].count++;
  });
  return Object.values(groups).sort((a, b) => b.count - a.count);
}

/**
 * Get statistics by country
 */
function getCountryStats(items) {
  const groups = groupByCountry(items);
  return groups.map(g => ({
    ...g,
    cleanCount: g.items.filter(i => i.clean).length,
    avgScore: Math.round(g.items.reduce((sum, i) => sum + (i.score || 0), 0) / g.count),
    avgPing: Math.round(g.items.reduce((sum, i) => sum + (i.avgMs || 0), 0) / g.count),
  }));
}

/**
 * Update GeoIP database from remote source
 * In production, this would download MaxMind GeoLite2 CSV
 */
async function updateGeoIPDB() {
  // Placeholder for actual database update logic
  // Would download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  const db = {
    ranges: { ...CLOUDFLARE_RANGES },
    lastUpdated: Date.now(),
    version: '1.0.0',
  };
  
  saveGeoIPDB(db);
  return db;
}

/**
 * Clear GeoIP cache
 */
function clearCache() {
  geoipCache.clear();
  try {
    if (fs.existsSync(GEOIP_CACHE_FILE)) {
      fs.unlinkSync(GEOIP_CACHE_FILE);
    }
  } catch (_) {}
}

// Initialize cache on module load
loadCache();

module.exports = {
  lookupIP,
  lookupOffline,
  lookupAPI,
  getCountryName,
  getFlag,
  filterByCountry,
  groupByCountry,
  getCountryStats,
  updateGeoIPDB,
  clearCache,
  FLAGS,
};
