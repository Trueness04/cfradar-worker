'use strict';
/**
 * Module 2: SQLite Database Layer (Lightweight Storage)
 * Stores IPs, domains, proxies, V2Ray configs with caching and backup
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_FILE = path.join(DATA_DIR, 'cfradar.db');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

// Simple in-memory cache
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Initialize database schema (JSON-based for zero dependencies)
 */
function initDB() {
  const schema = {
    version: 1,
    created: Date.now(),
    tables: {
      cloudflare_ips: [],
      domains: [],
      proxies: [],
      v2ray_configs: [],
      scan_history: [],
      geoip_cache: {},
    },
    indexes: {
      cloudflare_ips_by_ip: new Map(),
      domains_by_name: new Map(),
      proxies_by_address: new Map(),
      v2ray_by_name: new Map(),
    }
  };
  
  if (!fs.existsSync(DB_FILE)) {
    saveDB(schema);
  }
  
  return loadDB();
}

/**
 * Load database from file
 */
function loadDB() {
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('Failed to load DB, reinitializing:', e.message);
    return initDB();
  }
}

/**
 * Save database to file
 */
function saveDB(db) {
  // Convert Maps to arrays for JSON serialization
  const serializable = {
    ...db,
    indexes: {
      cloudflare_ips_by_ip: Array.from(db.indexes.cloudflare_ips_by_ip.entries()),
      domains_by_name: Array.from(db.indexes.domains_by_name.entries()),
      proxies_by_address: Array.from(db.indexes.proxies_by_address.entries()),
      v2ray_by_name: Array.from(db.indexes.v2ray_by_name.entries()),
    }
  };
  fs.writeFileSync(DB_FILE, JSON.stringify(serializable, null, 2));
}

/**
 * Rebuild indexes after loading
 */
function rebuildIndexes(db) {
  db.indexes = {
    cloudflare_ips_by_ip: new Map(db.indexes.cloudflare_ips_by_ip || []),
    domains_by_name: new Map(db.indexes.domains_by_name || []),
    proxies_by_address: new Map(db.indexes.proxies_by_address || []),
    v2ray_by_name: new Map(db.indexes.v2ray_by_name || []),
  };
  return db;
}

/**
 * Cache helper with TTL
 */
function getCached(key, ttl = CACHE_TTL) {
  const item = cache.get(key);
  if (!item) return null;
  if (Date.now() - item.timestamp > ttl) {
    cache.delete(key);
    return null;
  }
  return item.data;
}

function setCache(key, data) {
  cache.set(key, { data, timestamp: Date.now() });
}

function clearCache() {
  cache.clear();
}

/**
 * Insert Cloudflare IP result
 */
function insertCloudflareIP(result) {
  const db = rebuildIndexes(loadDB());
  const id = crypto.randomUUID();
  const record = {
    id,
    ip: result.ip,
    domain: result.domain || null,
    avgMs: result.avgMs,
    medianMs: result.medianMs,
    icmpMs: result.icmpMs,
    jitterMs: result.jitterMs,
    lossPct: result.lossPct,
    score: result.score,
    clean: result.clean ? 1 : 0,
    tlsOk: result.tlsOk ? 1 : 0,
    cfVerified: result.cfVerified ? 1 : 0,
    throughputKbps: result.throughputKbps,
    dpiBypass: result.dpiBypass ? 1 : 0,
    country: result.country || null,
    countryCode: result.countryCode || null,
    flagged: result.flagged ? 1 : 0,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  
  db.tables.cloudflare_ips.push(record);
  db.indexes.cloudflare_ips_by_ip.set(result.ip, record.id);
  saveDB(db);
  setCache(`ip:${result.ip}`, record);
  return id;
}

/**
 * Insert domain result
 */
function insertDomain(result) {
  const db = rebuildIndexes(loadDB());
  const id = crypto.randomUUID();
  const record = {
    id,
    domain: result.domain || result.target,
    ip: result.ip,
    avgMs: result.avgMs,
    medianMs: result.medianMs,
    score: result.score,
    clean: result.clean ? 1 : 0,
    cfVerified: result.cfVerified ? 1 : 0,
    category: result.category || 'unknown',
    country: result.country || null,
    countryCode: result.countryCode || null,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  
  db.tables.domains.push(record);
  db.indexes.domains_by_name.set(record.domain, record.id);
  saveDB(db);
  setCache(`domain:${record.domain}`, record);
  return id;
}

/**
 * Insert proxy result
 */
function insertProxy(result) {
  const db = rebuildIndexes(loadDB());
  const id = crypto.randomUUID();
  const address = `${result.ip || result.host}:${result.port}`;
  const record = {
    id,
    protocol: result.kind || result.protocol || 'http',
    host: result.host || result.ip,
    port: result.port,
    address,
    avgMs: result.avgMs,
    jitterMs: result.jitterMs,
    lossPct: result.lossPct,
    score: result.score,
    clean: result.clean ? 1 : 0,
    country: result.country || null,
    countryCode: result.countryCode || null,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  
  db.tables.proxies.push(record);
  db.indexes.proxies_by_address.set(address, record.id);
  saveDB(db);
  setCache(`proxy:${address}`, record);
  return id;
}

/**
 * Insert V2Ray config result
 */
function insertV2RayConfig(result) {
  const db = rebuildIndexes(loadDB());
  const id = crypto.randomUUID();
  const record = {
    id,
    name: result.target || result.domain,
    protocol: result.kind,
    host: result.ip.split(':')[0],
    port: result.ip.split(':')[1],
    raw: result.raw,
    avgMs: result.avgMs,
    jitterMs: result.jitterMs,
    lossPct: result.lossPct,
    score: result.score,
    clean: result.clean ? 1 : 0,
    tlsOk: result.tlsOk ? 1 : 0,
    country: result.country || null,
    countryCode: result.countryCode || null,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  
  db.tables.v2ray_configs.push(record);
  db.indexes.v2ray_by_name.set(record.name, record.id);
  saveDB(db);
  setCache(`v2ray:${record.name}`, record);
  return id;
}

/**
 * Query Cloudflare IPs with filters
 */
function queryCloudflareIPs(filters = {}) {
  const db = loadDB();
  let results = [...db.tables.cloudflare_ips];
  
  if (filters.clean !== undefined) {
    results = results.filter(r => r.clean === (filters.clean ? 1 : 0));
  }
  if (filters.countryCode) {
    results = results.filter(r => r.countryCode === filters.countryCode);
  }
  if (filters.minScore !== undefined) {
    results = results.filter(r => r.score <= filters.minScore);
  }
  if (filters.maxMs !== undefined) {
    results = results.filter(r => r.avgMs !== null && r.avgMs <= filters.maxMs);
  }
  
  // Sort by score (lower is better)
  results.sort((a, b) => a.score - b.score);
  
  if (filters.limit) {
    results = results.slice(0, filters.limit);
  }
  
  return results;
}

/**
 * Export table to CSV
 */
function exportToCSV(table, filePath) {
  const db = loadDB();
  const data = db.tables[table] || [];
  
  if (data.length === 0) {
    fs.writeFileSync(filePath, '');
    return 0;
  }
  
  const headers = Object.keys(data[0]);
  const lines = [headers.join(',')];
  
  data.forEach(row => {
    const values = headers.map(h => {
      const val = row[h];
      if (val === null || val === undefined) return '';
      if (typeof val === 'string' && val.includes(',')) {
        return `"${val.replace(/"/g, '""')}"`;
      }
      return val;
    });
    lines.push(values.join(','));
  });
  
  fs.writeFileSync(filePath, lines.join('\n'));
  return data.length;
}

/**
 * Export table to JSON
 */
function exportToJSON(table, filePath) {
  const db = loadDB();
  const data = db.tables[table] || [];
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  return data.length;
}

/**
 * Create automatic backup
 */
function createBackup() {
  const db = loadDB();
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupFile = path.join(BACKUP_DIR, `cfradar-backup-${timestamp}.json`);
  
  const serializable = {
    ...db,
    indexes: {
      cloudflare_ips_by_ip: Array.from(db.indexes.cloudflare_ips_by_ip.entries()),
      domains_by_name: Array.from(db.indexes.domains_by_name.entries()),
      proxies_by_address: Array.from(db.indexes.proxies_by_address.entries()),
      v2ray_by_name: Array.from(db.indexes.v2ray_by_name.entries()),
    }
  };
  
  fs.writeFileSync(backupFile, JSON.stringify(serializable, null, 2));
  
  // Keep only last 10 backups
  const backups = fs.readdirSync(BACKUP_DIR)
    .filter(f => f.startsWith('cfradar-backup-'))
    .sort()
    .reverse();
  
  backups.slice(10).forEach(f => {
    try { fs.unlinkSync(path.join(BACKUP_DIR, f)); } catch (_) {}
  });
  
  return backupFile;
}

/**
 * Get database statistics
 */
function getStats() {
  const db = loadDB();
  return {
    cloudflare_ips: db.tables.cloudflare_ips.length,
    domains: db.tables.domains.length,
    proxies: db.tables.proxies.length,
    v2ray_configs: db.tables.v2ray_configs.length,
    clean_ips: db.tables.cloudflare_ips.filter(r => r.clean === 1).length,
    clean_domains: db.tables.domains.filter(r => r.clean === 1).length,
    clean_proxies: db.tables.proxies.filter(r => r.clean === 1).length,
  };
}

/**
 * Batch insert for performance
 */
function batchInsert(table, records) {
  const db = rebuildIndexes(loadDB());
  const ids = [];
  
  records.forEach(result => {
    const id = crypto.randomUUID();
    ids.push(id);
    
    let record;
    if (table === 'cloudflare_ips') {
      record = {
        id,
        ip: result.ip,
        domain: result.domain || null,
        avgMs: result.avgMs,
        medianMs: result.medianMs,
        icmpMs: result.icmpMs,
        jitterMs: result.jitterMs,
        lossPct: result.lossPct,
        score: result.score,
        clean: result.clean ? 1 : 0,
        tlsOk: result.tlsOk ? 1 : 0,
        cfVerified: result.cfVerified ? 1 : 0,
        throughputKbps: result.throughputKbps,
        dpiBypass: result.dpiBypass ? 1 : 0,
        country: result.country || null,
        countryCode: result.countryCode || null,
        flagged: result.flagged ? 1 : 0,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
      db.indexes.cloudflare_ips_by_ip.set(result.ip, id);
    } else if (table === 'domains') {
      record = {
        id,
        domain: result.domain || result.target,
        ip: result.ip,
        avgMs: result.avgMs,
        score: result.score,
        clean: result.clean ? 1 : 0,
        cfVerified: result.cfVerified ? 1 : 0,
        category: result.category || 'unknown',
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
      db.indexes.domains_by_name.set(record.domain, id);
    }
    
    if (record) {
      db.tables[table].push(record);
      setCache(`${table}:${id}`, record);
    }
  });
  
  saveDB(db);
  return ids;
}

module.exports = {
  initDB,
  loadDB,
  saveDB,
  getCached,
  setCache,
  clearCache,
  insertCloudflareIP,
  insertDomain,
  insertProxy,
  insertV2RayConfig,
  queryCloudflareIPs,
  exportToCSV,
  exportToJSON,
  createBackup,
  getStats,
  batchInsert,
};
