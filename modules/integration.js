'use strict';
/**
 * Integration Layer - Connects all 4 modules with the main server
 * Add this require to server.js and use these enhanced functions
 */

const domainManager = require('./modules/domain-manager');
const database = require('./modules/database');
const scoring = require('./modules/scoring');
const geoip = require('./modules/geoip');

// Initialize database on module load
database.initDB();

/**
 * Enhanced scan result processor
 * Adds GeoIP, recalculates score, and saves to database
 */
async function processScanResult(result, mode, sessionId, saveToDB = true) {
  // Add GeoIP information
  try {
    const ipToLookup = result.ip?.split(':')[0] || result.ip; // Handle ip:port format
    if (ipToLookup && /^\d{1,3}(\.\d{1,3}){3}$/.test(ipToLookup)) {
      const geo = await geoip.lookupIP(ipToLookup, true);
      result.country = geo.country;
      result.countryCode = geo.countryCode;
      result.flag = geo.flag;
    }
  } catch (_) {
    // Ignore GeoIP errors
  }

  // Recalculate score using new scoring system
  const newScore = scoring.calculateScore({
    avgMs: result.avgMs,
    throughputKbps: result.throughputKbps,
    lossPct: result.lossPct,
    jitterMs: result.jitterMs,
    cfVerified: result.cfVerified,
  });
  
  result.newScore = newScore;
  result.rating = scoring.getScoreRating(newScore);

  // Save to database if enabled
  if (saveToDB) {
    try {
      const table = mode === 'cf' ? 'cloudflare_ips' :
                    mode === 'domains' ? 'domains' :
                    mode === 'proxy' || mode === 'proxyscrape' ? 'proxies' : 
                    mode === 'v2ray' ? 'v2ray_configs' : null;
      
      if (table) {
        database.insertCloudflareIP(result); // Generic insert works for all
      }
    } catch (_) {
      // Ignore DB errors
    }
  }

  return result;
}

/**
 * Batch process results after scan completion
 */
async function processScanResults(results, mode, sessionId, saveToDB = true) {
  const processed = [];
  
  for (const result of results) {
    const enriched = await processScanResult(result, mode, sessionId, saveToDB);
    processed.push(enriched);
  }

  // Re-rank with new scores
  const ranked = scoring.rankItems(processed, 'newScore');
  
  // Get statistics
  const stats = scoring.getScoreStats(ranked);
  const countryStats = geoip.getCountryStats(ranked);

  return {
    results: ranked,
    statistics: stats,
    byCountry: countryStats,
    alerts: generateAlerts(ranked),
  };
}

/**
 * Generate alerts for items with score drops
 */
function generateAlerts(items) {
  const alerts = [];
  const history = scoring.loadHistory();
  
  items.forEach(item => {
    const itemId = item.ip || item.target;
    const itemHistory = history.records.filter(r => r.itemId === itemId);
    
    if (itemHistory.length > 0) {
      const previous = itemHistory[itemHistory.length - 1].score;
      const current = item.newScore || item.score;
      
      const itemAlerts = scoring.checkScoreAlert(itemId, current, previous);
      alerts.push(...itemAlerts);
    }
  });

  return alerts;
}

/**
 * Get comprehensive statistics
 */
function getComprehensiveStats() {
  return {
    database: database.getStats(),
    domains: domainManager.getDomainStats(),
    scoring: {
      thresholds: scoring.SCORE_THRESHOLDS,
      weights: scoring.DEFAULT_WEIGHTS,
      alertThreshold: scoring.ALERT_THRESHOLD,
    },
    geoip: {
      flags: Object.keys(geoip.FLAGS).length,
    }
  };
}

/**
 * Export enhanced results with all metadata
 */
function exportEnhanced(sessionId, format = 'json', filePath) {
  // This would integrate with existing lastResults map in server.js
  // Placeholder for integration
  return { success: true, format, sessionId };
}

/**
 * Domain management helpers for API endpoints
 */
const domainAPI = {
  getList: (filter) => domainManager.getDomainsForScan(filter),
  addDomains: (domains, category) => domainManager.addCustomDomains(domains, category),
  removeDomains: (domains, category) => domainManager.removeDomains(domains, category),
  getStats: () => domainManager.getDomainStats(),
  exportToFile: (filePath, filter) => domainManager.exportDomainsToFile(filePath, filter),
  importFromFile: (filePath, category) => domainManager.importDomainsFromFile(filePath, category),
};

/**
 * Database helpers for API endpoints
 */
const databaseAPI = {
  query: (table, filters) => {
    if (table === 'cloudflare_ips') return database.queryCloudflareIPs(filters);
    // Add more table queries as needed
    return [];
  },
  exportCSV: (table, filePath) => database.exportToCSV(table, filePath),
  exportJSON: (table, filePath) => database.exportToJSON(table, filePath),
  backup: () => database.createBackup(),
  getStats: () => database.getStats(),
};

/**
 * Scoring helpers for API endpoints
 */
const scoringAPI = {
  calculate: (metrics, weights) => scoring.calculateScore(metrics, weights),
  getRating: (score) => scoring.getScoreRating(score),
  getHistory: (itemId, limit) => scoring.getScoreHistory(itemId, limit),
  rank: (items, sortBy) => scoring.rankItems(items, sortBy),
  filterByScore: (items, min, max) => scoring.filterByScore(items, min, max),
  filterByRating: (items, grade) => scoring.filterByRating(items, grade),
  getStats: (items) => scoring.getScoreStats(items),
  updateWeights: (newWeights) => {
    // Would need to persist new weights
    Object.assign(scoring.DEFAULT_WEIGHTS, newWeights);
  },
};

/**
 * GeoIP helpers for API endpoints
 */
const geoipAPI = {
  lookup: (ip, useAPI) => geoip.lookupIP(ip, useAPI),
  filterByCountry: (items, countries) => geoip.filterByCountry(items, countries),
  groupByCountry: (items) => geoip.groupByCountry(items),
  getStats: (items) => geoip.getCountryStats(items),
  updateDB: () => geoip.updateGeoIPDB(),
};

module.exports = {
  processScanResult,
  processScanResults,
  getComprehensiveStats,
  domainAPI,
  databaseAPI,
  scoringAPI,
  geoipAPI,
};
