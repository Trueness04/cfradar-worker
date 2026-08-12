'use strict';
/**
 * Module 3: Ranking & Scoring System
 * Multi-stage testing with configurable weights and historical tracking
 */

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const HISTORY_FILE = path.join(DATA_DIR, 'score-history.json');

// Default scoring weights (configurable)
const DEFAULT_WEIGHTS = {
  ping: 0.40,        // Latency/ping weight
  speed: 0.35,       // Throughput/download speed weight
  stability: 0.25,   // Packet loss/jitter/stability weight
};

// Score thresholds for visual indicators
const SCORE_THRESHOLDS = {
  excellent: { min: 0, max: 50, label: 'Excellent', color: '#22c55e', stars: 5 },    // Green
  good: { min: 50, max: 150, label: 'Good', color: '#84cc16', stars: 4 },           // Lime
  fair: { min: 150, max: 300, label: 'Fair', color: '#eab308', stars: 3 },          // Yellow
  poor: { min: 300, max: 500, label: 'Poor', color: '#f97316', stars: 2 },          // Orange
  bad: { min: 500, max: Infinity, label: 'Bad', color: '#ef4444', stars: 1 },       // Red
};

// Alert threshold - items below this need attention
const ALERT_THRESHOLD = 400;

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/**
 * Load score history
 */
function loadHistory() {
  try {
    if (fs.existsSync(HISTORY_FILE)) {
      return JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf-8'));
    }
  } catch (_) {}
  return { records: [], lastUpdated: Date.now() };
}

/**
 * Save score history
 */
function saveHistory(history) {
  history.lastUpdated = Date.now();
  fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));
}

/**
 * Add score record to history
 */
function addScoreRecord(itemId, itemType, score, metrics) {
  const history = loadHistory();
  
  history.records.push({
    itemId,
    itemType,
    score,
    metrics: { ...metrics },
    timestamp: Date.now(),
  });
  
  // Keep only last 1000 records per item
  const itemRecords = history.records.filter(r => r.itemId === itemId);
  if (itemRecords.length > 1000) {
    history.records = history.records.filter(r => r.itemId !== itemId);
    history.records.push(...itemRecords.slice(-1000));
  }
  
  saveHistory(history);
  return history.records.length;
}

/**
 * Get score history for an item
 */
function getScoreHistory(itemId, limit = 50) {
  const history = loadHistory();
  return history.records
    .filter(r => r.itemId === itemId)
    .sort((a, b) => b.timestamp - a.timestamp)
    .slice(0, limit);
}

/**
 * Calculate composite score from raw metrics
 * @param {Object} metrics - { avgMs, throughputKbps, lossPct, jitterMs, cfVerified }
 * @param {Object} weights - Custom weights (optional)
 */
function calculateScore(metrics, weights = DEFAULT_WEIGHTS) {
  const w = { ...DEFAULT_WEIGHTS, ...weights };
  
  // Normalize each component to 0-100 scale
  // Ping: lower is better, 0ms = 100, 500ms+ = 0
  const pingScore = Math.max(0, 100 - (metrics.avgMs || 0) / 5);
  
  // Speed: higher is better, 0 = 0, 10000 KB/s+ = 100
  const speedScore = Math.min(100, (metrics.throughputKbps || 0) / 100);
  
  // Stability: based on packet loss and jitter
  // 0% loss + 0 jitter = 100, 100% loss = 0
  const stabilityPenalty = (metrics.lossPct || 0) + (metrics.jitterMs || 0) / 10;
  const stabilityScore = Math.max(0, 100 - stabilityPenalty);
  
  // Cloudflare verification bonus (up to 20 points)
  const cfBonus = metrics.cfVerified ? 20 : 0;
  
  // Weighted composite (0-100 scale + bonus)
  const composite = (
    pingScore * w.ping +
    speedScore * w.speed +
    stabilityScore * w.stability
  ) + cfBonus;
  
  // Invert so lower score = better (consistent with existing code)
  // Excellent (0-50), Good (50-150), Fair (150-300), Poor (300-500), Bad (500+)
  const finalScore = Math.max(0, Math.round(500 - composite * 5));
  
  return finalScore;
}

/**
 * Get score rating/grade
 */
function getScoreRating(score) {
  for (const [key, threshold] of Object.entries(SCORE_THRESHOLDS)) {
    if (score >= threshold.min && score < threshold.max) {
      return {
        grade: key,
        ...threshold,
        score,
      };
    }
  }
  return SCORE_THRESHOLDS.bad;
}

/**
 * Run multi-stage test (3 passes with delays)
 * @param {Function} probeFn - Async function to run probe
 * @param {number} passes - Number of test passes (default: 3)
 * @param {number} delayMs - Delay between passes (default: 1000)
 */
async function runMultiStageTest(probeFn, passes = 3, delayMs = 1000) {
  const results = [];
  const timestamps = [];
  
  for (let i = 0; i < passes; i++) {
    timestamps.push(Date.now());
    try {
      const result = await probeFn(i);
      results.push(result);
    } catch (e) {
      results.push({ error: e.message });
    }
    
    if (i < passes - 1) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }
  
  // Calculate averages
  const validResults = results.filter(r => !r.error);
  
  const avgMetrics = {
    avgMs: average(validResults.map(r => r.avgMs).filter(v => v !== null)),
    medianMs: median(validResults.map(r => r.medianMs || r.avgMs).filter(v => v !== null)),
    throughputKbps: average(validResults.map(r => r.throughputKbps).filter(v => v !== null)),
    lossPct: average(validResults.map(r => r.lossPct).filter(v => v !== null)),
    jitterMs: average(validResults.map(r => r.jitterMs).filter(v => v !== null)),
    cfVerified: validResults.some(r => r.cfVerified),
    successRate: validResults.length / passes,
  };
  
  // Calculate score from averaged metrics
  const score = calculateScore(avgMetrics);
  const rating = getScoreRating(score);
  
  return {
    rawResults: results,
    timestamps,
    averaged: avgMetrics,
    score,
    rating,
    passes,
    completedAt: Date.now(),
  };
}

/**
 * Check if score dropped below alert threshold
 */
function checkScoreAlert(itemId, currentScore, previousScore) {
  const alerts = [];
  
  if (currentScore >= ALERT_THRESHOLD && previousScore < ALERT_THRESHOLD) {
    alerts.push({
      type: 'threshold_crossed',
      message: `Item ${itemId} score crossed alert threshold (${previousScore} → ${currentScore})`,
      severity: 'warning',
      timestamp: Date.now(),
    });
  }
  
  if (previousScore && currentScore > previousScore * 1.5) {
    alerts.push({
      type: 'significant_drop',
      message: `Item ${itemId} score dropped significantly (${previousScore} → ${currentScore})`,
      severity: 'info',
      timestamp: Date.now(),
    });
  }
  
  return alerts;
}

/**
 * Compare scores and rank items
 */
function rankItems(items, sortBy = 'score') {
  return items.sort((a, b) => {
    if (sortBy === 'score') {
      return a.score - b.score; // Lower is better
    } else if (sortBy === 'ping') {
      return (a.avgMs || Infinity) - (b.avgMs || Infinity);
    } else if (sortBy === 'speed') {
      return (b.throughputKbps || 0) - (a.throughputKbps || 0);
    } else if (sortBy === 'stability') {
      return (a.lossPct || 0) - (b.lossPct || 0);
    }
    return 0;
  }).map((item, index) => ({
    ...item,
    rank: index + 1,
    rating: getScoreRating(item.score),
  }));
}

/**
 * Filter items by score range
 */
function filterByScore(items, minScore = 0, maxScore = 500) {
  return items.filter(item => 
    item.score >= minScore && item.score <= maxScore
  );
}

/**
 * Get items by rating grade
 */
function filterByRating(items, grade) {
  const threshold = SCORE_THRESHOLDS[grade];
  if (!threshold) return items;
  
  return items.filter(item => 
    item.score >= threshold.min && item.score < threshold.max
  );
}

/**
 * Generate score statistics
 */
function getScoreStats(items) {
  if (items.length === 0) {
    return {
      count: 0,
      avgScore: 0,
      minScore: 0,
      maxScore: 0,
      distribution: {},
    };
  }
  
  const scores = items.map(i => i.score);
  const distribution = {
    excellent: items.filter(i => i.score < 50).length,
    good: items.filter(i => i.score >= 50 && i.score < 150).length,
    fair: items.filter(i => i.score >= 150 && i.score < 300).length,
    poor: items.filter(i => i.score >= 300 && i.score < 500).length,
    bad: items.filter(i => i.score >= 500).length,
  };
  
  return {
    count: items.length,
    avgScore: Math.round(scores.reduce((a, b) => a + b, 0) / scores.length),
    minScore: Math.min(...scores),
    maxScore: Math.max(...scores),
    medianScore: median(scores),
    distribution,
    cleanCount: items.filter(i => i.clean).length,
    cleanPct: Math.round(items.filter(i => i.clean).length / items.length * 100),
  };
}

/**
 * Helper: Calculate average
 */
function average(arr) {
  const valid = arr.filter(v => v !== null && v !== undefined && !isNaN(v));
  if (valid.length === 0) return null;
  return valid.reduce((a, b) => a + b, 0) / valid.length;
}

/**
 * Helper: Calculate median
 */
function median(arr) {
  const valid = arr.filter(v => v !== null && v !== undefined && !isNaN(v)).sort((a, b) => a - b);
  if (valid.length === 0) return null;
  const mid = Math.floor(valid.length / 2);
  return valid.length % 2 === 0
    ? (valid[mid - 1] + valid[mid]) / 2
    : valid[mid];
}

/**
 * Export score history to CSV
 */
function exportHistoryToCSV(filePath, itemId = null) {
  const history = loadHistory();
  let records = history.records;
  
  if (itemId) {
    records = records.filter(r => r.itemId === itemId);
  }
  
  const headers = ['timestamp', 'itemId', 'itemType', 'score', 'avgMs', 'throughputKbps', 'lossPct', 'jitterMs'];
  const lines = [headers.join(',')];
  
  records.forEach(r => {
    lines.push([
      r.timestamp,
      r.itemId,
      r.itemType,
      r.score,
      r.metrics?.avgMs ?? '',
      r.metrics?.throughputKbps ?? '',
      r.metrics?.lossPct ?? '',
      r.metrics?.jitterMs ?? '',
    ].join(','));
  });
  
  fs.writeFileSync(filePath, lines.join('\n'));
  return records.length;
}

module.exports = {
  DEFAULT_WEIGHTS,
  SCORE_THRESHOLDS,
  ALERT_THRESHOLD,
  calculateScore,
  getScoreRating,
  runMultiStageTest,
  addScoreRecord,
  getScoreHistory,
  checkScoreAlert,
  rankItems,
  filterByScore,
  filterByRating,
  getScoreStats,
  exportHistoryToCSV,
  loadHistory,
  saveHistory,
};
