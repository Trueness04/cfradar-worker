'use strict';
/**
 * Module 1: Domain List Management (Iranian + Foreign)
 * Supports separate scanning of Iranian and foreign Cloudflare-backed domains
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Popular foreign CDN-backed domains (Cloudflare customers)
const FOREIGN_DOMAINS = [
  // Tech & Services
  'discord.com', 'discordapp.com', 'steamcommunity.com', 'steampowered.com',
  'npmjs.com', 'yarnpkg.com', 'cdnjs.com', 'jsdelivr.net', 'unpkg.com',
  'github.io', 'gitlab.io', 'pages.dev', 'netlify.app', 'vercel.app',
  // Streaming & Media
  'twitch.tv', 'vimeo.com', 'dailymotion.com', 'soundcloud.com',
  'bandcamp.com', 'mixcloud.com',
  // Productivity
  'notion.so', 'trello.com', 'asana.com', 'figma.com', 'canva.com',
  'dropbox.com', 'box.com', 'airtable.com',
  // Communication
  'telegram.org', 'whatsapp.com', 'signal.org', 'slack.com',
  'zoom.us', 'teams.microsoft.com',
  // News & Content
  'medium.com', 'substack.com', 'ghost.io', 'wordpress.com',
  'blogger.com', 'tumblr.com', 'reddit.com',
  // Shopping
  'shopify.com', 'etsy.com', 'aliexpress.com',
  // Security & DNS
  'cloudflare-dns.com', 'dns.google', '1.1.1.1',
  // Testing & Speed
  'speed.cloudflare.com', 'benchmarks.cloudflare.com',
];

// Popular Iranian domains behind Cloudflare
const IRANIAN_DOMAINS = [
  // Banks & Finance
  'bankmellat.ir', 'bmi.ir', 'bsi.ir', 'tejaratbank.ir', 'refah-bank.ir',
  'parsian-bank.ir', 'eghtesadnovin.ir', 'samanbank.ir', 'shahr-bank.ir',
  // E-commerce
  'digikala.com', 'torob.com', 'emalls.ir', 'basalam.com',
  'divar.ir', 'sheypoor.com', 'bama.ir',
  // Services
  'snapp.taxi', 'tap30.org', 'alibaba.ir', 'flightright.ir',
  'digistyle.com', 'modiseh.com',
  // Tech & Startups
  'virgool.io', 'varzesh3.com', 'khabaronline.ir', 'isna.ir',
  'mehrnews.com', 'tasnimnews.com',
  // Education
  'maktabkhooneh.org', 'faradars.org', 'quera.ir',
];

const DATA_DIR = path.join(__dirname, '..', 'data');
const DOMAIN_CACHE_FILE = path.join(DATA_DIR, 'domain-cache.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/**
 * Load domain lists from cache or generate defaults
 */
function loadDomainLists() {
  let cache = { iranian: [], foreign: [], custom: [] };
  
  if (fs.existsSync(DOMAIN_CACHE_FILE)) {
    try {
      const raw = fs.readFileSync(DOMAIN_CACHE_FILE, 'utf-8');
      cache = JSON.parse(raw);
    } catch (_) {}
  }
  
  // Merge with defaults if empty
  if (!cache.iranian || cache.iranian.length === 0) {
    cache.iranian = [...IRANIAN_DOMAINS];
  }
  if (!cache.foreign || cache.foreign.length === 0) {
    cache.foreign = [...FOREIGN_DOMAINS];
  }
  if (!Array.isArray(cache.custom)) {
    cache.custom = [];
  }
  
  return cache;
}

/**
 * Save domain lists to cache
 */
function saveDomainLists(cache) {
  fs.writeFileSync(DOMAIN_CACHE_FILE, JSON.stringify(cache, null, 2));
}

/**
 * Add custom domains to a specific category
 */
function addCustomDomains(domains, category = 'custom') {
  const cache = loadDomainLists();
  const newDomains = domains.filter(d => d && !cache[category].includes(d.trim()));
  cache[category] = [...cache[category], ...newDomains.map(d => d.trim())];
  saveDomainLists(cache);
  return newDomains.length;
}

/**
 * Get all domains for scanning
 * @param {string} filter - 'iranian', 'foreign', 'all', 'custom'
 */
function getDomainsForScan(filter = 'all') {
  const cache = loadDomainLists();
  
  switch (filter) {
    case 'iranian':
      return cache.iranian;
    case 'foreign':
      return cache.foreign;
    case 'custom':
      return cache.custom;
    case 'all':
    default:
      return [...cache.iranian, ...cache.foreign, ...cache.custom];
  }
}

/**
 * Remove domains from a category
 */
function removeDomains(domains, category = 'custom') {
  const cache = loadDomainLists();
  const toRemove = new Set(domains.map(d => d.trim()));
  cache[category] = cache[category].filter(d => !toRemove.has(d));
  saveDomainLists(cache);
  return cache[category].length;
}

/**
 * Clear a specific category
 */
function clearCategory(category) {
  const cache = loadDomainLists();
  if (category !== 'custom') {
    // Reset to defaults instead of clearing
    cache[category] = category === 'iranian' ? [...IRANIAN_DOMAINS] : [...FOREIGN_DOMAINS];
  } else {
    cache[category] = [];
  }
  saveDomainLists(cache);
  return cache[category].length;
}

/**
 * Export domains to file
 */
function exportDomainsToFile(filePath, filter = 'all') {
  const domains = getDomainsForScan(filter);
  const content = domains.join('\n');
  fs.writeFileSync(filePath, content);
  return domains.length;
}

/**
 * Import domains from file
 */
function importDomainsFromFile(filePath, category = 'custom') {
  const content = fs.readFileSync(filePath, 'utf-8');
  const domains = content.split(/\r?\n/).map(d => d.trim()).filter(d => d && !d.startsWith('#'));
  return addCustomDomains(domains, category);
}

/**
 * Get statistics about domain lists
 */
function getDomainStats() {
  const cache = loadDomainLists();
  return {
    iranian: cache.iranian.length,
    foreign: cache.foreign.length,
    custom: cache.custom.length,
    total: cache.iranian.length + cache.foreign.length + cache.custom.length,
  };
}

module.exports = {
  loadDomainLists,
  saveDomainLists,
  getDomainsForScan,
  addCustomDomains,
  removeDomains,
  clearCategory,
  exportDomainsToFile,
  importDomainsFromFile,
  getDomainStats,
  IRANIAN_DOMAINS,
  FOREIGN_DOMAINS,
};
