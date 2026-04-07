#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
/**
 * Fetches ALL CVEs from NVD 2.0 API, extracts CWE IDs, maps to ATT&CK techniques
 * via CWE_TO_ATTACK, and outputs a pre-computed JSON asset.
 *
 * Usage:
 *   node scripts/fetch-all-cves.js [--api-key YOUR_KEY]
 *
 * Output: src/assets/data/cve-technique-map.json
 *   Format: { "T1190": ["CVE-2024-1234", ...], "T1059": [...], ... }
 *
 * Without API key: ~5 req/30s → ~15 min for full NVD
 * With API key:    ~50 req/30s → ~2 min for full NVD
 */

const fs = require('fs');
const path = require('path');

// Extract CWE_TO_ATTACK from cve.service.ts
const svcPath = path.join(__dirname, '..', 'src', 'app', 'services', 'cve.service.ts');
const svcSrc = fs.readFileSync(svcPath, 'utf8');
const mapMatch = svcSrc.match(/export const CWE_TO_ATTACK[^{]*(\{[\s\S]*?\n\};)/);
if (!mapMatch) { console.error('Could not extract CWE_TO_ATTACK'); process.exit(1); }

// Parse the map
const CWE_TO_ATTACK = {};
const entries = mapMatch[1].matchAll(/'CWE-(\d+)':\s*\[([^\]]*)\]/g);
for (const m of entries) {
  const cweId = m[1];
  const techIds = m[2].match(/'([^']+)'/g)?.map(s => s.replace(/'/g, '')) || [];
  CWE_TO_ATTACK[cweId] = techIds;
}
console.log(`Loaded ${Object.keys(CWE_TO_ATTACK).length} CWE→ATT&CK mappings`);

// Parse CLI args
const args = process.argv.slice(2);
const apiKeyIdx = args.indexOf('--api-key');
const apiKey = apiKeyIdx >= 0 ? args[apiKeyIdx + 1] : process.env.NVD_API_KEY || null;
const delayMs = apiKey ? 600 : 8000; // NVD rate limits: 5 req/30s without key
console.log(`API key: ${apiKey ? 'YES (fast mode)' : 'NO (slow mode, ~15 min)'}`);

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RESULTS_PER_PAGE = 2000;

// Result map: attackId → Set<cveId>
const techToCves = {};

function addMapping(attackId, cveId) {
  if (!techToCves[attackId]) techToCves[attackId] = new Set();
  techToCves[attackId].add(cveId);
}

async function fetchPage(startIndex) {
  const url = `${NVD_BASE}?resultsPerPage=${RESULTS_PER_PAGE}&startIndex=${startIndex}`;
  const headers = { 'Accept': 'application/json' };
  if (apiKey) headers['apiKey'] = apiKey;

  const resp = await fetch(url, { headers });
  if (!resp.ok) {
    throw new Error(`NVD API ${resp.status}: ${resp.statusText} (startIndex=${startIndex})`);
  }
  return resp.json();
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  console.log('Fetching total CVE count...');
  const first = await fetchPage(0);
  const total = first.totalResults;
  console.log(`Total CVEs in NVD: ${total.toLocaleString()}`);

  // Process first page
  processPage(first);
  let fetched = first.vulnerabilities.length;
  console.log(`Page 0: ${fetched} CVEs processed`);

  // Fetch remaining pages
  const totalPages = Math.ceil(total / RESULTS_PER_PAGE);
  for (let page = 1; page < totalPages; page++) {
    await sleep(delayMs);
    const startIndex = page * RESULTS_PER_PAGE;

    let retries = 3;
    while (retries > 0) {
      try {
        const data = await fetchPage(startIndex);
        processPage(data);
        fetched += data.vulnerabilities.length;
        const pct = ((fetched / total) * 100).toFixed(1);
        const mappedCount = Object.values(techToCves).reduce((s, set) => s + set.size, 0);
        process.stdout.write(`\rPage ${page}/${totalPages - 1}: ${fetched.toLocaleString()}/${total.toLocaleString()} CVEs (${pct}%) → ${mappedCount.toLocaleString()} mappings`);
        break;
      } catch (err) {
        retries--;
        if (retries === 0) {
          console.error(`\nFailed page ${page} after 3 retries: ${err.message}`);
          // Continue to next page instead of crashing
          break;
        }
        console.warn(`\nRetry page ${page}: ${err.message}`);
        await sleep(delayMs * 3);
      }
    }
  }

  console.log('\n\nDone fetching. Building output...');

  // Convert sets to sorted arrays
  const output = {};
  let totalMappings = 0;
  for (const [attackId, cveSet] of Object.entries(techToCves)) {
    const arr = [...cveSet].sort();
    output[attackId] = arr;
    totalMappings += arr.length;
  }

  // Sort by technique ID
  const sorted = {};
  for (const key of Object.keys(output).sort()) {
    sorted[key] = output[key];
  }

  const outPath = path.join(__dirname, '..', 'src', 'assets', 'data', 'cve-technique-map.json');
  fs.writeFileSync(outPath, JSON.stringify(sorted));

  const fileSizeKB = (fs.statSync(outPath).size / 1024).toFixed(0);
  console.log(`\nOutput: ${outPath}`);
  console.log(`Techniques with CVE mappings: ${Object.keys(sorted).length}`);
  console.log(`Total CVE→technique mappings: ${totalMappings.toLocaleString()}`);
  console.log(`File size: ${fileSizeKB} KB`);

  // Also export full uncapped CSV to Desktop folder
  const csvDir = path.join('data', 'cve-attack-mappings');
  try { fs.mkdirSync(csvDir, { recursive: true }); } catch {}
  let csv = 'CVE_ID,Technique_ID\n';
  for (const [tech, cves] of Object.entries(sorted)) {
    for (const cve of cves) csv += `${cve},${tech}\n`;
  }
  const csvPath = path.join(csvDir, 'cve-to-attack-FULL-4.5M.csv');
  fs.writeFileSync(csvPath, csv);
  console.log(`Full CSV: ${csvPath} (${(csv.length / 1024 / 1024).toFixed(1)} MB, ${totalMappings.toLocaleString()} rows)`);

  // Also write counts
  const countsPath = path.join(csvDir, 'cve-technique-counts-163.csv');
  let countsCsv = 'Technique_ID,CVE_Count\n';
  for (const [t, arr] of Object.entries(sorted).sort((a,b) => b[1].length - a[1].length)) {
    countsCsv += `${t},${arr.length}\n`;
  }
  fs.writeFileSync(countsPath, countsCsv);
  console.log(`Counts CSV: ${countsPath}`);

  // Write uncapped JSON too
  const jsonPath = path.join(csvDir, 'cve-technique-map-FULL.json');
  fs.writeFileSync(jsonPath, JSON.stringify(sorted));
  console.log(`Full JSON: ${jsonPath} (${(fs.statSync(jsonPath).size / 1024 / 1024).toFixed(1)} MB)`);
}

function processPage(data) {
  for (const vuln of (data.vulnerabilities || [])) {
    const cve = vuln.cve;
    if (!cve?.id) continue;
    const cveId = cve.id;

    // Extract CWE IDs
    const cwes = new Set();
    for (const w of (cve.weaknesses || [])) {
      for (const d of (w.description || [])) {
        const val = d.value || '';
        if (val.startsWith('CWE-') && val !== 'CWE-noinfo' && val !== 'CWE-Other') {
          cwes.add(val.replace('CWE-', ''));
        }
      }
    }

    // Map CWEs to ATT&CK techniques
    for (const cweNum of cwes) {
      const techIds = CWE_TO_ATTACK[cweNum];
      if (techIds) {
        for (const tid of techIds) {
          addMapping(tid, cveId);
        }
      }
    }
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
