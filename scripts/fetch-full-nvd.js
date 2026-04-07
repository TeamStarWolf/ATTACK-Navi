#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
/**
 * Fetches ALL CVEs from NVD 2.0 API with full metadata.
 * Saves per-year JSON chunks for on-demand loading.
 *
 * Output: src/assets/data/nvd/
 *   nvd-index.json          — compact index (CVE ID, desc snippet, CVSS, year)
 *   nvd-2024.json           — full CVEs for 2024
 *   nvd-2023.json           — full CVEs for 2023
 *   ...etc per year
 *
 * Each CVE record includes:
 *   id, description, cvssScore, cvssVector, severity, cwes[], cpes[],
 *   published, lastModified, references[], attackIds[], isKev,
 *   exploitCount, epssScore, capabilityGroup
 */
const fs = require('fs');
const path = require('path');

// Load CWE_TO_ATTACK mapping
const svcPath = path.join(__dirname, '..', 'src', 'app', 'services', 'cve.service.ts');
const svcSrc = fs.readFileSync(svcPath, 'utf8');
const CWE_TO_ATTACK = {};
for (const m of svcSrc.matchAll(/'CWE-(\d+)':\s*\[([^\]]*)\]/g)) {
  CWE_TO_ATTACK[m[1]] = m[2].match(/'([^']+)'/g)?.map(s => s.replace(/'/g, '')) || [];
}
console.log('Loaded', Object.keys(CWE_TO_ATTACK).length, 'CWE mappings');

const apiKey = process.argv.includes('--api-key')
  ? process.argv[process.argv.indexOf('--api-key') + 1]
  : process.env.NVD_API_KEY || null;
const delayMs = apiKey ? 600 : 8000;
console.log('API key:', apiKey ? 'YES' : 'NO (~25 min)');

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const outDir = path.join(__dirname, '..', 'src', 'assets', 'data', 'nvd');
fs.mkdirSync(outDir, { recursive: true });

// All CVEs grouped by year
const byYear = {};
const index = []; // compact index entries
let totalProcessed = 0;

function parseCve(cve) {
  const id = cve.id;
  if (!id) return null;

  const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
  const cvss31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  const cvss30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
  const cvss2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
  const cvssData = cvss31 || cvss30 || cvss2;

  const cwes = [];
  for (const w of (cve.weaknesses || [])) {
    for (const d of (w.description || [])) {
      if (d.value?.startsWith('CWE-') && d.value !== 'CWE-noinfo' && d.value !== 'CWE-Other') {
        cwes.push(d.value);
      }
    }
  }

  // Map CWEs to ATT&CK techniques
  const attackIds = new Set();
  for (const cwe of cwes) {
    const num = cwe.replace('CWE-', '');
    const techs = CWE_TO_ATTACK[num];
    if (techs) for (const t of techs) attackIds.add(t);
  }

  // Extract CPEs (first 10)
  const cpes = [];
  for (const cfg of (cve.configurations || [])) {
    for (const node of (cfg.nodes || [])) {
      for (const match of (node.cpeMatch || [])) {
        if (match.criteria && cpes.length < 10) cpes.push(match.criteria);
      }
    }
  }

  // Extract references (first 10)
  const refs = [];
  for (const r of (cve.references || []).slice(0, 10)) {
    refs.push({ url: r.url, tags: r.tags || [] });
  }

  const severity = cvssData?.baseSeverity ||
    (cvssData?.baseScore >= 9 ? 'CRITICAL' : cvssData?.baseScore >= 7 ? 'HIGH' :
     cvssData?.baseScore >= 4 ? 'MEDIUM' : cvssData?.baseScore > 0 ? 'LOW' : 'NONE');

  return {
    id,
    description: desc.substring(0, 500),
    cvssScore: cvssData?.baseScore ?? null,
    cvssVector: cvssData?.vectorString ?? null,
    severity,
    cwes: [...new Set(cwes)],
    attackIds: [...attackIds],
    cpes: cpes.slice(0, 5),
    published: cve.published?.substring(0, 10) || '',
    lastModified: cve.lastModified?.substring(0, 10) || '',
    references: refs,
    // Enriched fields (filled if available)
    attackVector: cvssData?.attackVector || null,
    userInteraction: cvssData?.userInteraction || null,
    privilegesRequired: cvssData?.privilegesRequired || null,
    confidentialityImpact: cvssData?.confidentialityImpact || null,
    integrityImpact: cvssData?.integrityImpact || null,
    availabilityImpact: cvssData?.availabilityImpact || null,
  };
}

async function fetchPage(startIndex) {
  const url = `${NVD_BASE}?resultsPerPage=2000&startIndex=${startIndex}`;
  const headers = { Accept: 'application/json' };
  if (apiKey) headers['apiKey'] = apiKey;
  const resp = await fetch(url, { headers });
  if (!resp.ok) throw new Error(`NVD ${resp.status}: ${resp.statusText}`);
  return resp.json();
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log('Fetching total count...');
  const first = await fetchPage(0);
  const total = first.totalResults;
  console.log('Total CVEs in NVD:', total.toLocaleString());

  // Process first page
  for (const v of first.vulnerabilities) {
    const cve = parseCve(v.cve);
    if (!cve) continue;
    const year = cve.id.split('-')[1];
    if (!byYear[year]) byYear[year] = [];
    byYear[year].push(cve);
    index.push({ id: cve.id, d: cve.description.substring(0, 120), s: cve.cvssScore, sv: cve.severity, y: year, t: cve.attackIds.length });
  }
  totalProcessed += first.vulnerabilities.length;

  const totalPages = Math.ceil(total / 2000);
  for (let page = 1; page < totalPages; page++) {
    await sleep(delayMs);
    let retries = 3;
    while (retries > 0) {
      try {
        const data = await fetchPage(page * 2000);
        for (const v of data.vulnerabilities) {
          const cve = parseCve(v.cve);
          if (!cve) continue;
          const year = cve.id.split('-')[1];
          if (!byYear[year]) byYear[year] = [];
          byYear[year].push(cve);
          index.push({ id: cve.id, d: cve.description.substring(0, 120), s: cve.cvssScore, sv: cve.severity, y: year, t: cve.attackIds.length });
        }
        totalProcessed += data.vulnerabilities.length;
        const pct = ((totalProcessed / total) * 100).toFixed(1);
        process.stdout.write(`\rPage ${page}/${totalPages - 1}: ${totalProcessed.toLocaleString()}/${total.toLocaleString()} (${pct}%) — ${Object.keys(byYear).length} years`);
        break;
      } catch (err) {
        retries--;
        if (retries === 0) { console.error(`\nSkip page ${page}: ${err.message}`); break; }
        await sleep(delayMs * 3);
      }
    }
  }

  console.log('\n\nWriting output...');

  // Write per-year files
  const yearStats = {};
  for (const [year, cves] of Object.entries(byYear).sort()) {
    const filePath = path.join(outDir, `nvd-${year}.json`);
    fs.writeFileSync(filePath, JSON.stringify(cves));
    const sizeMB = (fs.statSync(filePath).size / 1024 / 1024).toFixed(1);
    yearStats[year] = { count: cves.length, sizeMB };
    console.log(`  nvd-${year}.json: ${cves.length.toLocaleString()} CVEs (${sizeMB} MB)`);
  }

  // Write index
  const indexPath = path.join(outDir, 'nvd-index.json');
  fs.writeFileSync(indexPath, JSON.stringify(index));
  const indexSizeMB = (fs.statSync(indexPath).size / 1024 / 1024).toFixed(1);
  console.log(`  nvd-index.json: ${index.length.toLocaleString()} entries (${indexSizeMB} MB)`);

  // Write stats
  const statsPath = path.join(outDir, 'nvd-stats.json');
  fs.writeFileSync(statsPath, JSON.stringify({
    totalCves: index.length,
    lastUpdated: new Date().toISOString(),
    years: yearStats,
    withAttackMapping: index.filter(e => e.t > 0).length,
  }));

  console.log(`\nDone! ${index.length.toLocaleString()} CVEs across ${Object.keys(byYear).length} years`);
  console.log(`CVEs with ATT&CK mapping: ${index.filter(e => e.t > 0).length.toLocaleString()}`);

  // Also export to Desktop
  const desktopDir = path.join('C:', 'Users', 'dev', 'Desktop', 'CVE-ATT&CK Mappings');
  try {
    fs.mkdirSync(desktopDir, { recursive: true });
    let csv = 'CVE_ID,Description,CVSS_Score,Severity,CWEs,ATT&CK_Techniques,Published,Attack_Vector,Privileges_Required\n';
    for (const cves of Object.values(byYear)) {
      for (const c of cves) {
        const desc = c.description.replace(/"/g, '""').substring(0, 200);
        csv += `${c.id},"${desc}",${c.cvssScore || ''},${c.severity},"${c.cwes.join(';')}","${c.attackIds.join(';')}",${c.published},${c.attackVector || ''},${c.privilegesRequired || ''}\n`;
      }
    }
    fs.writeFileSync(path.join(desktopDir, 'ALL-CVEs-full-metadata.csv'), csv);
    console.log(`CSV exported to Desktop (${(csv.length/1024/1024).toFixed(1)} MB)`);
  } catch (e) {
    console.log('Desktop export skipped:', e.message);
  }
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });
