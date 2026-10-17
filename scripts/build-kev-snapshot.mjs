// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Regenerates src/assets/data/kev-snapshot.json: a dated copy of the CISA Known
// Exploited Vulnerabilities catalog that the app reads only when the live KEV feed
// fails (plan section 6.3, epic E1.3). The snapshot is pinned by date: the script
// resolves the last commit of cisagov/kev-data (CISA's official GitHub mirror of the
// feed) on or before that date and fetches the catalog at that commit, so re-running
// it for the same date writes the same bytes.
//
//   node scripts/build-kev-snapshot.mjs                    re-pin to the date already in the file
//   node scripts/build-kev-snapshot.mjs --date 2026-10-16  move the pin to another date
//   node scripts/build-kev-snapshot.mjs --check            fetch and compare, write nothing (exit 1 on drift)
//
// Set GITHUB_TOKEN to lift the unauthenticated api.github.com rate limit. Requires
// Node 20+ (built-in fetch). No shell commands are run by this script.
//
// After moving the pin, update the 'cisa-kev-snapshot' version in
// src/app/services/source-inventory.ts (scripts/build-kev-snapshot.test.mjs checks it)
// and run node scripts/gen-facts.mjs.
//
// Licence: the KEV catalog is CC0 1.0 Universal (THIRD_PARTY_NOTICES.md section 1.5).

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const OUT = 'src/assets/data/kev-snapshot.json';
export const REPO = 'cisagov/kev-data';
export const FILE = 'known_exploited_vulnerabilities.json';

/**
 * The entry fields the app reads (models/cve.ts KevEntry). The free-text fields
 * (shortDescription, requiredAction, notes) are left out to keep the fallback small;
 * no view reads them.
 */
export const FIELDS = [
  'cveID',
  'vendorProject',
  'product',
  'vulnerabilityName',
  'dateAdded',
  'dueDate',
  'knownRansomwareCampaignUse',
  'cwes',
];

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const CVE = /^CVE-\d{4}-\d{4,}$/;

/** Keep the fields the app reads, in a fixed order; a field upstream omits stays omitted. */
export function slimEntry(v) {
  const out = {};
  for (const f of FIELDS) if (v[f] !== undefined) out[f] = v[f];
  return out;
}

/**
 * Build the snapshot document from the upstream catalog at a pinned commit.
 * Pure: the same inputs give the same output.
 */
export function buildSnapshot(catalog, pin) {
  const vulns = Array.isArray(catalog?.vulnerabilities) ? catalog.vulnerabilities : [];
  const vulnerabilities = vulns.map(slimEntry);
  return {
    __meta: {
      title: 'CISA Known Exploited Vulnerabilities catalog, dated snapshot',
      snapshotDate: pin.date,
      catalogVersion: String(catalog?.catalogVersion ?? ''),
      dateReleased: String(catalog?.dateReleased ?? ''),
      count: vulnerabilities.length,
      upstream: `https://github.com/${REPO}`,
      commit: pin.commit,
      commitDate: pin.commitDate,
      url: `https://raw.githubusercontent.com/${REPO}/${pin.commit}/${FILE}`,
      licence: 'CC0 1.0 Universal (CISA KEV); see THIRD_PARTY_NOTICES.md section 1.5',
      fields: FIELDS,
      generator: 'scripts/build-kev-snapshot.mjs',
      note:
        'Read only when the live KEV feed fails. A CVE added to KEV after snapshotDate is not in this file, ' +
        'so absence here is not evidence of no exploitation after that date.',
    },
    vulnerabilities,
  };
}

/** Problems that make a snapshot unusable; an empty list means it is sound. */
export function validateSnapshot(doc) {
  const problems = [];
  const m = doc?.__meta ?? {};
  if (!DATE.test(m.snapshotDate ?? '')) problems.push(`__meta.snapshotDate is not YYYY-MM-DD: ${m.snapshotDate}`);
  if (!/^[0-9a-f]{40}$/.test(m.commit ?? '')) problems.push(`__meta.commit is not a full commit sha: ${m.commit}`);
  if (!m.catalogVersion) problems.push('__meta.catalogVersion is empty');
  const vulns = Array.isArray(doc?.vulnerabilities) ? doc.vulnerabilities : [];
  if (vulns.length === 0) problems.push('no vulnerabilities');
  if (m.count !== vulns.length) problems.push(`__meta.count ${m.count} != ${vulns.length} entries`);
  const seen = new Set();
  for (const v of vulns) {
    if (!CVE.test(v.cveID ?? '')) problems.push(`bad cveID: ${v.cveID}`);
    else if (seen.has(v.cveID)) problems.push(`duplicate cveID: ${v.cveID}`);
    seen.add(v.cveID);
    if (!DATE.test(v.dateAdded ?? '')) problems.push(`${v.cveID}: bad dateAdded ${v.dateAdded}`);
    else if (DATE.test(m.snapshotDate ?? '') && v.dateAdded > m.snapshotDate) {
      problems.push(`${v.cveID}: dateAdded ${v.dateAdded} is after the snapshot date ${m.snapshotDate}`);
    }
    for (const k of Object.keys(v)) if (!FIELDS.includes(k)) problems.push(`${v.cveID}: unexpected field ${k}`);
  }
  return problems;
}

/** One entry per line: diffs between two pins show added and changed CVEs. */
export function serialize(doc) {
  const lines = doc.vulnerabilities.map((v) => '    ' + JSON.stringify(v));
  return (
    '{\n' +
    `  "__meta": ${JSON.stringify(doc.__meta)},\n` +
    '  "vulnerabilities": [\n' +
    lines.join(',\n') +
    '\n  ]\n}\n'
  );
}

async function getJson(url) {
  const headers = { 'User-Agent': 'ATTACK-Navi build script', Accept: 'application/json' };
  if (url.startsWith('https://api.github.com/') && process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, { headers });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText} from ${url}`);
      return await res.json();
    } catch (err) {
      lastError = err;
      if (attempt < 3) await new Promise((r) => setTimeout(r, 1000 * attempt));
    }
  }
  throw lastError;
}

/** The last commit that touched the catalog on or before the end of `date` (UTC). */
export async function resolvePin(date) {
  const api =
    `https://api.github.com/repos/${REPO}/commits?path=${FILE}` +
    `&until=${date}T23:59:59Z&per_page=1`;
  const commits = await getJson(api);
  const c = Array.isArray(commits) ? commits[0] : undefined;
  if (!c?.sha) throw new Error(`no commit of ${REPO}/${FILE} on or before ${date}`);
  return { date, commit: c.sha, commitDate: c.commit?.committer?.date ?? '' };
}

function parseArgs(argv) {
  const out = { date: null, check: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--check') out.check = true;
    else if (argv[i] === '--date') out.date = argv[++i];
    else if (argv[i].startsWith('--date=')) out.date = argv[i].slice('--date='.length);
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return out;
}

async function main(argv) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const target = join(root, OUT);
  const args = parseArgs(argv);
  const current = existsSync(target) ? JSON.parse(readFileSync(target, 'utf8')) : null;
  const date = args.date ?? current?.__meta?.snapshotDate;
  if (!date || !DATE.test(date)) {
    throw new Error('pass --date YYYY-MM-DD (no snapshot to take the pinned date from)');
  }

  const pin = await resolvePin(date);
  process.stdout.write(`pinned ${REPO}@${pin.commit.slice(0, 7)} (${pin.commitDate}) for ${date}\n`);
  const catalog = await getJson(`https://raw.githubusercontent.com/${REPO}/${pin.commit}/${FILE}`);
  const doc = buildSnapshot(catalog, pin);
  const problems = validateSnapshot(doc);
  if (problems.length) throw new Error(`snapshot rejected:\n  ${problems.slice(0, 20).join('\n  ')}`);
  const text = serialize(doc);

  if (args.check) {
    const onDisk = existsSync(target) ? readFileSync(target, 'utf8').replace(/\r\n/g, '\n') : '';
    if (onDisk !== text) {
      console.error(`${OUT} differs from ${REPO}@${pin.commit.slice(0, 7)}: run node scripts/build-kev-snapshot.mjs`);
      return 1;
    }
    console.log(`${OUT} matches ${REPO}@${pin.commit.slice(0, 7)}.`);
    return 0;
  }
  writeFileSync(target, text);
  console.log(
    `wrote ${OUT}: ${doc.__meta.count} entries, catalogVersion ${doc.__meta.catalogVersion}, ` +
      `snapshot of ${date}, ${Math.round(text.length / 1024)} KB`,
  );
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (err) => { console.error(err.message ?? err); process.exitCode = 1; },
  );
}
