// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Gate for the monthly data refresh (.github/workflows/refresh-data.yml).
// Compares the freshly downloaded bundles in the working tree with the
// committed ones (git HEAD) and fails when:
//   - a file is not a STIX bundle with an x-mitre-collection version,
//   - a bundle has fewer objects than the floor for its domain,
//   - the downloaded x_mitre_version is older than the committed one, or
//   - the three ATT&CK domains do not share one version (upstream mid-release).
// Prints a Markdown table (also appended to GITHUB_STEP_SUMMARY when set) and
// writes `versions=<json>` to GITHUB_OUTPUT so the PR body can cite it.
// Run locally with: node scripts/check-refreshed-bundles.mjs

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const bundles = [
  { key: 'enterprise', file: 'src/assets/data/enterprise-attack.json', minObjects: 100, attack: true },
  { key: 'ics', file: 'src/assets/data/ics-attack.json', minObjects: 100, attack: true },
  { key: 'mobile', file: 'src/assets/data/mobile-attack.json', minObjects: 100, attack: true },
  { key: 'f3', file: 'src/assets/data/f3-attack.json', minObjects: 50, attack: false },
];

function describe(text, label, minObjects) {
  let bundle;
  try {
    bundle = JSON.parse(text);
  } catch (error) {
    assert.fail(`${label}: not valid JSON (${error.message})`);
  }
  assert.equal(bundle.type, 'bundle', `${label}: not a STIX bundle`);
  assert(Array.isArray(bundle.objects), `${label}: no objects array`);
  assert(bundle.objects.length >= minObjects, `${label}: only ${bundle.objects.length} objects (floor ${minObjects})`);
  const collection = bundle.objects.find(object => object.type === 'x-mitre-collection');
  const version = collection?.x_mitre_version;
  assert.match(version ?? '', /^\d+(\.\d+)*$/, `${label}: no x-mitre-collection version`);
  return { version, objects: bundle.objects.length, modified: collection.modified ?? null };
}

function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return Math.sign(diff);
  }
  return 0;
}

function committedText(file) {
  return execFileSync('git', ['show', `HEAD:${file}`], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 1024,
  });
}

const rows = [];
const failures = [];
for (const { key, file, minObjects, attack } of bundles) {
  const committed = describe(committedText(file), `${key} (committed)`, minObjects);
  const fresh = describe(readFileSync(new URL(file, root), 'utf8'), `${key} (downloaded)`, minObjects);
  const order = compareVersions(fresh.version, committed.version);
  if (order < 0) {
    failures.push(`${key}: downloaded ${fresh.version} is older than committed ${committed.version}; refusing to downgrade`);
  }
  rows.push({ key, file, attack, committed, fresh, change: order > 0 ? 'upgrade' : order < 0 ? 'DOWNGRADE' : 'same version' });
}

const attackVersions = new Set(rows.filter(row => row.attack).map(row => row.fresh.version));
if (attackVersions.size > 1) {
  failures.push(`ATT&CK domains do not share one version (${[...attackVersions].join(', ')}); upstream is mid-release, retry later`);
}

const table = [
  '| Bundle | Committed | Downloaded | Objects (committed -> downloaded) | Change |',
  '| --- | --- | --- | --- | --- |',
  ...rows.map(row => `| ${row.key} | ${row.committed.version} | ${row.fresh.version} | ${row.committed.objects} -> ${row.fresh.objects} | ${row.change} |`),
].join('\n');
console.log(table);
if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Bundle version gate\n\n${table}\n\n`);
}
if (process.env.GITHUB_OUTPUT) {
  const versions = Object.fromEntries(rows.map(row => [row.key, { committed: row.committed.version, downloaded: row.fresh.version, objects: row.fresh.objects }]));
  appendFileSync(process.env.GITHUB_OUTPUT, `versions=${JSON.stringify(versions)}\n`);
}
if (failures.length > 0) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exit(1);
}
console.log(`PASS ${rows.length} bundles; ATT&CK ${[...attackVersions][0]}, F3 ${rows.find(row => row.key === 'f3').fresh.version}`);
