// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for scripts/build-kev-snapshot.mjs and the snapshot it wrote. No network:
// the builder's pure parts run on a fixture, and the shipped file is checked against
// itself, the source registry and the notices.
//
//   node --test scripts/build-kev-snapshot.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FIELDS, OUT, buildSnapshot, serialize, slimEntry, validateSnapshot } from './build-kev-snapshot.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => readFileSync(join(ROOT, rel), 'utf8').replace(/\r\n/g, '\n');

const PIN = { date: '2026-10-16', commit: 'a'.repeat(40), commitDate: '2026-10-16T19:22:34Z' };
const CATALOG = {
  title: 'CISA Catalog of Known Exploited Vulnerabilities',
  catalogVersion: '2026.10.16',
  dateReleased: '2026-10-16T17:15:48.8752Z',
  count: 2,
  vulnerabilities: [
    {
      cveID: 'CVE-2024-3400', vendorProject: 'Palo Alto Networks', product: 'PAN-OS', vulnerabilityName: 'x',
      dateAdded: '2024-04-12', shortDescription: 'long text', requiredAction: 'patch', dueDate: '2024-04-19',
      knownRansomwareCampaignUse: 'Known', forensicTriage: 'No', notes: 'https://example.invalid', cwes: ['CWE-77'],
    },
    {
      cveID: 'CVE-2021-44228', vendorProject: 'Apache', product: 'Log4j2', vulnerabilityName: 'y',
      dateAdded: '2021-12-10', dueDate: '2021-12-24', knownRansomwareCampaignUse: 'Known',
    },
  ],
};

test('keeps only the fields the app reads, in a fixed order', () => {
  const e = slimEntry(CATALOG.vulnerabilities[0]);
  assert.deepEqual(Object.keys(e), FIELDS);
  assert.equal(e.notes, undefined);
  assert.equal(e.forensicTriage, undefined);
  // A field upstream omits stays omitted rather than invented.
  assert.equal('cwes' in slimEntry(CATALOG.vulnerabilities[1]), false);
});

test('is deterministic: the same catalogue and pin give the same bytes', () => {
  const a = serialize(buildSnapshot(CATALOG, PIN));
  const b = serialize(buildSnapshot(structuredClone(CATALOG), { ...PIN }));
  assert.equal(a, b);
  const doc = JSON.parse(a);
  assert.equal(doc.__meta.snapshotDate, '2026-10-16');
  assert.equal(doc.__meta.count, 2);
  assert.match(doc.__meta.url, new RegExp(`/${PIN.commit}/known_exploited_vulnerabilities.json$`));
  assert.deepEqual(validateSnapshot(doc), []);
});

test('rejects an undated, empty, duplicated or post-dated snapshot', () => {
  assert.ok(validateSnapshot(buildSnapshot(CATALOG, { ...PIN, date: '' })).some((p) => p.includes('snapshotDate')));
  assert.ok(validateSnapshot(buildSnapshot({ ...CATALOG, vulnerabilities: [] }, PIN)).includes('no vulnerabilities'));
  const dup = buildSnapshot({ ...CATALOG, vulnerabilities: [CATALOG.vulnerabilities[0], CATALOG.vulnerabilities[0]] }, PIN);
  assert.ok(validateSnapshot(dup).some((p) => p.startsWith('duplicate cveID')));
  const late = buildSnapshot(CATALOG, { ...PIN, date: '2023-01-01' });
  assert.ok(validateSnapshot(late).some((p) => p.includes('after the snapshot date')));
  assert.ok(validateSnapshot(buildSnapshot(CATALOG, { ...PIN, commit: 'main' })).some((p) => p.includes('commit')));
});

test('the shipped snapshot is sound and byte-identical to what the builder writes', () => {
  const text = read(OUT);
  const doc = JSON.parse(text);
  assert.deepEqual(validateSnapshot(doc), []);
  assert.equal(serialize(doc), text);
  assert.ok(doc.vulnerabilities.some((v) => v.cveID === 'CVE-2024-3400' && v.dateAdded === '2024-04-12'));
});

test('the source registry names the shipped snapshot (date, catalogue version, commit)', () => {
  const { __meta: m } = JSON.parse(read(OUT));
  const inventory = read('src/app/services/source-inventory.ts');
  const block = inventory.match(/export const BUNDLED_KEV_SNAPSHOT = \{([\s\S]*?)\} as const;/);
  assert.ok(block, 'BUNDLED_KEV_SNAPSHOT in source-inventory.ts');
  assert.ok(block[1].includes(`date: '${m.snapshotDate}'`), 'snapshot date in BUNDLED_KEV_SNAPSHOT');
  assert.ok(block[1].includes(`catalogVersion: '${m.catalogVersion}'`), 'catalogue version in BUNDLED_KEV_SNAPSHOT');
  assert.ok(block[1].includes(`commit: '${m.commit}'`), 'generator commit in BUNDLED_KEV_SNAPSHOT');
});

test('THIRD_PARTY_NOTICES covers the bundled snapshot under the KEV CC0 notice', () => {
  const notices = read('THIRD_PARTY_NOTICES.md');
  assert.match(notices, /src\/assets\/data\/kev-snapshot\.json/);
  assert.match(notices, /CC0 1\.0 Universal/);
});
