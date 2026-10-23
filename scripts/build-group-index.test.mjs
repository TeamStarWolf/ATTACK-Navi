// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for scripts/build-group-index.mjs and the index it wrote
// (src/assets/data/group-index.json, RP-F decision 25). The builder's pure parts run
// on a fixture; the shipped file is checked against the bundled STIX files.
//
//   node --test scripts/build-group-index.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { BUNDLES, OUT, buildIndex, bundleVersion, serialize, validateIndex } from './build-group-index.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'build-group-index.mjs');

const ref = (id) => [{ source_name: 'mitre-attack', external_id: id, url: `https://attack.mitre.org/groups/${id}` }];
const collection = (v) => ({ type: 'x-mitre-collection', id: 'x-mitre-collection--1', x_mitre_version: v });
const set = (id, attackId, name, extra = {}) => ({ type: 'intrusion-set', id, name, aliases: [name], external_references: ref(attackId), ...extra });

const FIXTURE = [
  {
    domain: 'enterprise', bundle: { objects: [
      collection('19.2'),
      set('intrusion-set--b', 'G0002', 'Beta', { aliases: ['Beta', 'Bee', 'Bee'] }),
      set('intrusion-set--a', 'G0001', 'Alpha'),
      set('intrusion-set--r', 'G0003', 'Revoked', { revoked: true }),
      set('intrusion-set--d', 'G0004', 'Deprecated', { x_mitre_deprecated: true }),
      { type: 'attack-pattern', id: 'attack-pattern--x', name: 'not a group' },
    ] },
  },
  {
    domain: 'ics', bundle: { objects: [
      collection('19.2'),
      set('intrusion-set--a', 'G0001', 'Alpha'),
      set('intrusion-set--i', 'G1000', 'IcsOnly'),
      set('intrusion-set--r', 'G0003', 'Revoked', { revoked: true }),
    ] },
  },
  {
    domain: 'mobile', bundle: { objects: [
      set('intrusion-set--m', 'G0097', 'MobileOnly'),
      set('intrusion-set--d', 'G0004', 'Deprecated'),   // current in Mobile only
    ] },
  },
];

test('one entry per group across the bundles, sorted by ATT&CK id, with the domains that carry it as current', () => {
  const doc = buildIndex(FIXTURE);
  assert.deepEqual(doc.versions, { enterprise: '19.2', ics: '19.2', mobile: 'unknown' });
  assert.deepEqual(doc.groups.map((g) => [g.attackId, g.domains]), [
    ['G0001', ['enterprise', 'ics']],
    ['G0002', ['enterprise']],
    ['G0003', []],
    ['G0004', ['mobile']],
    ['G0097', ['mobile']],
    ['G1000', ['ics']],
  ]);
});

test('aliases drop the name and duplicates; revoked and deprecated are flags, and current wins over withdrawn', () => {
  const doc = buildIndex(FIXTURE);
  const by = Object.fromEntries(doc.groups.map((g) => [g.attackId, g]));
  assert.deepEqual(by.G0002.aliases, ['Bee']);
  assert.equal(by.G0003.revoked, true);
  assert.equal(by.G0004.deprecated, false);   // Mobile carries it as current
  assert.deepEqual(validateIndex(doc), []);
});

test('the same bundles give the same bytes', () => {
  assert.equal(serialize(buildIndex(FIXTURE)), serialize(buildIndex(FIXTURE)));
});

test('validateIndex names a duplicate id, a missing name and a current group with no domain', () => {
  const g = { attackId: 'G1', stixId: 'intrusion-set--1', name: 'One', aliases: [], revoked: false, deprecated: false, domains: ['enterprise'] };
  assert.deepEqual(validateIndex({ groups: [g, g] }), ['duplicate stixId intrusion-set--1', 'duplicate current attackId G1']);
  assert.deepEqual(validateIndex({ groups: [{ ...g, name: '', domains: [] }] }), ['no name for intrusion-set--1', 'current group intrusion-set--1 has no domain']);
  assert.deepEqual(validateIndex({}), ['no groups array']);
});

test('bundleVersion reads the collection version', () => {
  assert.equal(bundleVersion({ objects: [collection('18.1')] }), '18.1');
  assert.equal(bundleVersion({ objects: [] }), 'unknown');
});

test('the shipped index matches the bundled STIX files (--check), and names the groups round 4 walked', () => {
  const run = spawnSync(process.execPath, [SCRIPT, '--check'], { encoding: 'utf8', cwd: ROOT });
  assert.equal(run.status, 0, run.stderr);
  const doc = JSON.parse(readFileSync(join(ROOT, OUT), 'utf8'));
  const by = Object.fromEntries(doc.groups.map((g) => [g.attackId, g]));
  assert.deepEqual([by.G0016.name, by.G0016.domains], ['APT29', ['enterprise']]);
  assert.deepEqual([by.G0046.name, by.G0046.domains], ['FIN7', ['enterprise', 'ics']]);
  assert.deepEqual(by.G1000.domains, ['ics']);
  assert.deepEqual(by.G0097.domains, ['mobile']);
  assert.equal(by.G0057.revoked, true);
  assert.equal(by.G0014.deprecated, true);
  assert.ok(by.G0007.aliases.includes('Fancy Bear'));
  assert.equal(by.G9999, undefined);
  assert.deepEqual(BUNDLES.map((b) => b.domain), ['enterprise', 'ics', 'mobile']);
});
