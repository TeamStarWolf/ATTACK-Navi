#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Regenerates src/assets/data/group-index.json: every ATT&CK group (intrusion-set)
// of the bundled Enterprise, ICS and Mobile STIX files, with its ATT&CK id, STIX
// id, name, aliases, revoked and deprecated flags and the domains that carry it
// (RP-F decision 25). The threat profile resolves stored group ids against it, so
// a real group the loaded domain lacks reads "<name> has no <domain> use" on a
// fresh boot into that domain, and only an id the index does not hold as a current
// group reads "<id>: unknown or withdrawn group id".
//
// The file is derived from the bundles only, so re-running it on the same bundles
// writes the same bytes. A domain is listed for a group when that domain's bundle
// carries the group and neither revokes nor deprecates it there.
//
//   node scripts/build-group-index.mjs            write the index
//   node scripts/build-group-index.mjs --check    compare, write nothing (exit 1 on drift)
//
// Run it after a bundle refresh (refresh-data.yml does), then commit the index.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const OUT = 'src/assets/data/group-index.json';

/** The bundles the index is built from, in the order a group's domains are listed. */
export const BUNDLES = [
  { domain: 'enterprise', file: 'src/assets/data/enterprise-attack.json' },
  { domain: 'ics', file: 'src/assets/data/ics-attack.json' },
  { domain: 'mobile', file: 'src/assets/data/mobile-attack.json' },
];

/** The ATT&CK id of a STIX object ('' when it has none). */
function attackIdOf(obj) {
  const ref = (obj.external_references ?? []).find((r) => r && r.source_name === 'mitre-attack' && typeof r.external_id === 'string');
  return ref ? ref.external_id : '';
}

/** The ATT&CK release a bundle carries (its x-mitre-collection version), or 'unknown'. */
export function bundleVersion(bundle) {
  const c = (bundle.objects ?? []).find((o) => o && o.type === 'x-mitre-collection');
  return c && typeof c.x_mitre_version === 'string' ? c.x_mitre_version : 'unknown';
}

/**
 * Build the index document from parsed bundles ([{ domain, bundle }]). Pure: the same
 * bundles give the same document. A group carried by several bundles is one entry; its
 * name and aliases come from the first bundle that carries it as current (else the
 * first that carries it at all), and it is revoked or deprecated only when no bundle
 * carries it as current.
 */
export function buildIndex(inputs) {
  const byId = new Map();
  const versions = {};
  for (const { domain, bundle } of inputs) {
    versions[domain] = bundleVersion(bundle);
    for (const obj of bundle.objects ?? []) {
      if (!obj || obj.type !== 'intrusion-set' || typeof obj.id !== 'string') continue;
      const current = !obj.revoked && !obj.x_mitre_deprecated;
      const seen = byId.get(obj.id);
      const fields = {
        attackId: attackIdOf(obj),
        stixId: obj.id,
        name: typeof obj.name === 'string' ? obj.name : '',
        aliases: Array.isArray(obj.aliases) ? obj.aliases.filter((a) => typeof a === 'string' && a !== obj.name) : [],
      };
      if (!seen) {
        byId.set(obj.id, { ...fields, revoked: !!obj.revoked, deprecated: !!obj.x_mitre_deprecated, domains: current ? [domain] : [], current });
        continue;
      }
      if (current) {
        if (!seen.current) Object.assign(seen, fields, { revoked: false, deprecated: false, current: true });
        if (!seen.domains.includes(domain)) seen.domains.push(domain);
      }
    }
  }
  const groups = [...byId.values()]
    .map(({ current, ...g }) => ({ ...g, aliases: [...new Set(g.aliases)].sort() }))
    .sort((a, b) => a.attackId.localeCompare(b.attackId) || a.stixId.localeCompare(b.stixId));
  return { generatedBy: 'node scripts/build-group-index.mjs', versions, groups };
}

/** The file's bytes: the header fields, then one group per line, so a refresh diff names each group. */
export function serialize(doc) {
  const lines = doc.groups.map((g) => `    ${JSON.stringify(g)}`);
  return [
    '{',
    `  "generatedBy": ${JSON.stringify(doc.generatedBy)},`,
    `  "versions": ${JSON.stringify(doc.versions)},`,
    '  "groups": [',
    lines.join(',\n'),
    '  ]',
    '}',
    '',
  ].join('\n');
}

/** Problems with an index document: a missing field, a duplicate id, a current group with no domain. */
export function validateIndex(doc) {
  const problems = [];
  if (!doc || !Array.isArray(doc.groups)) return ['no groups array'];
  const stix = new Set();
  const attack = new Set();
  for (const g of doc.groups) {
    if (!/^intrusion-set--\S+$/.test(g.stixId ?? '')) problems.push(`bad stixId ${g.stixId}`);
    if (stix.has(g.stixId)) problems.push(`duplicate stixId ${g.stixId}`);
    stix.add(g.stixId);
    const current = !g.revoked && !g.deprecated;
    if (current && g.attackId && attack.has(g.attackId)) problems.push(`duplicate current attackId ${g.attackId}`);
    if (current && g.attackId) attack.add(g.attackId);
    if (typeof g.name !== 'string' || g.name === '') problems.push(`no name for ${g.stixId}`);
    if (!Array.isArray(g.aliases)) problems.push(`no aliases array for ${g.stixId}`);
    if (current && (!Array.isArray(g.domains) || g.domains.length === 0)) problems.push(`current group ${g.stixId} has no domain`);
  }
  return problems;
}

function main(argv) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const inputs = BUNDLES.map(({ domain, file }) => ({ domain, bundle: JSON.parse(readFileSync(join(root, file), 'utf8')) }));
  const doc = buildIndex(inputs);
  const problems = validateIndex(doc);
  if (problems.length) {
    for (const p of problems) console.error(`build-group-index: ${p}`);
    return 1;
  }
  const text = serialize(doc);
  const out = join(root, OUT);
  if (argv.includes('--check')) {
    let current = '';
    try { current = readFileSync(out, 'utf8').replace(/\r\n/g, '\n'); } catch { /* missing reads as drift */ }
    if (current !== text) {
      console.error(`build-group-index: ${OUT} is out of date with the bundled STIX files; run node scripts/build-group-index.mjs`);
      return 1;
    }
    console.log(`build-group-index: ${OUT} matches the bundles (${doc.groups.length} groups)`);
    return 0;
  }
  writeFileSync(out, text);
  console.log(`build-group-index: wrote ${OUT} (${doc.groups.length} groups)`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) process.exit(main(process.argv.slice(2)));
