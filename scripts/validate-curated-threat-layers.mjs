// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
// Run offline with node scripts/validate-curated-threat-layers.mjs (npm run validate:layers).
// Add --verify-baseline to also fetch and verify the official 16.1 snapshot.
// Add --update-bundled-metadata after replacing src/assets/data/enterprise-attack.json
// (the monthly refresh workflow does this): the three curated layers' recorded
// bundled version and bundled_sha256_lf are rewritten to the new snapshot and
// the layers are then validated against it, so a retired technique or a moved
// tactic still fails the run and has to be curated by hand.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const layerRoot = new URL('src/assets/data/library-layers/', root);
const files = [
  'macos-linux-attacks.json',
  'insider-threat.json',
  'destruction-extortion-disruption.json',
];
const baselineUrl = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-16.1.json';
const baselineHash = '8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813';
const sha256 = text => createHash('sha256').update(text).digest('hex');
const readJson = url => JSON.parse(readFileSync(url, 'utf8'));
// Git checkout settings vary by platform; fingerprint the bundled JSON with LF endings.
const bundledText = readFileSync(new URL('src/assets/data/enterprise-attack.json', root), 'utf8').replace(/\r\n/g, '\n');
const bundled = JSON.parse(bundledText);
const manifest = readJson(new URL('index.json', layerRoot));
const args = process.argv.slice(2);
const knownArgs = ['--verify-baseline', '--update-bundled-metadata'];
assert(args.every(arg => knownArgs.includes(arg)), `Unknown argument; expected one of ${knownArgs.join(', ')}`);
const updateBundledMetadata = args.includes('--update-bundled-metadata');
const escapeRegExp = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function techniquesById(bundle) {
  return new Map(bundle.objects
    .filter(object => object.type === 'attack-pattern' && !object.revoked && !object.x_mitre_deprecated)
    .map(object => [object.external_references?.find(ref => ref.source_name === 'mitre-attack')?.external_id, object])
    .filter(([id]) => id));
}

function tacticsOf(technique) {
  return technique.kill_chain_phases
    .filter(phase => phase.kill_chain_name === 'mitre-attack')
    .map(phase => phase.phase_name)
    .sort();
}

// The bundled version is read from the snapshot itself; each curated layer must
// record the same version in its description and metadata, so a refreshed
// bundle fails validation until the layers are revalidated (or rewritten with
// --update-bundled-metadata) against it.
const bundledVersion = bundled.objects.find(object => object.type === 'x-mitre-collection')?.x_mitre_version;
assert.match(bundledVersion ?? '', /^\d+\.\d+$/, 'Bundled snapshot has no x-mitre-collection version');
const bundledHash = sha256(bundledText);
const bundledVersionPattern = new RegExp(`\\b${escapeRegExp(bundledVersion)}\\b`);
const snapshots = [{ name: `bundled ${bundledVersion}`, techniques: techniquesById(bundled) }];
if (args.includes('--verify-baseline')) {
  const response = await fetch(baselineUrl, { signal: AbortSignal.timeout(60000) });
  assert(response.ok, `Official baseline HTTP ${response.status}`);
  const text = await response.text();
  assert.equal(sha256(text), baselineHash, 'Official baseline bytes changed; review before accepting');
  const baseline = JSON.parse(text);
  assert.equal(baseline.objects.find(object => object.type === 'x-mitre-collection')?.x_mitre_version, '16.1');
  snapshots.push({ name: 'official 16.1', techniques: techniquesById(baseline) });
}

assert.equal(new Set(manifest.map(entry => entry.file)).size, manifest.length, 'Duplicate manifest file');
assert.equal(new Set(manifest.map(entry => entry.name)).size, manifest.length, 'Duplicate manifest name');
for (const entry of manifest) {
  assert.match(entry.file, /^[a-z0-9-]+\.json$/, 'Unexpected manifest path');
  assert.equal(readJson(new URL(entry.file, layerRoot)).name, entry.name, `${entry.file}: name drift`);
}

// Rewrites the version the layer records for the bundled snapshot (description,
// tactic_policy, validation_source, versions.attack) and its bundled_sha256_lf.
// Only those fields carry the version; technique rows are never touched.
function refreshBundledMetadata(layer, entry, file) {
  const recorded = layer.description.match(/bundled Enterprise ATT&CK (\d+\.\d+) dataset/)?.[1];
  assert(recorded, `${file}: description does not record the bundled version`);
  const swap = text => text.replace(new RegExp(`\\b${escapeRegExp(recorded)}\\b`, 'g'), bundledVersion);
  layer.description = swap(layer.description);
  entry.description = layer.description;
  layer.versions.attack = bundledVersion.split('.')[0];
  for (const item of layer.metadata) {
    if (item.name === 'bundled_sha256_lf') item.value = bundledHash;
    if (item.name === 'tactic_policy' || item.name === 'validation_source') item.value = swap(item.value);
  }
  writeFileSync(new URL(file, layerRoot), `${JSON.stringify(layer, null, 2)}\n`);
  console.log(`UPDATED ${file}: bundled ${recorded} -> ${bundledVersion}, bundled_sha256_lf ${bundledHash.slice(0, 12)}...`);
}

for (const file of files) {
  const layer = readJson(new URL(file, layerRoot));
  const entry = manifest.find(item => item.file === file);
  assert(entry, `${file}: missing manifest entry`);
  if (updateBundledMetadata) refreshBundledMetadata(layer, entry, file);
  assert.equal(entry.description, layer.description, `${file}: description drift`);
  assert(entry.blurb?.length > 40 && entry.blurb.length < 300, `${file}: missing or oversized blurb`);
  assert.deepEqual(layer.versions, { attack: bundledVersion.split('.')[0], navigator: '4.9', layer: '4.5' },
    `${file}: versions.attack must match the bundled major version`);
  assert.equal(layer.domain, 'enterprise-attack');
  assert.equal(layer.selectSubtechniquesWithParent, false);
  assert.match(layer.description, /not an official MITRE mapping/);
  assert.match(layer.description, /coverage guarantee/);
  assert.match(layer.description, new RegExp(`16\\.1.*\\b${escapeRegExp(bundledVersion)}\\b`),
    `${file}: description must cite the official 16.1 baseline and the bundled ${bundledVersion} snapshot; bundled snapshot changed, revalidate the layer provenance`);
  assert.match(layer.description, new RegExp(`bundled Enterprise ATT&CK ${escapeRegExp(bundledVersion)} dataset`),
    `${file}: description records a different bundled version than the snapshot (${bundledVersion})`);
  assert.equal(layer.gradient.minValue, 0);
  assert.equal(layer.gradient.maxValue, 100);
  assert.deepEqual(layer.legendItems.map(item => item.label), [
    '100: Core (curated membership)', '55: Supporting (curated membership)',
  ]);

  const metadata = new Map(layer.metadata.map(item => [item.name, item.value]));
  assert.equal(metadata.size, layer.metadata.length, `${file}: duplicate metadata`);
  assert.equal(metadata.get('baseline_sha256'), baselineHash);
  assert.equal(metadata.get('bundled_sha256_lf'), bundledHash,
    `${file}: bundled_sha256_lf does not match src/assets/data/enterprise-attack.json; run with --update-bundled-metadata after a refresh`);
  for (const name of ['tactic_policy', 'validation_source']) {
    assert.match(metadata.get(name) ?? '', bundledVersionPattern, `${file}: ${name} must cite the bundled ${bundledVersion} snapshot`);
  }
  const pairs = new Set();
  const byId = new Map();
  for (const row of layer.techniques) {
    assert([55, 100].includes(row.score), `${file}: invalid tier`);
    const pair = `${row.techniqueID}/${row.tactic}`;
    assert(!pairs.has(pair), `${file}: duplicate pair ${pair}`);
    pairs.add(pair);
    assert(row.comment.length > 50, `${file}: missing rationale for ${pair}`);
    assert(row.comment.includes(row.score === 100 ? '. Core: ' : '. Supporting: '), `${file}: tier/comment mismatch`);
    if (!byId.has(row.techniqueID)) byId.set(row.techniqueID, []);
    byId.get(row.techniqueID).push(row);
    if (file === 'destruction-extortion-disruption.json') {
      assert.equal(row.tactic === 'impact', row.score === 100, `${file}: core/supporting scope drift`);
    }
  }

  for (const [id, rows] of byId) {
    assert.equal(new Set(rows.map(row => row.score)).size, 1, `${file}: inconsistent tier for ${id}`);
    assert.equal(new Set(rows.map(row => row.comment)).size, 1, `${file}: inconsistent rationale for ${id}`);
    for (const snapshot of snapshots) {
      const technique = snapshot.techniques.get(id);
      assert(technique, `${file}: ${id} missing, revoked or deprecated in ${snapshot.name}`);
      assert.deepEqual(rows.map(row => row.tactic).sort(), tacticsOf(technique),
        `${file}: tactic mismatch for ${id} in ${snapshot.name}`);
      if (file === 'macos-linux-attacks.json') {
        const platforms = technique.x_mitre_platforms.filter(platform => ['Linux', 'macOS'].includes(platform)).sort();
        assert(platforms.length > 0, `${file}: no relevant platform for ${id}`);
        for (const row of rows) {
          const declared = row.metadata?.find(item => item.name === 'platform_scope')?.value.split(', ').sort();
          assert.deepEqual(declared, platforms, `${file}: platform mismatch for ${id} in ${snapshot.name}`);
        }
      }
    }
  }
  const core = [...byId.values()].filter(rows => rows[0].score === 100).length;
  const supporting = byId.size - core;
  assert(core > 0 && supporting > 0, `${file}: both tiers required`);
  assert.equal(metadata.get('techniques_scored'), String(byId.size));
  assert.equal(metadata.get('technique_tactic_entries'), String(pairs.size));
  assert.equal(metadata.get('core_techniques'), String(core));
  assert.equal(metadata.get('supporting_techniques'), String(supporting));
  assert(layer.links.length >= 3, `${file}: missing provenance links`);
  for (const link of layer.links) {
    const url = new URL(link.url);
    assert.equal(url.protocol, 'https:');
    assert.equal(url.hostname, 'github.com');
    assert(!url.username && !url.password && !url.search, `${file}: unexpected URL metadata`);
  }
  console.log(`PASS ${file}: ${byId.size} techniques, ${pairs.size} rows, ${core} core / ${supporting} supporting`);
}
if (updateBundledMetadata) {
  writeFileSync(new URL('index.json', layerRoot), `${JSON.stringify(manifest, null, 2)}\n`);
}
console.log(`PASS ${manifest.length} manifest entries; checked ${snapshots.map(snapshot => snapshot.name).join(' + ')}`);
