// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
// Run offline with node scripts/validate-curated-threat-layers.mjs.
// Add --verify-baseline to also fetch and verify the official 16.1 snapshot.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const dataRoot = new URL('src/assets/data/', root);
const layerRoot = new URL('library-layers/', dataRoot);
const missionRoot = new URL('lylat-mission-layers/', dataRoot);
const files = [
  'macos-linux-attacks.json',
  'insider-threat.json',
  'destruction-extortion-disruption.json',
];
const baselineUrl = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-16.1.json';
const baselineHash = '8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813';
const sha256 = text => createHash('sha256').update(text).digest('hex');
const readJson = url => JSON.parse(readFileSync(url, 'utf8'));
// Git checkout settings vary by platform; read text with LF endings.
const readText = url => readFileSync(url, 'utf8').replace(/\r\n/g, '\n');
const bundledText = readText(new URL('enterprise-attack.json', dataRoot));
const bundled = JSON.parse(bundledText);
const manifest = readJson(new URL('index.json', layerRoot));
const args = process.argv.slice(2);
assert(args.every(arg => arg === '--verify-baseline'), 'Unknown argument');

function techniquesById(bundle) {
  return new Map(bundle.objects
    .filter(object => object.type === 'attack-pattern' && !object.revoked && !object.x_mitre_deprecated)
    .map(object => [object.external_references?.find(ref => ref.source_name === 'mitre-attack')?.external_id, object])
    .filter(([id]) => id));
}

// Kill-chain names are per domain: mitre-attack, mitre-ics-attack, mitre-mobile-attack.
function tacticsOf(technique) {
  return technique.kill_chain_phases
    .filter(phase => /^mitre-(ics-|mobile-)?attack$/.test(phase.kill_chain_name))
    .map(phase => phase.phase_name)
    .sort();
}

function collectionVersion(bundle) {
  return bundle.objects.find(object => object.type === 'x-mitre-collection')?.x_mitre_version;
}

const snapshots = [{ name: 'bundled 19.2', techniques: techniquesById(bundled) }];
assert.equal(collectionVersion(bundled), '19.2',
  'Bundled snapshot changed; revalidate the layer provenance');
if (args.includes('--verify-baseline')) {
  const response = await fetch(baselineUrl, { signal: AbortSignal.timeout(60000) });
  assert(response.ok, `Official baseline HTTP ${response.status}`);
  const text = await response.text();
  assert.equal(sha256(text), baselineHash, 'Official baseline bytes changed; review before accepting');
  const baseline = JSON.parse(text);
  assert.equal(collectionVersion(baseline), '16.1');
  snapshots.push({ name: 'official 16.1', techniques: techniquesById(baseline) });
}

// The three bundled ATT&CK domains must move together: ICS and Mobile were once left at
// 18.1 after Enterprise was bumped to 19.2, so the ICS matrix showed retired techniques.
const domainBundles = {
  'enterprise-attack': bundled,
  'ics-attack': readJson(new URL('ics-attack.json', dataRoot)),
  'mobile-attack': readJson(new URL('mobile-attack.json', dataRoot)),
};
const bundledVersions = Object.fromEntries(Object.entries(domainBundles).map(([domain, bundle]) => [domain, collectionVersion(bundle)]));
assert.equal(new Set(Object.values(bundledVersions)).size, 1,
  `Bundled ATT&CK domains disagree on x_mitre_version: ${JSON.stringify(bundledVersions)}`);
const f3Version = collectionVersion(readJson(new URL('f3-attack.json', dataRoot)));
assert(f3Version, 'Bundled F3 snapshot has no x-mitre-collection version');

// README's data-source table must state the versions that are really bundled.
const readme = readText(new URL('README.md', root));
for (const [label, version] of [
  ['Enterprise ATT&CK', bundledVersions['enterprise-attack']],
  ['ICS ATT&CK', bundledVersions['ics-attack']],
  ['Mobile ATT&CK', bundledVersions['mobile-attack']],
  ['CTID F3 Fraud Framework', f3Version],
]) {
  const row = readme.split('\n').find(line => line.startsWith(`| ${label} |`));
  assert(row, `README.md: no data-source row for ${label}`);
  assert(row.endsWith(`| v${version} |`), `README.md: ${label} row says "${row}" but the bundled snapshot is v${version}`);
}

assert.equal(new Set(manifest.map(entry => entry.file)).size, manifest.length, 'Duplicate manifest file');
assert.equal(new Set(manifest.map(entry => entry.name)).size, manifest.length, 'Duplicate manifest name');
for (const entry of manifest) {
  assert.match(entry.file, /^[a-z0-9-]+\.json$/, 'Unexpected manifest path');
  assert.equal(readJson(new URL(entry.file, layerRoot)).name, entry.name, `${entry.file}: name drift`);
}

// Headline layer counts in the docs must match the manifest.
for (const [doc, pattern] of [
  ['docs/LIBRARY_LAYERS.md', /This build ships \*\*(\d+) layers\*\*/],
  ['docs/README.md', /The (\d+) bundled ATT&CK overlays/],
]) {
  const match = readText(new URL(doc, root)).match(pattern);
  assert(match, `${doc}: layer-count sentence not found`);
  assert.equal(Number(match[1]), manifest.length, `${doc}: says ${match[1]} layers, manifest has ${manifest.length}`);
}

// Every manifest layer must resolve against the bundled enterprise snapshot: live
// technique ids, and a tactic slug (when present) that the technique really has.
function assertRowsResolve(file, rows, techniques, snapshotName) {
  let unresolvedTactics = 0;
  for (const row of rows) {
    if (row.techniqueID.startsWith('AML.')) continue; // ATLAS ids have no bundled matrix
    const technique = techniques.get(row.techniqueID);
    assert(technique, `${file}: ${row.techniqueID} missing, revoked or deprecated in ${snapshotName}`);
    if (!row.tactic) { unresolvedTactics += 1; continue; }
    assert(tacticsOf(technique).includes(row.tactic),
      `${file}: ${row.techniqueID} has no tactic '${row.tactic}' in ${snapshotName} (has ${tacticsOf(technique).join(', ')})`);
  }
  return unresolvedTactics;
}
for (const entry of manifest) {
  const layer = readJson(new URL(entry.file, layerRoot));
  assertRowsResolve(entry.file, layer.techniques, snapshots[0].techniques, snapshots[0].name);
}

// The vendored Lylat mission layers resolve against their own domain's bundled snapshot
// (ATLAS rows excepted). scripts/normalize-lylat-layers.mjs rewrites them when ATT&CK
// retires an id or renames a tactic.
const missionManifest = readJson(new URL('index.json', missionRoot));
const missionFiles = readdirSync(missionRoot).filter(file => file !== 'index.json').sort();
assert.deepEqual(missionManifest.map(entry => entry.file).sort(), missionFiles, 'lylat-mission-layers/index.json: file list drift');
const domainTechniques = Object.fromEntries(Object.entries(domainBundles).map(([domain, bundle]) => [domain, techniquesById(bundle)]));
let missionRows = 0;
for (const entry of missionManifest) {
  const layer = readJson(new URL(entry.file, missionRoot));
  assert.equal(layer.name, entry.name, `${entry.file}: name drift`);
  assert.equal(layer.domain, entry.domain, `${entry.file}: domain drift`);
  assert(domainTechniques[layer.domain], `${entry.file}: unknown domain ${layer.domain}`);
  assertRowsResolve(entry.file, layer.techniques, domainTechniques[layer.domain], `bundled ${layer.domain} ${bundledVersions[layer.domain]}`);
  missionRows += layer.techniques.length;
}

for (const file of files) {
  const layer = readJson(new URL(file, layerRoot));
  const entry = manifest.find(item => item.file === file);
  assert(entry, `${file}: missing manifest entry`);
  assert.equal(entry.description, layer.description, `${file}: description drift`);
  assert(entry.blurb?.length > 40 && entry.blurb.length < 300, `${file}: missing or oversized blurb`);
  assert.deepEqual(layer.versions, { attack: '19', navigator: '4.9', layer: '4.5' });
  assert.equal(layer.domain, 'enterprise-attack');
  assert.equal(layer.selectSubtechniquesWithParent, false);
  assert.match(layer.description, /not an official MITRE mapping/);
  assert.match(layer.description, /coverage guarantee/);
  assert.match(layer.description, /16\.1.*19\.2/);
  assert.equal(layer.gradient.minValue, 0);
  assert.equal(layer.gradient.maxValue, 100);
  assert.deepEqual(layer.legendItems.map(item => item.label), [
    '100: Core (curated membership)', '55: Supporting (curated membership)',
  ]);

  const metadata = new Map(layer.metadata.map(item => [item.name, item.value]));
  assert.equal(metadata.size, layer.metadata.length, `${file}: duplicate metadata`);
  assert.equal(metadata.get('baseline_sha256'), baselineHash);
  assert.equal(metadata.get('bundled_sha256_lf'), sha256(bundledText));
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
console.log(`PASS bundled ATT&CK ${bundledVersions['enterprise-attack']} (enterprise/ics/mobile) + F3 ${f3Version}; README data table matches`);
console.log(`PASS ${manifest.length} manifest entries resolve against ${snapshots[0].name}; ${missionManifest.length} Lylat mission layers (${missionRows} rows) resolve against their domains`);
console.log(`PASS checked ${snapshots.map(snapshot => snapshot.name).join(' + ')}`);
