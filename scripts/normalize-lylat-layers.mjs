// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Resolves the vendored Lylat mission layers against the bundled ATT&CK snapshots.
//
// The per-mission layers are generated upstream from mission front-matter, whose
// technique ids and tactic slugs were written against earlier ATT&CK releases. This
// script keeps the vendored copies honest against src/assets/data/*-attack.json:
//
//   1. per-mission layers: every technique id is followed through the STIX
//      `revoked-by` chain to its live successor, and every tactic slug is checked
//      against the technique's kill_chain_phases (a pre-v19 `defense-evasion` row
//      becomes `stealth` and/or `defense-impairment`, whichever the technique has);
//   2. per-domain coverage layers (lylat-coverage-*.json): the `techniques` array is
//      rebuilt from the normalized per-mission layers with the upstream generator's
//      algorithm (score = number of missions mapping the technique);
//   3. the curated picker layer (library-layers/lylat-mission-coverage.json): rebuilt
//      from the enterprise coverage layer (score normalized to the most-mapped technique).
//
// ATLAS rows (AML.T* ids) have no bundled matrix and are copied through unchanged.
// Names, descriptions, metadata and layout of every file are preserved.
//
// Run offline with node scripts/normalize-lylat-layers.mjs (rewrites the files) or
// node scripts/normalize-lylat-layers.mjs --check (exit 1 if any file would change).

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const dataRoot = new URL('src/assets/data/', root);
const missionRoot = new URL('lylat-mission-layers/', dataRoot);
const pickerUrl = new URL('library-layers/lylat-mission-coverage.json', dataRoot);
const manifestUrl = new URL('library-layers/index.json', dataRoot);
const checkOnly = process.argv.includes('--check');
const unknownArgs = process.argv.slice(2).filter(arg => arg !== '--check');
if (unknownArgs.length) throw new Error(`Unknown argument(s): ${unknownArgs.join(' ')}`);

const RENAMED_TACTICS = { 'defense-evasion': ['stealth', 'defense-impairment'] };
const isAtlasId = id => id.startsWith('AML.');
const readJson = url => JSON.parse(readFileSync(url, 'utf8'));
const serialize = value => JSON.stringify(value, null, 2) + '\n';

function attackId(object) {
  return object.external_references?.find(ref => ref.source_name === 'mitre-attack')?.external_id;
}

function loadDomain(file) {
  const bundle = readJson(new URL(file, dataRoot));
  const byStix = new Map();
  const byAttackId = new Map();
  const revokedBy = new Map();
  const tactics = new Set();
  for (const object of bundle.objects) {
    if (object.type === 'attack-pattern') {
      const id = attackId(object);
      if (!id) continue;
      const technique = {
        id,
        name: object.name,
        stixId: object.id,
        retired: Boolean(object.revoked || object.x_mitre_deprecated),
        phases: (object.kill_chain_phases ?? []).map(phase => phase.phase_name),
      };
      byStix.set(object.id, technique);
      byAttackId.set(id, technique);
    } else if (object.type === 'relationship' && object.relationship_type === 'revoked-by') {
      revokedBy.set(object.source_ref, object.target_ref);
    } else if (object.type === 'x-mitre-tactic') {
      tactics.add(object.x_mitre_shortname);
    }
  }
  const version = bundle.objects.find(object => object.type === 'x-mitre-collection')?.x_mitre_version;
  return { file, version, byStix, byAttackId, revokedBy, tactics };
}

const domains = {
  'enterprise-attack': loadDomain('enterprise-attack.json'),
  'ics-attack': loadDomain('ics-attack.json'),
  'mobile-attack': loadDomain('mobile-attack.json'),
};

// Follow revoked-by until a live technique is reached.
function resolveTechnique(domain, id, context) {
  let technique = domain.byAttackId.get(id);
  if (!technique) throw new Error(`${context}: ${id} is not in ${domain.file}`);
  const seen = new Set();
  while (technique.retired) {
    seen.add(technique.id);
    const successor = domain.byStix.get(domain.revokedBy.get(technique.stixId));
    if (!successor || seen.has(successor.id)) {
      throw new Error(`${context}: ${id} is retired in ${domain.file} (${domain.version}) with no live successor; decide a replacement by hand`);
    }
    technique = successor;
  }
  return technique;
}

// A row's tactic must be one of the technique's kill-chain phases. A tactic that
// ATT&CK renamed maps to the phases the technique actually has among the new names.
function resolveTactics(domain, technique, tactic, context) {
  if (!tactic) return [undefined];
  if (technique.phases.includes(tactic)) return [tactic];
  const renamed = (RENAMED_TACTICS[tactic] ?? []).filter(phase => technique.phases.includes(phase));
  if (renamed.length) return renamed;
  if (technique.phases.length === 1) return technique.phases;
  throw new Error(`${context}: ${technique.id} has no tactic '${tactic}' in ${domain.file} (${domain.version}); its phases are ${technique.phases.join(', ')} - pick one by hand`);
}

function metadataValue(layer, name) {
  return layer.metadata?.find(item => item.name === name)?.value;
}

const changed = [];
function emit(url, layer, before) {
  const after = serialize(layer);
  const file = decodeURIComponent(url.pathname.split('/').slice(-2).join('/'));
  // Git checkout settings vary by platform; compare and write with LF endings.
  if (after === before.replace(/\r\n/g, '\n')) return;
  changed.push(file);
  if (!checkOnly) writeFileSync(url, after, 'utf8');
}

// --- 1. per-mission layers --------------------------------------------------------
const missionFiles = readdirSync(missionRoot).filter(file => /^lylat-mission-.*\.json$/.test(file)).sort();
const missions = []; // { id, group, techniques: [{ id, name, tactic }] }
for (const file of missionFiles) {
  const url = new URL(file, missionRoot);
  const before = readFileSync(url, 'utf8');
  const layer = JSON.parse(before);
  const mission = metadataValue(layer, 'mission');
  if (!mission) throw new Error(`${file}: missing 'mission' metadata`);
  const domain = domains[layer.domain];
  if (!domain) throw new Error(`${file}: unknown domain ${layer.domain}`);
  const atlas = layer.techniques.some(row => isAtlasId(row.techniqueID));
  const prefix = `${mission} planned coverage: `;
  const rows = [];
  const seen = new Set();
  for (const row of layer.techniques) {
    const context = `${file} ${row.techniqueID}/${row.tactic ?? ''}`;
    const originalName = row.comment.startsWith(prefix) ? row.comment.slice(prefix.length) : row.comment;
    let candidates;
    if (isAtlasId(row.techniqueID)) {
      candidates = [{ id: row.techniqueID, name: originalName, tactic: row.tactic }];
    } else {
      const technique = resolveTechnique(domain, row.techniqueID, context);
      const name = technique.id === row.techniqueID ? originalName : technique.name;
      candidates = resolveTactics(domain, technique, row.tactic, context).map(tactic => ({ id: technique.id, name, tactic }));
    }
    for (const candidate of candidates) {
      const key = `${candidate.id}/${candidate.tactic ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({
        techniqueID: candidate.id,
        ...(candidate.tactic ? { tactic: candidate.tactic } : {}),
        color: row.color,
        enabled: row.enabled,
        comment: `${prefix}${candidate.name}`,
        showSubtechniques: candidate.id.includes('.'),
      });
    }
  }
  layer.techniques = rows;
  emit(url, layer, before);
  missions.push({
    id: mission,
    group: atlas ? 'atlas' : layer.domain.replace(/-attack$/, ''),
    techniques: rows.map(row => ({ id: row.techniqueID, name: row.comment.slice(prefix.length), tactic: row.tactic })),
  });
}

// --- 2. per-domain coverage layers -------------------------------------------------
const coverageByGroup = new Map();
for (const group of ['enterprise', 'ics', 'mobile', 'atlas']) {
  const groupMissions = missions.filter(mission => mission.group === group);
  if (!groupMissions.length) continue;
  const cover = new Map(); // id -> { name, tactics: [], missions: Set }
  for (const mission of groupMissions) {
    for (const technique of mission.techniques) {
      if (!cover.has(technique.id)) cover.set(technique.id, { name: technique.name, tactics: [], missions: new Set() });
      const entry = cover.get(technique.id);
      entry.missions.add(mission.id);
      if (technique.tactic && !entry.tactics.includes(technique.tactic)) entry.tactics.push(technique.tactic);
    }
  }
  const max = Math.max(...[...cover.values()].map(entry => entry.missions.size));
  const rows = [];
  for (const id of [...cover.keys()].sort()) {
    const entry = cover.get(id);
    const missionList = [...entry.missions].sort();
    for (const tactic of entry.tactics.length ? entry.tactics : [undefined]) {
      rows.push({
        techniqueID: id,
        ...(tactic ? { tactic } : {}),
        score: missionList.length,
        enabled: true,
        comment: `${entry.name} - mapped by ${missionList.length} mission(s): ${missionList.join(', ')}`,
        showSubtechniques: id.includes('.'),
      });
    }
  }
  const url = new URL(`lylat-coverage-${group}.json`, missionRoot);
  const before = readFileSync(url, 'utf8');
  const layer = JSON.parse(before);
  layer.techniques = rows;
  layer.gradient.maxValue = max;
  layer.legendItems = layer.legendItems.map(item =>
    /^\d+ missions \(planned\)$/.test(item.label) ? { ...item, label: `${max} missions (planned)` } : item);
  emit(url, layer, before);
  coverageByGroup.set(group, { rows, max, missionCount: groupMissions.length });
}

// --- 3. curated picker layer (enterprise coverage normalized to 0-100) ------------
const enterprise = coverageByGroup.get('enterprise');
const pickerBefore = readFileSync(pickerUrl, 'utf8');
const picker = JSON.parse(pickerBefore);
picker.techniques = enterprise.rows.map(row => {
  const missionList = row.comment.slice(row.comment.indexOf(' - mapped by ') + ' - mapped by '.length);
  return {
    techniqueID: row.techniqueID,
    ...(row.tactic ? { tactic: row.tactic } : {}),
    score: Math.round(row.score / enterprise.max * 100),
    comment: `Mapped by ${row.score} of ${enterprise.missionCount} Lylat enterprise missions (mapped by ${missionList}). `
      + 'Planned/training coverage (missions are execution_verified:false) — NOT a validated detection. Not an official MITRE mapping.',
  };
});
picker.description = picker.description
  .replace(/across the \d+ enterprise Lylat Labs training missions/, `across the ${enterprise.missionCount} enterprise Lylat Labs training missions`)
  .replace(/most-mapped technique \(\d+\)/, `most-mapped technique (${enterprise.max})`);
emit(pickerUrl, picker, pickerBefore);

const manifestBefore = readFileSync(manifestUrl, 'utf8');
const manifest = JSON.parse(manifestBefore);
const pickerEntry = manifest.find(entry => entry.file === 'lylat-mission-coverage.json');
if (!pickerEntry) throw new Error('library-layers/index.json: lylat-mission-coverage.json is not listed');
pickerEntry.description = picker.description;
emit(manifestUrl, manifest, manifestBefore);

const summary = [...coverageByGroup].map(([group, { rows, missionCount }]) => `${group} ${missionCount} missions / ${rows.length} rows`).join('; ');
if (changed.length) {
  console.log(`${checkOnly ? 'STALE' : 'REWROTE'} ${changed.length} file(s): ${changed.join(', ')}`);
  console.log(summary);
  if (checkOnly) process.exit(1);
} else {
  console.log(`PASS all Lylat layers already normalized against ${Object.values(domains).map(domain => `${domain.file} ${domain.version}`).join(', ')}`);
  console.log(summary);
}
