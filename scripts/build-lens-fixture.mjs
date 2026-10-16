// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Derives the small, FIXED STIX bundle that the characterization specs
// (src/app/testing/lens-snapshots.spec.ts and friends) parse with the real
// DataService. The bundle is a deterministic slice of the bundled Enterprise
// ATT&CK snapshot, so re-running this script against the same input always
// produces a byte-identical file; re-running it after a data refresh produces a
// reviewable diff (and, through the snapshots, a failing spec until the
// snapshots are deliberately refreshed).
//
// Selection rules (all ordering is by ATT&CK id, never by file order):
//   - every tactic in the x-mitre-matrix tactic_refs, plus the collection and
//     matrix objects themselves;
//   - per tactic, PARENTS_PER_TACTIC live parent techniques at evenly spaced
//     positions in that tactic's attackId-sorted list (a technique already picked
//     for an earlier tactic is skipped in favour of the next unpicked one);
//   - for each picked parent that has sub-techniques, its first sub-technique;
//   - per picked technique, at most MAX_GROUPS intrusion-sets, MAX_SOFTWARE
//     tools/malware and MAX_CAMPAIGNS campaigns that `uses` it (lowest ids
//     first), with those objects; group/campaign -> software `uses` and
//     campaign -> group `attributed-to` edges among the kept objects;
//   - every `mitigates` edge onto a picked technique, with its mitigation;
//   - every `detects` edge onto a picked technique, with its detection strategy,
//     the strategy's analytics and the analytics' data components;
//   - every revoked technique whose `revoked-by` target was picked (so the
//     supersededBy index is exercised), with that edge.
// Objects are trimmed to the fields DataService.parseBundle reads, and long
// descriptions are cut to DESC_MAX (relationships: REL_DESC_MAX) characters, to
// keep the fixture small.
//
// Usage:
//   node scripts/build-lens-fixture.mjs [input] [output]
//     input  defaults to src/assets/data/enterprise-attack.json
//     output defaults to src/testing/fixtures/enterprise-lens.stix.json
// Requires Node 20+. Reads and writes local files only; no network access.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const INPUT = process.argv[2] ?? 'src/assets/data/enterprise-attack.json';
const OUTPUT = process.argv[3] ?? 'src/testing/fixtures/enterprise-lens.stix.json';

const PARENTS_PER_TACTIC = 3;
const MAX_GROUPS = 5;
const MAX_SOFTWARE = 4;
const MAX_CAMPAIGNS = 2;
const DESC_MAX = 160;
const REL_DESC_MAX = 80;

const bundle = JSON.parse(readFileSync(INPUT, 'utf8'));
const objects = bundle.objects ?? [];
const byId = new Map(objects.map((o) => [o.id, o]));

const attackIdOf = (o) =>
  (o.external_references ?? []).find((r) => r.source_name === 'mitre-attack')?.external_id ?? null;
const live = (o) => !o.revoked && !o.x_mitre_deprecated;
const byAttackId = (a, b) => (attackIdOf(a) ?? '').localeCompare(attackIdOf(b) ?? '');

const collection = objects.find((o) => o.type === 'x-mitre-collection');
const matrix = objects.find((o) => o.type === 'x-mitre-matrix' && live(o));
if (!matrix) throw new Error(`no live x-mitre-matrix in ${INPUT}`);
const tactics = matrix.tactic_refs.map((ref) => byId.get(ref)).filter(Boolean);

const techniques = objects.filter((o) => o.type === 'attack-pattern' && live(o) && attackIdOf(o));
const parents = techniques.filter((t) => !t.x_mitre_is_subtechnique);

// ── techniques ───────────────────────────────────────────────────────────────
const picked = new Map(); // stix id -> object
for (const tactic of tactics) {
  const column = parents
    .filter((t) => (t.kill_chain_phases ?? []).some((p) => p.phase_name === tactic.x_mitre_shortname))
    .sort(byAttackId);
  let taken = 0;
  for (let slot = 0; slot < PARENTS_PER_TACTIC && column.length > 0; slot++) {
    let idx = Math.floor((slot * column.length) / PARENTS_PER_TACTIC);
    while (idx < column.length && picked.has(column[idx].id)) idx++;
    if (idx >= column.length) break;
    picked.set(column[idx].id, column[idx]);
    taken++;
  }
  if (taken === 0) console.warn(`tactic ${tactic.x_mitre_shortname}: no technique picked`);
}
for (const parent of [...picked.values()]) {
  const parentId = attackIdOf(parent);
  const firstSub = techniques
    .filter((t) => t.x_mitre_is_subtechnique && attackIdOf(t).startsWith(parentId + '.'))
    .sort(byAttackId)[0];
  if (firstSub) picked.set(firstSub.id, firstSub);
}

// ── relationships onto picked techniques ─────────────────────────────────────
const rels = objects.filter((o) => o.type === 'relationship' && live(o));
const keep = new Map(); // stix id -> object (everything that goes in the fixture)
const add = (o) => { if (o) keep.set(o.id, o); };

if (collection) add(collection);
add(matrix);
tactics.forEach(add);
picked.forEach(add);

const prefixOf = (ref) => ref.split('--')[0];
const usesInto = new Map(); // technique id -> rels
for (const r of rels) {
  if (r.relationship_type === 'uses' && picked.has(r.target_ref)) {
    if (!usesInto.has(r.target_ref)) usesInto.set(r.target_ref, []);
    usesInto.get(r.target_ref).push(r);
  }
}
const capFor = { 'intrusion-set': MAX_GROUPS, tool: MAX_SOFTWARE, malware: MAX_SOFTWARE, campaign: MAX_CAMPAIGNS };
const softwareCap = (kind) => (kind === 'tool' || kind === 'malware' ? 'software' : kind);
for (const techId of [...picked.keys()].sort()) {
  const candidates = (usesInto.get(techId) ?? [])
    .map((r) => ({ r, src: byId.get(r.source_ref) }))
    .filter(({ src }) => src && live(src) && attackIdOf(src) && capFor[src.type] !== undefined)
    .sort((a, b) => attackIdOf(a.src).localeCompare(attackIdOf(b.src)) || a.r.id.localeCompare(b.r.id));
  const used = { 'intrusion-set': 0, software: 0, campaign: 0 };
  for (const { r, src } of candidates) {
    const bucket = softwareCap(src.type);
    if (used[bucket] >= capFor[src.type]) continue;
    used[bucket]++;
    add(src);
    add(r);
  }
}
// toolkit + attribution edges among kept objects
for (const r of rels) {
  if (!keep.has(r.source_ref) || !keep.has(r.target_ref)) continue;
  const s = prefixOf(r.source_ref);
  const t = prefixOf(r.target_ref);
  if (r.relationship_type === 'uses' && (s === 'intrusion-set' || s === 'campaign') && (t === 'tool' || t === 'malware')) add(r);
  if (r.relationship_type === 'attributed-to' && s === 'campaign' && t === 'intrusion-set') add(r);
}
// mitigations
for (const r of rels) {
  if (r.relationship_type !== 'mitigates' || !picked.has(r.target_ref)) continue;
  const coa = byId.get(r.source_ref);
  if (!coa || !live(coa)) continue;
  add(coa);
  add(r);
}
// detection model (v18+)
for (const r of rels) {
  if (r.relationship_type !== 'detects' || !picked.has(r.target_ref)) continue;
  const strategy = byId.get(r.source_ref);
  if (!strategy || !live(strategy)) continue;
  add(strategy);
  add(r);
  for (const analyticId of strategy.x_mitre_analytic_refs ?? []) {
    const analytic = byId.get(analyticId);
    if (!analytic) continue;
    add(analytic);
    for (const lsr of analytic.x_mitre_log_source_references ?? []) add(byId.get(lsr.x_mitre_data_component_ref));
  }
}
// revoked -> picked replacements
for (const r of objects) {
  if (r.type !== 'relationship' || r.relationship_type !== 'revoked-by' || !picked.has(r.target_ref)) continue;
  const retired = byId.get(r.source_ref);
  if (!retired || retired.type !== 'attack-pattern') continue;
  add(retired);
  add(r);
}

// ── trimming ─────────────────────────────────────────────────────────────────
const DROP = new Set([
  'spec_version', 'created', 'created_by_ref', 'object_marking_refs', 'x_mitre_modified_by_ref',
  'x_mitre_attack_spec_version', 'x_mitre_domains', 'x_mitre_contributors', 'x_mitre_version',
  'x_mitre_deprecated', 'revoked', 'modified',
]);
const KEEP_EXT = new Set(['mitre-attack', 'capec']);
const cut = (s, max = DESC_MAX) => {
  if (typeof s !== 'string') return s;
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length > max ? flat.slice(0, max - 1).trimEnd() + '…' : flat;
};
// Detection-model objects carry long per-platform lists that parseBundle never
// reads; keep only the references it follows.
const SLIM = {
  'x-mitre-analytic': (o) => ({
    type: o.type, id: o.id, name: o.name,
    x_mitre_log_source_references: (o.x_mitre_log_source_references ?? [])
      .map((l) => ({ x_mitre_data_component_ref: l.x_mitre_data_component_ref })),
  }),
  'x-mitre-data-component': (o) => ({
    type: o.type, id: o.id, name: o.name,
    ...(o.x_mitre_data_source_ref ? { x_mitre_data_source_ref: o.x_mitre_data_source_ref } : {}),
    x_mitre_log_sources: (o.x_mitre_log_sources ?? []).slice(0, 1).map((l) => ({ name: l.name })),
  }),
  'x-mitre-detection-strategy': (o) => ({
    type: o.type, id: o.id, name: o.name, x_mitre_analytic_refs: o.x_mitre_analytic_refs ?? [],
  }),
  relationship: (o) => ({
    type: o.type, id: o.id, relationship_type: o.relationship_type,
    source_ref: o.source_ref, target_ref: o.target_ref,
    ...(o.description ? { description: cut(o.description, REL_DESC_MAX) } : {}),
  }),
};
function trim(o) {
  if (SLIM[o.type]) return SLIM[o.type](o);
  const out = {};
  for (const [k, v] of Object.entries(o)) {
    if (DROP.has(k) && !(o.type === 'x-mitre-collection' && (k === 'x_mitre_version' || k === 'modified'))) continue;
    if (k === 'external_references') {
      const refs = v
        .filter((r) => KEEP_EXT.has(r.source_name))
        .map((r) => ({ source_name: r.source_name, external_id: r.external_id, ...(r.url ? { url: r.url } : {}) }));
      if (refs.length) out[k] = refs;
      continue;
    }
    if (o.type === 'x-mitre-collection' && k === 'x_mitre_contents') continue;
    if (k === 'description' || k === 'x_mitre_detection') { out[k] = cut(v); continue; }
    out[k] = v;
  }
  if (o.revoked) out.revoked = true;
  return out;
}

const TYPE_ORDER = [
  'x-mitre-collection', 'x-mitre-matrix', 'x-mitre-tactic', 'attack-pattern', 'course-of-action',
  'intrusion-set', 'campaign', 'malware', 'tool', 'x-mitre-detection-strategy', 'x-mitre-analytic',
  'x-mitre-data-component', 'relationship',
];
const sorted = [...keep.values()]
  .map(trim)
  .sort((a, b) => TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type) || a.id.localeCompare(b.id));

const lines = sorted.map((o) => '    ' + JSON.stringify(o));
const text =
  '{\n' +
  '  "type": "bundle",\n' +
  '  "id": "bundle--lens-fixture",\n' +
  `  "x_lens_fixture": ${JSON.stringify({
    source: INPUT.replace(/\\/g, '/'),
    generator: 'scripts/build-lens-fixture.mjs',
    attackVersion: collection?.x_mitre_version ?? '',
    techniques: [...picked.values()].map(attackIdOf).sort(),
  })},\n` +
  '  "objects": [\n' + lines.join(',\n') + '\n  ]\n}\n';

mkdirSync(dirname(OUTPUT), { recursive: true });
writeFileSync(OUTPUT, text);

const count = (type) => sorted.filter((o) => o.type === type).length;
console.log(
  `wrote ${OUTPUT}: ${sorted.length} objects, ${Buffer.byteLength(text)} bytes; ` +
  `${picked.size} techniques (${[...picked.values()].filter((t) => !t.x_mitre_is_subtechnique).length} parents), ` +
  `${count('intrusion-set')} groups, ${count('malware') + count('tool')} software, ${count('campaign')} campaigns, ` +
  `${count('course-of-action')} mitigations, ${count('relationship')} relationships`,
);
