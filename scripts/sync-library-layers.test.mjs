// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for scripts/sync-library-layers.mjs. The pure parts run on fixtures; a
// whole sync runs offline into a temporary root (applySync with a fixture pull),
// and --check runs against that root and against this repository.
//
//   node --test scripts/sync-library-layers.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  BUNDLE_FILES, DOC, DOCS_README, DOC_END, DOC_START, GROUP_ORDER, LAYER_DIR, LOCK, SITE,
  applySync, bundledGroup, check, extraPaths, indexBundle, plan, renderReport, resolveLayer, rowsKey, tableCell, targetName, validateLayer,
} from './sync-library-layers.mjs';

test('tableCell escapes backslashes before pipes', () => {
  assert.equal(tableCell('a | b'), 'a \\| b');
  assert.equal(tableCell('C:\\x | y\\|z'), 'C:\\\\x \\| y\\\\\\|z');
});

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'sync-library-layers.mjs');

// ─── Fixture ATT&CK bundle ────────────────────────────────────────────────────

const pattern = (stixId, attackId, tactics, extra = {}) => ({
  type: 'attack-pattern', id: stixId,
  external_references: [{ source_name: 'mitre-attack', external_id: attackId }],
  kill_chain_phases: tactics.map((t) => ({ kill_chain_name: 'mitre-attack', phase_name: t })),
  ...extra,
});
const ENTERPRISE = {
  objects: [
    { type: 'x-mitre-collection', id: 'x-mitre-collection--1', x_mitre_version: '19.2' },
    pattern('attack-pattern--1', 'T1190', ['initial-access']),
    pattern('attack-pattern--2', 'T1078', ['initial-access', 'persistence']),
    pattern('attack-pattern--3', 'T1070.001', ['stealth'], { revoked: true }),
    pattern('attack-pattern--4', 'T1685.005', ['defense-impairment']),
    { type: 'relationship', id: 'relationship--1', relationship_type: 'revoked-by', source_ref: 'attack-pattern--3', target_ref: 'attack-pattern--4' },
  ],
};
const ICS = { objects: [{ type: 'x-mitre-collection', id: 'x-mitre-collection--2', x_mitre_version: '19.2' }, pattern('attack-pattern--9', 'T0803', ['inhibit-response-function'])] };
const MOBILE = { objects: [{ type: 'x-mitre-collection', id: 'x-mitre-collection--3', x_mitre_version: '19.2' }] };
const F3 = { objects: [{ type: 'x-mitre-collection', id: 'x-mitre-collection--4', x_mitre_version: '1.2' }, { type: 'attack-pattern', id: 'attack-pattern--f', external_references: [{ source_name: 'mitre-f3', external_id: 'F1001' }], kill_chain_phases: [] }] };
const BUNDLES = { enterprise: indexBundle(ENTERPRISE), ics: indexBundle(ICS), mobile: indexBundle(MOBILE), f3: indexBundle(F3) };

const layer = (name, rows, domain = 'enterprise-attack') => ({
  name, description: `${name} description.`, domain, versions: { attack: '20', navigator: '4.9', layer: '4.5' },
  techniques: rows.map(([techniqueID, tactic, score]) => ({ techniqueID, ...(tactic ? { tactic } : {}), ...(score !== undefined ? { score } : {}) })),
});

// ─── Pure parts ───────────────────────────────────────────────────────────────

test('validateLayer accepts a Navigator layer and names what is missing', () => {
  assert.deepEqual(validateLayer(layer('A', [['T1190', 'initial-access', 1]])), []);
  assert.deepEqual(validateLayer(layer('A', [['T1190']])), [], 'a missing tactic is allowed');
  assert.deepEqual(validateLayer([]), ['not a JSON object']);
  const bad = { name: '', versions: {}, techniques: [{ tactic: 'x' }, { techniqueID: 'T1', tactic: 3 }, { techniqueID: 'T2', score: 'high' }] };
  assert.deepEqual(validateLayer(bad), [
    'no name', 'no domain', 'no versions.layer',
    'techniques[0]: no techniqueID', 'techniques[1]: tactic is not a string', 'techniques[2]: score is not a number',
  ]);
  assert.deepEqual(validateLayer({ ...layer('A', []) }), ['no techniques']);
});

test('targetName prefixes by group and keeps names to [a-z0-9-]', () => {
  assert.equal(targetName('Case studies', 'log4shell-cve-2021-44228.json'), 'study-log4shell-cve-2021-44228.json');
  assert.equal(targetName('Vendors', 'EDR_CrowdStrike_SentinelOne.json'), 'vendor-edr-crowdstrike-sentinelone.json');
  assert.equal(targetName('Kill-chain stages', 'stage1_governance_grc.json'), 'stage-stage1-governance-grc.json');
  for (const g of ['Threat actors', 'Computed', 'Analytics', 'AI', 'Fraud']) assert.match(targetName(g, 'x.json'), /^[a-z]+-x\.json$/);
});

test('bundledGroup maps the bundled files to their groups', () => {
  assert.equal(bundledGroup('group-apt29.json'), 'Threat groups');
  assert.equal(bundledGroup('htb-easy-techniques.json'), 'HTB frequency');
  assert.equal(bundledGroup('agentic-ai-swarm.json'), 'Agentic AI');
  assert.equal(bundledGroup('lylat-mission-coverage.json'), 'Lylat');
  assert.equal(bundledGroup('web-application-attacks.json'), 'Curated themes');
});

test('resolveLayer records unknown, retired and tactic-mismatched rows and counts unchecked ones', () => {
  const found = resolveLayer(layer('A', [
    ['T1190', 'initial-access'], ['T1190', 'execution'], ['T9999', 'impact'], ['T1070.001', 'stealth'],
    ['T1078'], ['AML.T0010', 'ml-attack-staging'],
  ]), BUNDLES);
  assert.deepEqual(found, {
    unknown: ['T9999'],
    retired: [{ id: 'T1070.001', successor: 'T1685.005' }],
    tacticMismatch: [{ id: 'T1190', tactic: 'execution', bundled: ['initial-access'] }],
    noTactic: 1,
    unchecked: 1,
  });
  // ICS rows resolve against the ICS bundle only; F3 against F3 then Enterprise; ATLAS is unchecked.
  assert.deepEqual(resolveLayer(layer('I', [['T0803', 'inhibit-response-function'], ['T1190', 'initial-access']], 'ics-attack'), BUNDLES), { unknown: ['T1190'] });
  assert.deepEqual(resolveLayer(layer('F', [['F1001'], ['T1190'], ['F1010']], 'f3-financial'), BUNDLES), { unknown: ['F1010'], noTactic: 3 });
  assert.deepEqual(resolveLayer(layer('L', [['AML.T0000']], 'atlas-atlas'), BUNDLES), { noTactic: 1, unchecked: 1 });
});

test('rowsKey ignores row order and duplicates but not domain or score', () => {
  const a = layer('A', [['T1190', 'initial-access', 1], ['T1078', 'persistence', 2]]);
  const b = layer('B', [['T1078', 'persistence', 2], ['T1190', 'initial-access', 1], ['T1190', 'initial-access', 1]]);
  assert.equal(rowsKey(a), rowsKey(b));
  assert.notEqual(rowsKey(a), rowsKey(layer('C', [['T1190', 'initial-access', 1], ['T1078', 'persistence', 3]])));
  assert.notEqual(rowsKey(a), rowsKey({ ...a, domain: 'ics-attack' }));
});

test('extraPaths lists the known folders and the loose files, and reports the rest', () => {
  const tree = {
    truncated: false,
    tree: [
      { type: 'blob', path: 'navigator/library-layers/index.json' },
      { type: 'blob', path: 'navigator/library-layers/x.json' },
      { type: 'blob', path: 'navigator/vendors/b.json' },
      { type: 'blob', path: 'navigator/case-studies/a-ics.json' },
      { type: 'blob', path: 'navigator/top.json' },
      { type: 'blob', path: 'navigator/index.md' },
      { type: 'blob', path: 'navigator/new-folder/z.json' },
      { type: 'tree', path: 'navigator/vendors' },
      { type: 'blob', path: 'docs/other.json' },
    ],
  };
  const { paths, unmapped } = extraPaths(tree);
  assert.deepEqual(paths.map((p) => p.rel), ['case-studies/a-ics.json', 'vendors/b.json', 'top.json']);
  assert.deepEqual(unmapped, ['new-folder/z.json']);
  assert.throws(() => extraPaths({ truncated: true, tree: [] }), /truncated/);
});

test('plan keeps the published copy, skips duplicates by name or rows, and groups actors', () => {
  const bundled = [{ entry: { file: 'web-application-attacks.json', name: 'TeamStarWolf - Web Application Attacks' }, layer: layer('TeamStarWolf - Web Application Attacks', [['T1190', 'initial-access', 100]]) }];
  const cand = (kind, rel, l, extra = {}) => ({ kind, rel, file: rel.split('/').pop(), source: `${SITE}${rel}`, text: JSON.stringify(l), ...extra });
  const study = layer('TeamStarWolf - Log4Shell Case Study', [['T1190', 'initial-access', 3]]);
  const { kept, duplicates, invalid } = plan(bundled, [
    cand('published', 'library-layers/web-application-attacks.json', layer('TeamStarWolf - Web Application Attacks', [['T1078', 'persistence', 1]]), { entry: { file: 'web-application-attacks.json' } }),
    cand('published', 'library-layers/log4shell.json', study, { entry: { file: 'log4shell.json', description: 'From the index.', blurb: 'Blurb.' } }),
    cand('published', 'library-layers/threat-actors-china.json', layer('TeamStarWolf - China-Attributed Threat Actors Case Study', [['T1078', 'initial-access', 2]]), { entry: {} }),
    cand('extra', 'case-studies/log4shell-copy.json', { ...study, name: 'Another name' }, { folder: 'case-studies' }),
    cand('extra', 'case-studies/threat-actors-iran-ics.json', layer('TeamStarWolf - Iran-Attributed Threat Actors (ICS)', [['T0803']], 'ics-attack'), { folder: 'case-studies' }),
    cand('extra', 'vendors/broken.json', { name: 'x' }, { folder: 'vendors' }),
    cand('extra', 'stages/s1.json', layer('Stage 1', [['T1078']]), { folder: 'stages' }),
  ], BUNDLES);
  assert.deepEqual(kept.map((k) => [k.entry.file, k.entry.group]), [
    ['study-log4shell.json', 'Case studies'],
    ['actor-threat-actors-china.json', 'Threat actors'],
    ['actor-threat-actors-iran-ics.json', 'Threat actors'],
    ['stage-s1.json', 'Kill-chain stages'],
  ]);
  assert.deepEqual(kept[0].entry, {
    file: 'study-log4shell.json', name: 'TeamStarWolf - Log4Shell Case Study', description: 'From the index.', blurb: 'Blurb.',
    group: 'Case studies', source: `${SITE}library-layers/log4shell.json`,
  });
  assert.deepEqual(duplicates.map((d) => [d.source.replace(SITE, ''), d.reason, d.keptAs, d.keptFrom === 'bundled' ? 'bundled' : 'library']), [
    ['library-layers/web-application-attacks.json', 'same name', 'web-application-attacks.json', 'bundled'],
    ['case-studies/log4shell-copy.json', 'same rows', 'study-log4shell.json', 'library'],
  ]);
  assert.equal(invalid.length, 1);
  assert.match(invalid[0].problems.join(';'), /no domain/);
});

// ─── A whole sync into a temporary root ───────────────────────────────────────

function fixtureRoot() {
  const root = mkdtempSync(join(tmpdir(), 'sync-library-layers-'));
  const data = join(root, 'src', 'assets', 'data');
  mkdirSync(join(root, LAYER_DIR), { recursive: true });
  mkdirSync(join(root, 'docs'), { recursive: true });
  const bundles = { enterprise: ENTERPRISE, ics: ICS, mobile: MOBILE, f3: F3 };
  for (const [key, file] of Object.entries(BUNDLE_FILES)) writeFileSync(join(root, file), JSON.stringify(bundles[key]));
  writeFileSync(join(data, 'library-layers', 'web-application-attacks.json'), JSON.stringify(layer('TeamStarWolf - Web Application Attacks', [['T1190', 'initial-access', 100]])));
  writeFileSync(join(data, 'library-layers', 'index.json'), JSON.stringify([{ file: 'web-application-attacks.json', name: 'TeamStarWolf - Web Application Attacks', description: 'curated', blurb: 'b' }], null, 2));
  // CRLF on purpose: the guide is checked out with CRLF on Windows.
  writeFileSync(join(root, DOC), `# Guide\r\n\r\nThis build ships **1 layers**.\r\n\r\n${DOC_START}\r\n${DOC_END}\r\n\r\n## After\r\n`);
  writeFileSync(join(root, DOCS_README), 'The 1 bundled ATT&CK overlays.\n');
  return root;
}

const PULL = {
  indexUrl: `${SITE}library-layers/index.json`,
  indexSha256: 'a'.repeat(64),
  indexVersion: null,
  unmapped: [],
  candidates: [
    { kind: 'published', rel: 'library-layers/log4shell.json', file: 'log4shell.json', source: `${SITE}library-layers/log4shell.json`, entry: { file: 'log4shell.json', description: 'Study.', blurb: 'Short | blurb.' }, text: `${JSON.stringify(layer('TeamStarWolf - Log4Shell Case Study', [['T1190', 'initial-access', 3], ['T9999', 'impact', 1]]), null, 2)}\n` },
    { kind: 'extra', rel: 'vendors/edr.json', file: 'edr.json', folder: 'vendors', source: `${SITE}vendors/edr.json`, text: `${JSON.stringify(layer('EDR: Example', [['T1078']]), null, 2)}\n` },
  ],
};

test('applySync writes files, index, lock and docs that --check accepts; tampering fails it', () => {
  const root = fixtureRoot();
  try {
    const { index, lock } = applySync(root, PULL, '2026-11-13');
    assert.deepEqual(index.map((e) => [e.file, e.group, e.source ?? null]), [
      ['web-application-attacks.json', 'Curated themes', null],
      ['study-log4shell.json', 'Case studies', `${SITE}library-layers/log4shell.json`],
      ['vendor-edr.json', 'Vendors', `${SITE}vendors/edr.json`],
    ]);
    assert.ok(index.every((e) => GROUP_ORDER.includes(e.group)));
    assert.equal(lock.synced, '2026-11-13');
    assert.deepEqual(lock.files[0].unknown, ['T9999']);
    assert.deepEqual(check(root), []);

    // The doc kept its CRLF endings and carries the generated tables and counts.
    const guide = readFileSync(join(root, DOC), 'utf8');
    assert.match(guide, /\r\n/);
    assert.match(guide, /This build ships \*\*3 layers\*\*/);
    assert.match(guide, /### Case studies \(synced\)/);
    assert.match(guide, /Short \\\| blurb\. 1 id not in the bundled data/);
    assert.match(readFileSync(join(root, DOCS_README), 'utf8'), /The 3 bundled ATT&CK overlays/);

    // A re-run with nothing new keeps the earlier date.
    assert.equal(applySync(root, PULL, '2026-12-01').lock.synced, '2026-11-13');

    // A CRLF checkout of a synced file still verifies.
    const study = join(root, LAYER_DIR, 'study-log4shell.json');
    const original = readFileSync(study, 'utf8');
    writeFileSync(study, original.replace(/\n/g, '\r\n'));
    assert.deepEqual(check(root), []);

    // A hand edit, an unlisted file and a stale doc each fail.
    writeFileSync(study, original.replace('"score": 3', '"score": 4'));
    assert.match(check(root).join('\n'), /study-log4shell\.json: sha256 does not match/);
    writeFileSync(study, original);
    writeFileSync(join(root, LAYER_DIR, 'stray.json'), '{}');
    assert.match(check(root).join('\n'), /stray\.json is not listed/);
    rmSync(join(root, LAYER_DIR, 'stray.json'));
    writeFileSync(join(root, DOCS_README), 'The 2 bundled ATT&CK overlays.\n');
    assert.match(check(root).join('\n'), /docs\/README\.md is out of date/);
    writeFileSync(join(root, DOCS_README), 'The 3 bundled ATT&CK overlays.\n');
    assert.deepEqual(check(root), []);

    // A hand-edited lock that hides an unknown id fails.
    const lockPath = join(root, LAYER_DIR, LOCK);
    const edited = JSON.parse(readFileSync(lockPath, 'utf8'));
    delete edited.files[0].unknown;
    writeFileSync(lockPath, JSON.stringify(edited));
    assert.match(check(root).join('\n'), /study-log4shell\.json: the library-sync\.json record/);

    // The report quotes the counts, duplicates and unknown ids.
    const report = renderReport(index, lock);
    assert.match(report, /\| Case studies \| 1 \| synced \|/);
    assert.match(report, /study-log4shell\.json \| T9999/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a library layer the library no longer publishes is removed on the next sync', () => {
  const root = fixtureRoot();
  try {
    applySync(root, PULL, '2026-11-13');
    const { index, lock } = applySync(root, { ...PULL, candidates: PULL.candidates.slice(0, 1) }, '2026-11-14');
    assert.deepEqual(index.map((e) => e.file), ['web-application-attacks.json', 'study-log4shell.json']);
    assert.equal(lock.synced, '2026-11-14');
    assert.deepEqual(check(root), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('--check passes on this repository', () => {
  const run = spawnSync(process.execPath, [SCRIPT, '--check'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /every file listed once; docs current/);
});

test('an unknown argument is refused', () => {
  const run = spawnSync(process.execPath, [SCRIPT, '--chek'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /unknown argument --chek/);
});
