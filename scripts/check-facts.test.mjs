// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Plant tests for scripts/check-facts.mjs: a wrong count planted in a doc must
// fail the check. Run with: node --test scripts/check-facts.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, copyFileSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { checkText, parseNumber, DEFAULT_DOCS, checkFreshness } from './check-facts.mjs';
import { collectFacts, headline, renderFacts, parseFactsMarkdown } from './gen-facts.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'check-facts.mjs');

const FACTS = {
  heatmapModes: 33, routedWorkspaces: 10, routeFileWorkspaces: 8, routedTabs: 47,
  libraryLayers: 37, unitSpecs: 165, angularMajor: 22, typescriptMajor: 6,
  bundleVersions: { 'Enterprise ATT&CK': '19.2', 'ICS ATT&CK': '18.1' },
};

test('number words and digits parse', () => {
  assert.equal(parseNumber('nine'), 9);
  assert.equal(parseNumber('thirty-three'), 33);
  assert.equal(parseNumber('1,024'), 1024);
  assert.equal(parseNumber('47'), 47);
});

test('correct statements pass', () => {
  const text = [
    'The picker has 33 heatmap modes across ten workspaces.',
    'Routing: 10 lazily loaded workspaces; the other eight workspaces lazy-load a route file.',
    'There are 47 routed tabs, 37 library layers and 165 unit spec files.',
    'The library mode lists 37 overlays. Built with Angular 22.2 and TypeScript 6.0.',
    '| Domain | Live source | Bundled snapshot |',
    '| :-- | :-- | :-- |',
    '| Enterprise ATT&CK | `mitre-attack/attack-stix-data` | v19.2 |',
    '| ICS ATT&CK | `mitre-attack/attack-stix-data` | v18.1 |',
  ].join('\n');
  assert.deepEqual(checkText(text, FACTS), []);
});

const PLANTS = [
  ['34 heatmap modes', 'heatmapModes'],
  ['25+ heatmap modes are fine but 40+ heatmap modes are not', 'heatmapModes'],
  ['nine workspaces', 'routedWorkspaces'],
  ['9 routed workspaces', 'routedWorkspaces'],
  ['the other seven workspaces lazy-load a route file', 'routeFileWorkspaces'],
  ['46 workspace tabs', 'routedTabs'],
  ['36 library layers', 'libraryLayers'],
  ['now lists 36 overlays from index.json', 'libraryLayers'],
  ['220 unit specs', 'unitSpecs'],
  ['164 spec files', 'unitSpecs'],
  ['a single-page Angular 21.2.x application', 'angularMajor'],
  ['TypeScript 5.9.x', 'typescriptMajor'],
];

for (const [planted, fact] of PLANTS) {
  test(`planted "${planted}" fails on ${fact}`, () => {
    const problems = checkText(`Intro line.\n${planted}\n`, FACTS, 'X.md');
    assert.equal(problems.length, 1, JSON.stringify(problems));
    assert.equal(problems[0].fact, fact);
    assert.equal(problems[0].line, 2);
  });
}

test('planted bundle version in a Bundled snapshot table fails', () => {
  const text = '| Domain | Live | Bundled snapshot |\n| :-- | :-- | :-- |\n| ICS ATT&CK | x | v17.0 |\n';
  const problems = checkText(text, FACTS);
  assert.equal(problems.length, 1);
  assert.equal(problems[0].fact, 'bundleVersions.ICS ATT&CK');
});

test('versions in other tables are not read as bundle versions', () => {
  const text = '| Dataset | Pinned to |\n| :-- | :-- |\n| ICS ATT&CK | v16.1 |\n';
  assert.deepEqual(checkText(text, FACTS), []);
});

test('fenced code, facts:ignore lines and ignore blocks are skipped', () => {
  const text = [
    '```text', '25 heatmap modes', '```',
    'Upgraded from Angular 21 in PR #110. <!-- facts:ignore -->',
    '<!-- facts:ignore-start -->', '9 workspaces in v0.8.0', '<!-- facts:ignore-end -->',
  ].join('\n');
  assert.deepEqual(checkText(text, FACTS), []);
});

test('docs/FACTS.md in the repo matches the code and its JSON block', () => {
  assert.deepEqual(checkFreshness(ROOT), []);
  const md = readFileSync(join(ROOT, 'docs/FACTS.md'), 'utf8');
  assert.deepEqual(parseFactsMarkdown(md), headline(collectFacts(ROOT)));
});

test('a FACTS.md that no longer matches the code makes HANDOFF.md disagree', () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-facts-'));
  try {
    mkdirSync(join(dir, 'docs'));
    const fresh = renderFacts(collectFacts(ROOT));
    const stale = fresh.replace('"heatmapModes": 33', '"heatmapModes": 32');
    assert.notEqual(stale, fresh, 'fixture assumes 33 heatmap modes; update the test if the code changed');
    writeFileSync(join(dir, 'docs/FACTS.md'), stale);
    copyFileSync(join(ROOT, 'HANDOFF.md'), join(dir, 'HANDOFF.md'));
    const r = spawnSync(process.execPath, [SCRIPT, '--root', dir, '--no-freshness', 'HANDOFF.md'], { encoding: 'utf8' });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /HANDOFF\.md:\d+: "33 heatmap modes" states 33 heatmap modes; docs\/FACTS\.md says 32/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI: the repository docs pass, and a planted wrong count in a copy exits 1', () => {
  const ok = spawnSync(process.execPath, [SCRIPT], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);

  const dir = mkdtempSync(join(tmpdir(), 'check-facts-'));
  try {
    mkdirSync(join(dir, 'docs'));
    copyFileSync(join(ROOT, 'docs/FACTS.md'), join(dir, 'docs/FACTS.md'));
    for (const f of DEFAULT_DOCS) copyFileSync(join(ROOT, f), join(dir, f));
    const clean = spawnSync(process.execPath, [SCRIPT, '--root', dir, '--no-freshness'], { encoding: 'utf8' });
    assert.equal(clean.status, 0, clean.stderr);

    const facts = parseFactsMarkdown(readFileSync(join(dir, 'docs/FACTS.md'), 'utf8'));
    const readme = join(dir, 'README.md');
    writeFileSync(readme, readFileSync(readme, 'utf8') + `\nThe picker offers ${facts.heatmapModes + 1} heatmap modes.\n`);
    const bad = spawnSync(process.execPath, [SCRIPT, '--root', dir, '--no-freshness'], { encoding: 'utf8' });
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, new RegExp(`README\\.md:\\d+: "${facts.heatmapModes + 1} heatmap modes"`));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
