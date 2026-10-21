// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for scripts/check-seams.mjs (Phase 2 design P2-08, §4.2): the
// repository passes with its generated allow-list; a planted violation fails;
// an allow-listed file passes; a stale entry (a listed file that no longer
// matches) fails, so the list shrinks as files move to PostureService.
// Run with: node --test scripts/check-seams.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { DEFAULT_ALLOWLIST, checkSeams, generateAllowlist, readAllowlist, scanRule } from './check-seams.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'check-seams.mjs');

/** Both posture-rollup regexes: a mitigation map and the implementation store. */
const BOTH = "import { ImplementationService } from './implementation.service';\nconst m = domain.mitigationsByTechnique.get(id);\n";
const MAP_ONLY = 'const m = domain.mitigationsByTechnique.get(id);\n';
const STORE_ONLY = 'const s = implService.getStatusMap();\n';

function fixture(files, allowlist) {
  const dir = mkdtempSync(join(tmpdir(), 'check-seams-'));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  if (allowlist) {
    mkdirSync(join(dir, 'scripts'), { recursive: true });
    writeFileSync(join(dir, DEFAULT_ALLOWLIST), JSON.stringify(allowlist, null, 2));
  }
  return dir;
}

const entry = (file, extra = {}) => ({
  file, uses: { ImplementationService: 1, mitigationsByTechnique: 1 }, bucket: 'stays', reason: 'mitigation-level', removedBy: 'E9.1', ...extra,
});
const list = (...entries) => ({ rules: { 'posture-rollup': { entries } } });
const run = (dir, ...args) => spawnSync(process.execPath, [SCRIPT, '--root', dir, ...args], { encoding: 'utf8' });

function withFixture(files, allowlist, fn) {
  const dir = fixture(files, allowlist);
  try { fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('this repository passes with its generated allow-list, and the list is exactly the grep', () => {
  const allowlist = readAllowlist(join(ROOT, DEFAULT_ALLOWLIST));
  const { problems } = checkSeams(ROOT, allowlist);
  assert.deepEqual(problems, []);
  const listed = allowlist.rules['posture-rollup'].entries.map((e) => e.file);
  assert.deepEqual(listed, scanRule(ROOT, 'posture-rollup').map((h) => h.file));
  // Regenerating changes nothing: membership, uses and annotations are current.
  assert.deepEqual(generateAllowlist(ROOT, allowlist).rules['posture-rollup'].entries, allowlist.rules['posture-rollup'].entries);
  for (const e of allowlist.rules['posture-rollup'].entries) {
    assert.ok(e.reason && e.removedBy && e.bucket, `${e.file} has a bucket, reason and removedBy`);
  }
  // The three files P2-07 cleaned are not listed (design §4.2).
  for (const clean of ['stats-bar.component.ts', 'report-split.ts', 'actor-profile-panel.component.ts']) {
    assert.equal(listed.some((f) => f.endsWith(`/${clean}`)), false, `${clean} is clean after P2-07`);
  }
  // one-picker (P2-12b): the list is exactly the grep, and every entry is annotated.
  const listedOnePicker = allowlist.rules['one-picker'].entries.map((e) => e.file);
  assert.deepEqual(listedOnePicker, scanRule(ROOT, 'one-picker').map((h) => h.file));
  assert.deepEqual(generateAllowlist(ROOT, allowlist).rules['one-picker'].entries, allowlist.rules['one-picker'].entries);
  for (const e of allowlist.rules['one-picker'].entries) {
    assert.ok(e.reason && e.removedBy && e.bucket, `${e.file} (one-picker) has a bucket, reason and removedBy`);
  }
  // The compare panels moved to the shared picker in P2-12b, so they are not rival pickers.
  for (const onPicker of ['actor-compare-panel.component.ts', 'comparison-panel.component.ts', 'scenario-panel.component.ts']) {
    assert.equal(listedOnePicker.some((f) => f.endsWith(`/${onPicker}`)), false, `${onPicker} is on the shared picker`);
  }
  // picker-select (RP-F item 3): the list is exactly the grep, every entry is annotated,
  // and the emulation panel, whose Common picks are now the picker's presets, is clean.
  const listedSelect = allowlist.rules['picker-select'].entries.map((e) => e.file);
  assert.deepEqual(listedSelect, scanRule(ROOT, 'picker-select').map((h) => h.file));
  assert.deepEqual(generateAllowlist(ROOT, allowlist).rules['picker-select'].entries, allowlist.rules['picker-select'].entries);
  for (const e of allowlist.rules['picker-select'].entries) {
    assert.ok(e.reason && e.removedBy && e.bucket, `${e.file} (picker-select) has a bucket, reason and removedBy`);
  }
  for (const clean of ['emulation-plan-panel.component.ts', 'emulation-plan-panel.component.html']) {
    assert.equal(listedSelect.some((f) => f.endsWith(`/${clean}`)), false, `${clean} selects through the shared picker`);
  }
  // It leaves one-picker's patterns as decided (P2-17): domain.groups AND aliases.some( only.
  assert.deepEqual(allowlist.rules['one-picker'].patterns, [String.raw`domain\.groups\b`, String.raw`\baliases\.some\(`]);
});

test('a planted violation fails the CLI and is named', () => {
  withFixture({
    'src/app/services/listed.service.ts': BOTH,
    'src/app/components/new/new.component.ts': BOTH,
  }, list(entry('src/app/services/listed.service.ts')), (dir) => {
    const r = run(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /src\/app\/components\/new\/new\.component\.ts matches both regexes and is not on the allow-list/);
    assert.doesNotMatch(r.stderr, /listed\.service\.ts/);
  });
});

test('one-picker: a planted rival group picker fails; the threat-profile-picker itself is excluded', () => {
  // A component outside the picker that filters domain.groups by alias is a rival picker.
  const PICKER_COPY = 'const hits = domain.groups.filter(g => g.name.toLowerCase().includes(q) || g.aliases.some(a => a.toLowerCase().includes(q)));\n';
  withFixture({ 'src/app/components/rival/rival.component.ts': PICKER_COPY }, { rules: { 'one-picker': { entries: [] } } }, (dir) => {
    const r = run(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /one-picker: src\/app\/components\/rival\/rival\.component\.ts matches both regexes and is not on the allow-list/);
  });
  // The same code UNDER threat-profile-picker is excluded — it is the one allowed picker.
  withFixture({ 'src/app/components/threat-profile-picker/threat-profile-picker.component.ts': PICKER_COPY }, { rules: { 'one-picker': { entries: [] } } }, (dir) => {
    assert.equal(run(dir).status, 0);
  });
  // A technique-name filter plus a domain.groups STIX lookup is NOT a rival picker (no aliases.some).
  withFixture({ 'src/app/components/graph/graph.component.ts': 'const t = list.filter(x => x.name.toLowerCase().includes(q)); const g = domain.groups.find(g => g.id === id);\n' }, { rules: { 'one-picker': { entries: [] } } }, (dir) => {
    assert.equal(run(dir).status, 0);
  });
});

test('picker-select: a planted direct selectGroup( call fails; the picker itself is excluded; a listed file passes', () => {
  const none = { rules: { 'picker-select': { entries: [] } } };
  // The RP-F form: preset buttons in a template that call a selectGroup() beside the picker.
  const PRESETS = '<button (click)="selectGroup(qp.group)">{{ qp.label }}</button>\n<app-threat-profile-picker mode="single" (groupSelected)="onGroupPicked($event)" />\n';
  withFixture({ 'src/app/components/rival/rival.component.html': PRESETS }, none, (dir) => {
    const r = run(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /picker-select: src\/app\/components\/rival\/rival\.component\.html matches both regexes and is not on the allow-list/);
    assert.match(r.stderr, /\(groupSelected\) output or pass presets as \[quickPicks\]/);
  });
  // A TypeScript call (this.selectGroup(g), picker.selectCampaign(c)) is the same seam.
  for (const call of ['this.selectGroup(group);\n', 'picker.selectCampaign(c);\n']) {
    withFixture({ 'src/app/components/rival/rival.component.ts': call }, none, (dir) => {
      assert.equal(run(dir).status, 1, call);
    });
  }
  // The picker's own selection methods and template are excluded.
  withFixture({
    'src/app/components/threat-profile-picker/threat-profile-picker.component.ts': 'selectGroup(g: ThreatGroup): void { this.selectGroup(g); }\n',
    'src/app/components/threat-profile-picker/threat-profile-picker.component.html': '<button (click)="selectGroup(g)"></button>\n',
  }, none, (dir) => {
    assert.equal(run(dir).status, 0);
  });
  // Binding the picker's output, passing presets, or a name that only starts the same is not a call.
  withFixture({ 'src/app/components/ok/ok.component.html': '<app-threat-profile-picker mode="single" [quickPicks]="quickPicks" (groupSelected)="onGroupPicked($event)" />\n<p>{{ reselectGroup }} {{ selectGroupId }}</p>\n' }, none, (dir) => {
    assert.equal(run(dir).status, 0);
  });
  // A listed file with a reason passes.
  withFixture({ 'src/app/components/browse/browse.component.ts': 'onGroupPicked(id) { this.selectGroup(find(id)); }\n' }, {
    rules: { 'picker-select': { entries: [{ file: 'src/app/components/browse/browse.component.ts', uses: { 'selectGroup(': 1 }, bucket: 'stays', reason: 'handler of the picker output', removedBy: 'stays' }] } },
  }, (dir) => {
    const r = run(dir);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /picker-select: 1 allow-listed files/);
  });
});

test('an allow-listed file passes, and the CLI prints the list with its reason and target', () => {
  withFixture({ 'src/app/services/listed.service.ts': BOTH }, list(entry('src/app/services/listed.service.ts')), (dir) => {
    const r = run(dir);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /posture-rollup: 1 allow-listed files/);
    assert.match(r.stdout, /src\/app\/services\/listed\.service\.ts {2}\[stays; removed by E9\.1\]/);
    assert.match(r.stdout, /mitigation-level/);
    assert.match(r.stdout, /check-seams: OK/);
  });
});

test('a stale entry (a listed file that no longer matches both regexes) fails, so the list shrinks', () => {
  withFixture({
    'src/app/services/moved.service.ts': MAP_ONLY,
    'src/app/services/kept.service.ts': BOTH,
  }, list(entry('src/app/services/kept.service.ts'), entry('src/app/services/moved.service.ts')), (dir) => {
    const r = run(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /src\/app\/services\/moved\.service\.ts is on the allow-list but no longer matches both regexes \(stale entry\)/);
    assert.doesNotMatch(r.stderr, /kept\.service\.ts/);
  });
  // A listed file that was deleted is stale too.
  withFixture({}, list(entry('src/app/services/gone.service.ts')), (dir) => {
    assert.match(run(dir).stderr, /gone\.service\.ts is on the allow-list but no longer matches/);
  });
});

test('spec files and files matching only one regex are outside the rule', () => {
  withFixture({
    'src/app/services/a.service.spec.ts': BOTH,
    'src/app/services/map-only.service.ts': MAP_ONLY,
    'src/app/services/store-only.service.ts': STORE_ONLY,
    'src/app/components/x/x.component.html': '<p>{{ implService.getStatusMap() }}</p>\n',
  }, list(), (dir) => {
    assert.deepEqual(scanRule(dir, 'posture-rollup'), []);
    assert.equal(run(dir).status, 0);
  });
  // A template counts like any other non-spec file under src/app.
  withFixture({ 'src/app/components/x/x.component.html': '<p>{{ d.mitigationsByTechnique }} {{ implService }}</p>\n' }, list(), (dir) => {
    assert.match(run(dir).stderr, /x\.component\.html matches both regexes/);
  });
});

test('an entry without a reason or removedBy fails', () => {
  withFixture({ 'src/app/services/listed.service.ts': BOTH }, list(entry('src/app/services/listed.service.ts', { reason: '' })), (dir) => {
    const r = run(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /listed\.service\.ts is listed without a reason or removedBy/);
  });
});

test('--write regenerates membership and uses from the grep, keeps annotations, and leaves new files for a person to annotate', () => {
  withFixture({
    'src/app/services/kept.service.ts': BOTH + MAP_ONLY,
    'src/app/services/moved.service.ts': MAP_ONLY,
    'src/app/services/new.service.ts': BOTH,
  }, list(entry('src/app/services/kept.service.ts', { reason: 'kept reason', removedBy: 'P2-99' }), entry('src/app/services/moved.service.ts')), (dir) => {
    const r = run(dir, '--write');
    const written = JSON.parse(readFileSync(join(dir, DEFAULT_ALLOWLIST), 'utf8')).rules['posture-rollup'];
    assert.deepEqual(written.entries.map((e) => e.file), ['src/app/services/kept.service.ts', 'src/app/services/new.service.ts']);
    assert.deepEqual(written.entries[0], {
      file: 'src/app/services/kept.service.ts', uses: { ImplementationService: 1, mitigationsByTechnique: 2 },
      bucket: 'stays', reason: 'kept reason', removedBy: 'P2-99',
    });
    assert.deepEqual([written.entries[1].reason, written.entries[1].removedBy], ['', '']);
    // The new file still fails until a person gives it a reason and a target.
    assert.equal(r.status, 1);
    assert.match(r.stderr, /new\.service\.ts is listed without a reason or removedBy/);
  });
});

test('a listed file whose uses changed passes with a note to regenerate', () => {
  withFixture({ 'src/app/services/listed.service.ts': BOTH + MAP_ONLY }, list(entry('src/app/services/listed.service.ts')), (dir) => {
    const r = run(dir);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /note: posture-rollup: src\/app\/services\/listed\.service\.ts uses changed/);
  });
});
