// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for scripts/check-branch-coverage.mjs:
//   node --test scripts/check-branch-coverage.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import { checkBranchCoverage, findEntry, normalisePath } from './check-branch-coverage.mjs';

const SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)), 'check-branch-coverage.mjs');
const FILES = ['src/app/models/posture/derive-posture.ts', 'src/app/models/posture/mitigation-rollup.ts'];

const pctEntry = (covered, total) => ({
  lines: { total: 10, covered: 10, skipped: 0, pct: 100 },
  statements: { total: 10, covered: 10, skipped: 0, pct: 100 },
  functions: { total: 2, covered: 2, skipped: 0, pct: 100 },
  branches: { total, covered, skipped: 0, pct: total === 0 ? 100 : Math.round((covered / total) * 10000) / 100 },
});

/** A synthetic json-summary keyed the way karma-coverage keys it on the given platform. */
function summary(prefix, sep, branches) {
  const out = { total: pctEntry(1, 1) };
  for (const f of FILES) out[prefix + f.split('/').join(sep)] = branches;
  return out;
}

function runCli(summaryObj, files = FILES) {
  const dir = mkdtempSync(join(tmpdir(), 'branch-cov-'));
  try {
    const p = join(dir, 'coverage-summary.json');
    writeFileSync(p, JSON.stringify(summaryObj));
    return spawnSync(process.execPath, [SCRIPT, '--summary', p, ...files], { encoding: 'utf8' });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('passes on a synthetic json-summary at 100% branches (ubuntu keys)', () => {
  const r = runCli(summary('/home/runner/work/ATTACK-Navi/ATTACK-Navi/', '/', pctEntry(100, 100)));
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /derive-posture\.ts branches 100%/);
  assert.match(r.stdout, /mitigation-rollup\.ts branches 100%/);
});

test('passes at 100% with Windows keys (backslashes, drive letter in another case)', () => {
  const r = runCli(summary('C:\\Users\\dev\\ATTACK-Navi\\', '\\', pctEntry(57, 57)));
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /derive-posture\.ts branches 100% \(57\/57\)/);
});

test('fails on a synthetic json-summary at 99% branches', () => {
  const r = runCli(summary('/home/runner/work/ATTACK-Navi/ATTACK-Navi/', '/', pctEntry(99, 100)));
  assert.equal(r.status, 1);
  assert.match(r.stderr, /derive-posture\.ts branches 99% \(99\/100\)\s+FAIL/);
  assert.match(r.stderr, /2 of 2 file\(s\) below 100% branch coverage/);
});

test('fails when only one file is below 100%', () => {
  const s = summary('/repo/', '/', pctEntry(100, 100));
  s['/repo/src/app/models/posture/mitigation-rollup.ts'] = pctEntry(11, 12);
  const r = runCli(s);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /derive-posture\.ts branches 100%/);
  assert.match(r.stderr, /mitigation-rollup\.ts branches 91\.66% \(11\/12\)\s+FAIL/);
});

test('fails when a named file is missing from the summary', () => {
  const r = runCli({ total: pctEntry(1, 1), '/repo/src/app/other.ts': pctEntry(1, 1) });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /not in the coverage summary/);
});

test('exits 2 on usage errors and on an unreadable summary', () => {
  assert.equal(spawnSync(process.execPath, [SCRIPT], { encoding: 'utf8' }).status, 2);
  const missing = spawnSync(process.execPath, [SCRIPT, '--summary', join(tmpdir(), 'no-such-dir-xyz', 's.json'), FILES[0]], { encoding: 'utf8' });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /cannot read/);
});

test('matches on a whole trailing path segment only', () => {
  const s = { '/repo/src/app/models/posture/not-derive-posture.ts': pctEntry(1, 1) };
  assert.equal(findEntry(s, 'derive-posture.ts'), null);
  assert.notEqual(findEntry(s, 'posture/not-derive-posture.ts'), null);
  assert.equal(normalisePath('.\\src\\app\\x.ts'), 'src/app/x.ts');
  assert.equal(normalisePath('C:\\A\\B.ts'), 'c:/a/b.ts');
});

test('a file with no branches passes at 100%', () => {
  const [r] = checkBranchCoverage({ '/repo/a.ts': pctEntry(0, 0) }, ['a.ts']);
  assert.deepEqual([r.ok, r.pct], [true, 100]);
});
