#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Per-file branch-coverage gate (Phase 2 design P2-01; epic E2.1 "100% branch
// coverage of rung derivation"). Reads the json-summary that Karma writes when
// `ng test --code-coverage` runs (karma.conf.js, coverageReporter) and fails
// unless every named file reaches 100% branches.
//
//   node scripts/check-branch-coverage.mjs FILE...
//   node scripts/check-branch-coverage.mjs --summary PATH FILE...
//
// FILE is repository-relative (src/app/models/posture/derive-posture.ts). The
// summary keys are absolute paths in the runner's own form (C:\... on
// Windows, /home/runner/... on ubuntu), so both sides are normalised to
// forward slashes and matched on a whole trailing path segment, without case
// on Windows-style keys. A file missing from the summary fails: a gate that
// silently skips a file it was asked to check proves nothing.

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_SUMMARY = 'coverage/attack-navi/coverage-summary.json';

/** Forward slashes, no leading './', and lower case when the path has a drive letter. */
export function normalisePath(p) {
  let s = String(p).replace(/\\/g, '/').replace(/^\.\//, '');
  if (/^[A-Za-z]:\//.test(s)) s = s.toLowerCase();
  return s;
}

/** The summary entry whose key ends with `/<file>` (or is `<file>`), or null. */
export function findEntry(summary, file) {
  const want = normalisePath(file);
  for (const [key, entry] of Object.entries(summary)) {
    if (key === 'total') continue;
    const k = normalisePath(key);
    const w = /^[a-z]:\//.test(k) ? want.toLowerCase() : want;
    if (k === w || k.endsWith(`/${w}`)) return entry;
  }
  return null;
}

/**
 * Check each file's branch coverage. Returns one result per file:
 * { file, ok, pct, covered, total, reason? }. A file with no branches at all
 * passes at 100% (istanbul reports it that way too).
 */
export function checkBranchCoverage(summary, files) {
  return files.map(file => {
    const entry = findEntry(summary, file);
    const b = entry?.branches;
    if (!b || typeof b.total !== 'number' || typeof b.covered !== 'number') {
      return { file, ok: false, pct: null, covered: 0, total: 0, reason: 'not in the coverage summary' };
    }
    const pct = b.total === 0 ? 100 : Math.floor((b.covered / b.total) * 10000) / 100;
    const ok = b.covered >= b.total;
    return ok
      ? { file, ok, pct, covered: b.covered, total: b.total }
      : { file, ok, pct, covered: b.covered, total: b.total, reason: `${b.total - b.covered} of ${b.total} branches not covered` };
  });
}

function parseArgs(argv) {
  const files = [];
  let summary = DEFAULT_SUMMARY;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--summary') summary = argv[++i];
    else files.push(argv[i]);
  }
  return { summary, files };
}

export function main(argv, log = console.log, error = console.error) {
  const { summary: summaryPath, files } = parseArgs(argv);
  if (!summaryPath || files.length === 0) {
    error('usage: node scripts/check-branch-coverage.mjs [--summary PATH] FILE...');
    return 2;
  }
  let summary;
  try {
    summary = JSON.parse(readFileSync(resolve(ROOT, summaryPath), 'utf8'));
  } catch (e) {
    error(`check-branch-coverage: cannot read ${summaryPath} (run ng test with --code-coverage first): ${e.message}`);
    return 2;
  }
  const results = checkBranchCoverage(summary, files);
  for (const r of results) {
    const line = `${r.file} branches ${r.pct === null ? 'n/a' : `${r.pct}%`} (${r.covered}/${r.total})`;
    if (r.ok) log(line);
    else error(`${line}  FAIL: ${r.reason}`);
  }
  const failed = results.filter(r => !r.ok).length;
  if (failed > 0) {
    error(`check-branch-coverage: ${failed} of ${results.length} file(s) below 100% branch coverage`);
    return 1;
  }
  log(`check-branch-coverage: ${results.length} file(s) at 100% branch coverage`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exit(main(process.argv.slice(2)));
}
