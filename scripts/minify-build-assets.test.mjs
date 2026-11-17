// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for scripts/minify-build-assets.mjs: pretty JSON shrinks losslessly,
// already-minified files are left byte-for-byte alone (idempotent), invalid
// JSON is a hard error, and the walk is recursive.
// Run with: node --test scripts/minify-build-assets.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { findJsonFiles, minifyJsonFile, minifyDir } from './minify-build-assets.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'minify-build-assets.mjs');

function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'minify-assets-'));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

test('minifies a pretty-printed file losslessly and reports the saving', () => {
  const value = { type: 'bundle', objects: [{ id: 'a', n: 1 }, { id: 'b', n: 2 }] };
  const dir = fixture({ 'data.json': JSON.stringify(value, null, 4) });
  try {
    const file = join(dir, 'data.json');
    const r = minifyJsonFile(file);
    assert.equal(r.changed, true);
    assert.ok(r.after < r.before);
    const after = readFileSync(file, 'utf8');
    assert.equal(after, JSON.stringify(value)); // no whitespace
    assert.deepEqual(JSON.parse(after), value); // identical data
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('is idempotent: an already-minified file is left byte-for-byte unchanged', () => {
  const value = { a: 1, b: [2, 3] };
  const dir = fixture({ 'data.json': JSON.stringify(value) });
  try {
    const file = join(dir, 'data.json');
    const before = readFileSync(file);
    const r = minifyJsonFile(file);
    assert.equal(r.changed, false);
    assert.deepEqual(readFileSync(file), before);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('invalid JSON is a hard error naming the file', () => {
  const dir = fixture({ 'broken.json': '{ not valid json ,,, }' });
  try {
    assert.throws(() => minifyJsonFile(join(dir, 'broken.json')), /Invalid JSON in .*broken\.json/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('walks nested directories and only touches .json', () => {
  const dir = fixture({
    'a.json': '{\n  "x": 1\n}',
    'sub/b.json': '{\n  "y": 2\n}',
    'sub/readme.md': '# not json\n',
  });
  try {
    assert.equal(findJsonFiles(dir).length, 2);
    const s = minifyDir(dir);
    assert.equal(s.count, 2);
    assert.equal(s.changed, 2);
    assert.ok(s.after < s.before);
    assert.equal(readFileSync(join(dir, 'sub/readme.md'), 'utf8'), '# not json\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI exits 0 and prints a summary; missing dir exits 1', () => {
  const dir = fixture({ 'data.json': '{\n  "x": 1\n}' });
  try {
    const ok = spawnSync(process.execPath, [SCRIPT, dir], { encoding: 'utf8' });
    assert.equal(ok.status, 0);
    assert.match(ok.stdout, /minify-build-assets: 1\/1 JSON assets minified/);

    const missing = spawnSync(process.execPath, [SCRIPT, join(dir, 'nope')], { encoding: 'utf8' });
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /directory not found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
