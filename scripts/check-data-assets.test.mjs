// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for scripts/check-data-assets.mjs: the repository passes, and a planted
// unread asset, a stale SERVED_UNREAD row and an inventory-only mention fail.
// Run with: node --test scripts/check-data-assets.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { checkAssets } from './check-data-assets.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'check-data-assets.mjs');

function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'data-assets-'));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

test('every entry under src/assets/data in this repository is read or listed', () => {
  const { problems, scanned } = checkAssets(ROOT);
  assert.deepEqual(problems, []);
  assert.ok(scanned.length > 0);
  assert.equal(scanned.some((s) => s.entry === 'cve-technique-counts.json'), false);
});

test('a planted unread asset fails the CLI and is named', () => {
  const dir = fixture({
    'src/assets/data/read.json': '{}',
    'src/assets/data/orphan.json': '{}',
    'src/app/services/a.service.ts': "const URL = 'assets/data/read.json';\n",
  });
  try {
    const run = spawnSync(process.execPath, [SCRIPT, '--root', dir], { encoding: 'utf8' });
    assert.equal(run.status, 1);
    assert.match(run.stderr, /src\/assets\/data\/orphan\.json ships but no code/);
    assert.doesNotMatch(run.stderr, /read\.json/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a mention in the source inventory, a spec, a test helper or a comment is not a read', () => {
  const dir = fixture({
    'src/assets/data/x.json': '{}',
    'src/app/services/source-inventory.ts': "owner: 'src/assets/data/x.json',\n",
    'src/app/services/a.service.spec.ts': "http.get('assets/data/x.json');\n",
    'src/app/testing/helper.ts': "const F = 'assets/data/x.json';\n",
    'src/app/services/b.service.ts': '// reads assets/data/x.json elsewhere\n',
  });
  try {
    assert.equal(checkAssets(dir, {}).problems.length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a prefix of another entry name is not a read of it', () => {
  const dir = fixture({
    'src/assets/data/map.json': '{}',
    'src/assets/data/map.json.bak': '{}',
    'src/app/services/a.service.ts': "const URL = 'assets/data/map.json';\n",
  });
  try {
    assert.deepEqual(checkAssets(dir, {}).problems.map((p) => p.split(' ')[0]), ['src/assets/data/map.json.bak']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a SERVED_UNREAD row that is read or missing fails', () => {
  const dir = fixture({
    'src/assets/data/layers/index.json': '{}',
    'src/app/services/a.service.ts': "const DIR = 'assets/data/layers';\n",
  });
  try {
    const { problems } = checkAssets(dir, { layers: 'served', gone: 'served' });
    assert.equal(problems.length, 2);
    assert.match(problems[0], /layers is read by src\/app\/services\/a\.service\.ts/);
    assert.match(problems[1], /gone, which does not exist/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
