// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for check-sw-prefetch.mjs: it must PASS when every application script is in a prefetch
// asset group, and FAIL (exit 1) when any script is in a lazy group — the configuration that
// caused the cold-start dead load. Each case writes a minimal ngsw.json fixture and runs the
// real CLI against it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const CHECK = fileURLToPath(new URL('./check-sw-prefetch.mjs', import.meta.url));

function runCheck(dir, ...flags) {
  try {
    const stdout = execFileSync('node', [CHECK, dir, ...flags], { encoding: 'utf8' });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status ?? 1, stdout: String(e.stdout ?? ''), stderr: String(e.stderr ?? '') };
  }
}

function fixture(ngsw) {
  const dir = mkdtempSync(join(tmpdir(), 'swprefetch-'));
  const browser = join(dir, 'browser');
  mkdirSync(browser);
  writeFileSync(join(browser, 'ngsw.json'), JSON.stringify(ngsw));
  // index.html + the dummy files on disk, so --report's entry-closure walk and size lookups
  // resolve. The entry src is base-relative (as Angular emits it), never base-prefixed.
  writeFileSync(join(browser, 'index.html'), '<script src="main-AAA.js" type="module"></script>');
  writeFileSync(join(browser, 'main-AAA.js'), 'export{};');
  writeFileSync(join(browser, 'chunk-BBB.js'), 'export{};');
  return { dir, browser, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('passes when every application script is in a prefetch group', () => {
  const { browser, cleanup } = fixture({
    configVersion: 1,
    index: '/index.html',
    assetGroups: [
      {
        name: 'app-shell',
        installMode: 'prefetch',
        urls: ['/index.html', '/main-AAA.js', '/chunk-BBB.js'],
        patterns: [],
      },
      { name: 'assets', installMode: 'lazy', urls: ['/favicon.ico'], patterns: [] },
    ],
  });
  try {
    const r = runCheck(browser);
    assert.equal(r.code, 0, r.stdout);
    assert.match(r.stdout, /all 2 application scripts are prefetched/);
  } finally {
    cleanup();
  }
});

test('--report handles a base-href deploy build without a lookup error', () => {
  // Deploy builds use `ng build --base-href /ATTACK-Navi/`, so manifest URLs carry that prefix
  // while index.html's src stays relative. --report must resolve both to the same space (and
  // disk paths), classify correctly, and exit 0 when every script is prefetched.
  const { browser, cleanup } = fixture({
    configVersion: 1,
    index: '/ATTACK-Navi/index.html',
    assetGroups: [
      {
        name: 'app-shell',
        installMode: 'prefetch',
        urls: ['/ATTACK-Navi/index.html', '/ATTACK-Navi/main-AAA.js', '/ATTACK-Navi/chunk-BBB.js'],
        patterns: [],
      },
    ],
  });
  try {
    const r = runCheck(browser, '--report');
    assert.equal(r.code, 0, (r.stdout || '') + (r.stderr || ''));
    assert.match(r.stdout, /app base: \/ATTACK-Navi\//);
    assert.match(r.stdout, /scripts NOT in a prefetch group: 0/);
    // The entry closure resolved against the base (no "not in any asset group").
    assert.doesNotMatch(r.stdout, /not in any asset group/);
  } finally {
    cleanup();
  }
});

test('fails when a script is only in a lazy group (the cold-start defect)', () => {
  const { browser, cleanup } = fixture({
    configVersion: 1,
    index: '/index.html',
    assetGroups: [
      { name: 'app-shell', installMode: 'prefetch', urls: ['/index.html', '/main-AAA.js'], patterns: [] },
      { name: 'lazy-code', installMode: 'lazy', urls: ['/chunk-BBB.js'], patterns: [] },
    ],
  });
  try {
    const r = runCheck(browser);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /not in a prefetch asset group/);
    assert.match(r.stderr, /chunk-BBB\.js/);
  } finally {
    cleanup();
  }
});
