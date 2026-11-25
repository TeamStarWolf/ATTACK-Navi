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

function runCheck(dir) {
  try {
    const stdout = execFileSync('node', [CHECK, dir], { encoding: 'utf8' });
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
  // A couple of dummy files so size lookups resolve (not required for the pass/fail logic).
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
