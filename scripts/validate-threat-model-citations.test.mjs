// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Self-test for validate-threat-model-citations.mjs. Run with:
//   node --test scripts/validate-threat-model-citations.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { extractCitations, checkCitations } from './validate-threat-model-citations.mjs';

function makeRepo() {
  const root = mkdtempSync(join(tmpdir(), 'tm-cite-'));
  mkdirSync(join(root, '.github', 'workflows'), { recursive: true });
  mkdirSync(join(root, 'node_modules', 'pkg'), { recursive: true });
  writeFileSync(join(root, 'docker-compose.yml'), 'a\nb\nc\n');            // 3 lines
  writeFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'x\ny\n');   // 2 lines
  writeFileSync(join(root, 'Dockerfile'), 'FROM scratch\n');               // 1 line
  writeFileSync(join(root, 'node_modules', 'pkg', 'index.js'), '1\n2\n');  // 2 lines
  return root;
}

test('extracts path:line and path:first-last tokens from nested strings', () => {
  const model = {
    summary: { description: 'see docker-compose.yml:2 and ./Dockerfile:1' },
    detail: { cells: [{ data: { threats: [{ description: 'Evidence: .github/workflows/ci.yml:1-2; node_modules/pkg/index.js:2' }] } }] },
  };
  const found = extractCitations(model).map(c => `${c.path}:${c.from}${c.to ? '-' + c.to : ''}`);
  assert.deepEqual(found, ['docker-compose.yml:2', 'Dockerfile:1', '.github/workflows/ci.yml:1-2', 'node_modules/pkg/index.js:2']);
});

test('accepts citations inside the cited files', () => {
  const root = makeRepo();
  const citations = extractCitations({ t: 'docker-compose.yml:1-3, .github/workflows/ci.yml:2, Dockerfile:1' });
  const result = checkCitations(citations, root);
  assert.deepEqual(result.problems, []);
  assert.equal(result.verified, 3);
});

test('fails citations past end of file and missing files', () => {
  const root = makeRepo();
  const citations = extractCitations({ t: 'docker-compose.yml:62-63 nginx.conf:40 ci.yml:1' });
  const result = checkCitations(citations, root);
  assert.equal(result.problems.length, 3);
  assert.match(result.problems[0], /docker-compose\.yml:62-63: past end of file \(3 lines\)/);
  assert.match(result.problems[1], /nginx\.conf:40: file not found/);
  assert.match(result.problems[2], /ci\.yml:1: file not found/);
});

test('verifies node_modules citations when installed and skips them when not', () => {
  const root = makeRepo();
  const installed = checkCitations(extractCitations({ t: 'node_modules/pkg/index.js:2' }), root);
  assert.deepEqual(installed.problems, []);
  assert.equal(installed.verified, 1);
  const tooFar = checkCitations(extractCitations({ t: 'node_modules/pkg/index.js:9' }), root);
  assert.equal(tooFar.problems.length, 1);
  const absent = checkCitations(extractCitations({ t: 'node_modules/other/index.js:1' }), root);
  assert.deepEqual(absent.problems, []);
  assert.equal(absent.unverified, 1);
});

test('rejects a citation that escapes the repository root', () => {
  const root = makeRepo();
  const result = checkCitations(extractCitations({ t: '../../etc/passwd.txt:1' }), root);
  assert.equal(result.problems.length, 1);
  assert.match(result.problems[0], /escapes the repository root/);
});
