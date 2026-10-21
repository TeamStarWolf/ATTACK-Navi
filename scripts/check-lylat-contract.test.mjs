// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tests for scripts/check-lylat-contract.mjs: the repository passes, the hash
// projection ignores prose/identity keys but tracks structure, the privacy
// sweep fires, and the validator agrees with the schema on the shared corpus.
// Run with: node --test scripts/check-lylat-contract.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync, mkdirSync, writeFileSync, cpSync, rmSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  checkContract, canonicalize, schemaHash, privacyErrors, validateExport, pinnedHash,
  SCHEMA_PATH, FIXTURE_PATH, INVALID_DIR, PROVENANCE_PATH,
} from './check-lylat-contract.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'check-lylat-contract.mjs');
const schema = () => JSON.parse(readFileSync(join(ROOT, SCHEMA_PATH), 'utf8'));

test('the repository passes the contract check', () => {
  const { problems, invalidCount } = checkContract(ROOT);
  assert.deepEqual(problems, []);
  assert.ok(invalidCount >= 4);
});

test('the CLI exits 0 on this repository', () => {
  const r = spawnSync(process.execPath, [SCRIPT], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
});

test('the CLI process exits non-zero on every invalid-corpus file (promoted to the fixture)', () => {
  // Each negative, put where the valid fixture belongs, must fail the CLI end-to-end:
  // the schema, PROVENANCE and the real negative corpus are copied unchanged, so the
  // only thing that can make the process exit non-zero is the invalid fixture itself.
  const invalid = readdirSync(join(ROOT, INVALID_DIR)).filter(f => f.endsWith('.json')).sort();
  assert.ok(invalid.length >= 4);
  for (const file of invalid) {
    const root = mkdtempSync(join(tmpdir(), 'lylat-contract-'));
    try {
      mkdirSync(join(root, 'docs', 'contracts'), { recursive: true });
      mkdirSync(join(root, 'src', 'testing', 'fixtures', 'lylat'), { recursive: true });
      cpSync(join(ROOT, SCHEMA_PATH), join(root, SCHEMA_PATH));
      cpSync(join(ROOT, PROVENANCE_PATH), join(root, PROVENANCE_PATH));
      cpSync(join(ROOT, INVALID_DIR), join(root, INVALID_DIR), { recursive: true });
      // the invalid file now stands in for the valid fixture the CLI expects to pass
      writeFileSync(join(root, FIXTURE_PATH), readFileSync(join(ROOT, INVALID_DIR, file)));
      const r = spawnSync(process.execPath, [SCRIPT, '--root', root], { encoding: 'utf8' });
      assert.notEqual(r.status, 0, `CLI should reject ${file} as the fixture, but exited 0`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test('the pinned hash in PROVENANCE matches the schema', () => {
  const pinned = pinnedHash(readFileSync(join(ROOT, PROVENANCE_PATH), 'utf8'));
  assert.equal(pinned, schemaHash(schema()));
});

test('the canonical projection ignores prose and identity but tracks structure', () => {
  const s = schema();
  // $id / title / description / comment / $comment / x-navi-pin do not change the hash.
  assert.equal(schemaHash({ ...s, description: 'anything else' }), schemaHash(s));
  assert.equal(schemaHash({ ...s, $id: 'urn:x', comment: 'c', $comment: 'c' }), schemaHash(s));
  // round 2 (item 10): title and the Navi-only x-navi-pin marker are dropped too,
  // so flipping the pin to 'stable' or retitling the schema does not move the hash.
  assert.equal(schemaHash({ ...s, title: 'A totally different title', 'x-navi-pin': 'stable' }), schemaHash(s));
  // a real structural change does.
  assert.notEqual(schemaHash({ ...s, type: 'array' }), schemaHash(s));
  // keys are sorted, so key order in source does not matter.
  assert.deepEqual(canonicalize({ b: 1, a: 2 }), { a: 2, b: 1 });
});

test('the validator refuses an impossible calendar date (round 2, item 9)', () => {
  const s = schema();
  const fixture = JSON.parse(readFileSync(join(ROOT, FIXTURE_PATH), 'utf8'));
  // 2026-02-30 matches the date regex but is not a real day: refused in a row
  // `validated_at` (format: date) and in the export `generated_at` (date-time).
  const badDay = { ...fixture, rows: [{ ...fixture.rows[0], validated_at: '2026-02-30' }] };
  assert.ok(validateExport(s, badDay).some(e => e.includes('/validated_at')), 'impossible validated_at should fail');
  const badGen = { ...fixture, generated_at: '2026-02-30T00:00:00Z' };
  assert.ok(validateExport(s, badGen).some(e => e.includes('/generated_at')), 'impossible generated_at should fail');
});

test('the privacy sweep fires on the three free-id fields only', () => {
  const row = (f, v) => ({ rows: [{ mission_id: 'M', detection_ref: 'wazuh:1', evidence_ref: 'E', [f]: v }] });
  assert.equal(privacyErrors(row('evidence_ref', '10.0.0.5')).length, 1);
  assert.equal(privacyErrors(row('mission_id', 'a/b')).length, 1);
  assert.equal(privacyErrors(row('detection_ref', 'user@host')).length, 1);
  // a locked field with a dot is fine; the sweep does not look at it.
  assert.equal(privacyErrors({ rows: [{ mission_id: 'M', detection_ref: 'wazuh:1', evidence_ref: 'E', validated_at: '1.2.3.4' }] }).length, 0);
});

test('the validator accepts the fixture and rejects every invalid-corpus file (parity)', () => {
  const s = schema();
  assert.deepEqual(validateExport(s, JSON.parse(readFileSync(join(ROOT, FIXTURE_PATH), 'utf8'))), []);
  for (const f of readdirSync(join(ROOT, INVALID_DIR)).filter(x => x.endsWith('.json'))) {
    const parsed = JSON.parse(readFileSync(join(ROOT, INVALID_DIR, f), 'utf8'));
    assert.ok(validateExport(s, parsed).length > 0, `${f} should be rejected`);
  }
});
