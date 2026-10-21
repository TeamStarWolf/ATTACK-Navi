#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Guards the Lylat `lylat-validated-detections/1` consumer contract (P2-20):
//
//   1. the synthetic fixture validates against the consumer schema AND is clean
//      under the privacy regex;
//   2. every file in the invalid corpus is rejected (by the schema, the privacy
//      regex, or both) -- a negative that stops failing is a hole in the guard;
//   3. the schema's canonical projection still hashes to the sha256 pinned in
//      PROVENANCE.md, so the provisional structural pin cannot drift silently.
//
// Dependency-free: the schema is checked by scripts/lib/json-schema-subset.mjs
// and the privacy regex is the same one src/app/contracts/lylat-validated-
// detections.ts enforces at import, so CI and the app refuse the same inputs.
//
//   node scripts/check-lylat-contract.mjs            check this repository
//   node scripts/check-lylat-contract.mjs --root DIR check DIR instead

import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { validate } from './lib/json-schema-subset.mjs';

export const SCHEMA_PATH = 'docs/contracts/lylat-validated-detections.schema.json';
export const PROVENANCE_PATH = 'docs/contracts/PROVENANCE.md';
export const FIXTURE_PATH = 'src/testing/fixtures/lylat/validated-detections.fixture.json';
export const INVALID_DIR = 'src/testing/fixtures/lylat/invalid';

// Same privacy rule as the app: a path separator, '@', whitespace or a dotted-quad
// IP in any of the three free-id fields refuses the whole export.
const PRIVACY_RE = /[/\\@\s]|[0-9]{1,3}(\.[0-9]{1,3}){3}/;
const PRIVACY_FIELDS = ['detection_ref', 'evidence_ref', 'mission_id'];

// Keys dropped from the canonical projection: identity and prose that may differ
// between the producer's copy and ours without changing the structure.
const DROPPED_KEYS = new Set(['$id', 'description', 'comment', '$comment']);

/** Recursively sort object keys and drop identity/prose keys. Arrays keep order. */
export function canonicalize(node) {
  if (Array.isArray(node)) return node.map(canonicalize);
  if (node && typeof node === 'object') {
    const out = {};
    for (const key of Object.keys(node).sort()) {
      if (DROPPED_KEYS.has(key)) continue;
      out[key] = canonicalize(node[key]);
    }
    return out;
  }
  return node;
}

/** The sha256 (hex) of the schema's canonical projection. */
export function schemaHash(schema) {
  return createHash('sha256').update(JSON.stringify(canonicalize(schema))).digest('hex');
}

/** Privacy-regex errors over the three free-id fields of every row. */
export function privacyErrors(exportObj) {
  const errors = [];
  const rows = Array.isArray(exportObj?.rows) ? exportObj.rows : [];
  rows.forEach((row, i) => {
    if (!row || typeof row !== 'object') return;
    for (const field of PRIVACY_FIELDS) {
      const v = row[field];
      if (typeof v === 'string' && PRIVACY_RE.test(v)) {
        errors.push(`#/rows[${i}]/${field}: fails the privacy rule`);
      }
    }
  });
  return errors;
}

/** Schema errors plus privacy errors: the full consumer contract. */
export function validateExport(schema, exportObj) {
  return [...validate(schema, exportObj), ...privacyErrors(exportObj)];
}

/** Read the sha256 pinned in PROVENANCE.md, or null when absent. */
export function pinnedHash(text) {
  const m = text.match(/sha256:\s*`?([0-9a-f]{64})`?/i);
  return m ? m[1].toLowerCase() : null;
}

export function checkContract(root) {
  const problems = [];
  const read = (rel) => readFileSync(join(root, rel), 'utf8');
  const schema = JSON.parse(read(SCHEMA_PATH));

  // 1. the fixture validates and is privacy-clean.
  const fixture = JSON.parse(read(FIXTURE_PATH));
  const fixtureErrors = validateExport(schema, fixture);
  if (fixtureErrors.length) {
    problems.push(`${FIXTURE_PATH} does not satisfy the contract: ${fixtureErrors.join('; ')}`);
  }

  // 2. every invalid-corpus file is rejected.
  const invalidFiles = readdirSync(join(root, INVALID_DIR)).filter((f) => f.endsWith('.json')).sort();
  if (invalidFiles.length === 0) problems.push(`${INVALID_DIR} has no negative fixtures`);
  for (const file of invalidFiles) {
    let parsed;
    try {
      parsed = JSON.parse(read(`${INVALID_DIR}/${file}`));
    } catch {
      continue; // unparseable is a valid rejection
    }
    if (validateExport(schema, parsed).length === 0) {
      problems.push(`${INVALID_DIR}/${file} is accepted but should be rejected`);
    }
  }

  // 3. the pinned hash still matches the schema's canonical projection.
  const pinned = pinnedHash(read(PROVENANCE_PATH));
  const actual = schemaHash(schema);
  if (!pinned) {
    problems.push(`${PROVENANCE_PATH} does not pin a sha256 for the schema`);
  } else if (pinned !== actual) {
    problems.push(`${PROVENANCE_PATH} pins sha256 ${pinned} but the schema hashes to ${actual}: re-pin it or revert the schema`);
  }

  return { problems, invalidCount: invalidFiles.length, hash: actual };
}

function main(argv) {
  const at = argv.indexOf('--root');
  const root = at >= 0 ? resolve(argv[at + 1]) : resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const { problems, invalidCount, hash } = checkContract(root);
  if (problems.length) {
    for (const p of problems) console.error(`check-lylat-contract: ${p}`);
    return 1;
  }
  console.log(`check-lylat-contract: fixture valid, ${invalidCount} negatives rejected, schema sha256 ${hash.slice(0, 12)}… matches PROVENANCE`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) process.exit(main(process.argv.slice(2)));
