// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Regenerates src/app/testing/__snapshots__/lens-snapshots.json, the committed
// score maps of the 36 heatmap lenses (see src/app/testing/lens-snapshots.spec.ts).
//
// Karma specs run in the browser and cannot write files, so the spec logs one
// machine-readable line per lens whose map differs from the snapshot:
//   [lens-snapshot] <mode> <json>
// This script runs only that spec, collects those lines, merges them into the
// snapshot file (lenses that already match are kept as they are) and writes it
// back in a stable, diff-friendly layout: modes sorted, one technique per line.
//
// Use it only for an INTENDED change to a lens, then review `git diff` of the
// snapshot like any other code change and re-run the unit suite.
//
// Frozen-hash guard (P2-13): every lens except the registry-hosted ones
// (REGISTRY_MODES) is frozen. The script keeps one sha256 per frozen lens in
// src/app/testing/__snapshots__/lens-snapshots.frozen.json, computed with Node
// crypto over that lens's block of the snapshot file exactly as written below.
// A frozen lens with no hash yet gets one; a frozen lens whose block would
// change is refused and nothing is written. To change a frozen lens on
// purpose, delete its key from the frozen file in the same reviewed change.
// lens-snapshots.spec.ts recomputes the same hashes at spec time.
//
// Usage: node scripts/update-lens-snapshots.mjs
// Runs `npx ng test` for the one spec (ChromeHeadless); exits non-zero if the
// test run produced no snapshot lines and the snapshot file is incomplete.

import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const SNAPSHOT = 'src/app/testing/__snapshots__/lens-snapshots.json';
const FROZEN = 'src/app/testing/__snapshots__/lens-snapshots.frozen.json';
const SPEC = 'src/app/testing/lens-snapshots.spec.ts';
const EXPECTED_MODES = 36;
/**
 * Lenses hosted by the LensRegistry seam: not frozen. Every other lens is.
 * P2-13 added posture; P2-14 added proven and covered and moved status and
 * controls into the registry (their frozen keys deleted in that reviewed change).
 */
const REGISTRY_MODES = new Set(['posture', 'status', 'controls', 'proven', 'covered']);

// One fixed command line (no user input is interpolated); a shell resolves npx on Windows.
const run = spawnSync(`npx ng test --watch=false --browsers=ChromeHeadless --include=${SPEC}`, {
  encoding: 'utf8',
  shell: true,
  maxBuffer: 256 * 1024 * 1024,
});
if (run.error) throw run.error;
const output = `${run.stdout ?? ''}\n${run.stderr ?? ''}`;

const updates = {};
for (const match of output.matchAll(/\[lens-snapshot\] ([a-z0-9-]+) (\{.*?\})'?\r?$/gm)) {
  updates[match[1]] = JSON.parse(match[2]);
}

let current = {};
try {
  current = JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
} catch {
  current = {};
}
const merged = { ...current, ...updates };

/** One lens's block of the snapshot file, exactly as written below (and as the spec rebuilds it). */
function block(mode, snap) {
  const entries = Object.keys(snap)
    .sort()
    .map((id) => `    ${JSON.stringify(id)}: ${JSON.stringify(snap[id])}`);
  return `  ${JSON.stringify(mode)}: {\n${entries.join(',\n')}\n  }`;
}
const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

const modes = Object.keys(merged).sort();

// The frozen-hash guard: refuse any change to a frozen lens; hash new frozen lenses.
let frozen = {};
try {
  frozen = JSON.parse(readFileSync(FROZEN, 'utf8'));
} catch {
  frozen = {};
}
const moved = [];
for (const mode of modes) {
  if (REGISTRY_MODES.has(mode)) continue;
  const hash = sha256(block(mode, merged[mode]));
  if (frozen[mode] === undefined) frozen[mode] = hash;
  else if (frozen[mode] !== hash) moved.push(mode);
}
if (moved.length > 0) {
  console.error(`refusing to write: frozen lens(es) would change: ${moved.join(', ')}`);
  console.error(`(an intended change deletes the key from ${FROZEN} in the same reviewed change)`);
  process.exit(1);
}
const frozenBody = Object.keys(frozen)
  .sort()
  .map((mode) => `  ${JSON.stringify(mode)}: ${JSON.stringify(frozen[mode])}`)
  .join(',\n');
writeFileSync(FROZEN, `{\n${frozenBody}\n}\n`);

const body = modes.map((mode) => block(mode, merged[mode])).join(',\n');
writeFileSync(SNAPSHOT, `{\n${body}\n}\n`);

const changed = Object.keys(updates).sort();
console.log(`ng test exit code ${run.status}; ${changed.length} lens(es) updated: ${changed.join(', ') || '(none)'}`);
console.log(`${SNAPSHOT} now holds ${modes.length} lens(es); ${FROZEN} freezes ${Object.keys(frozen).length}.`);
if (modes.length !== EXPECTED_MODES) {
  console.error(`expected ${EXPECTED_MODES} lenses; check the ng test output:`);
  console.error(output.split('\n').slice(-40).join('\n'));
  process.exit(1);
}
