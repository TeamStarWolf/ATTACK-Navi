// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Regenerates src/app/testing/__snapshots__/lens-snapshots.json, the committed
// score maps of the 33 heatmap lenses (see src/app/testing/lens-snapshots.spec.ts).
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
// Usage: node scripts/update-lens-snapshots.mjs
// Runs `npx ng test` for the one spec (ChromeHeadless); exits non-zero if the
// test run produced no snapshot lines and the snapshot file is incomplete.

import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const SNAPSHOT = 'src/app/testing/__snapshots__/lens-snapshots.json';
const SPEC = 'src/app/testing/lens-snapshots.spec.ts';
const EXPECTED_MODES = 33;

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

const modes = Object.keys(merged).sort();
const body = modes
  .map((mode) => {
    const entries = Object.keys(merged[mode])
      .sort()
      .map((id) => `    ${JSON.stringify(id)}: ${JSON.stringify(merged[mode][id])}`);
    return `  ${JSON.stringify(mode)}: {\n${entries.join(',\n')}\n  }`;
  })
  .join(',\n');
writeFileSync(SNAPSHOT, `{\n${body}\n}\n`);

const changed = Object.keys(updates).sort();
console.log(`ng test exit code ${run.status}; ${changed.length} lens(es) updated: ${changed.join(', ') || '(none)'}`);
console.log(`${SNAPSHOT} now holds ${modes.length} lens(es).`);
if (modes.length !== EXPECTED_MODES) {
  console.error(`expected ${EXPECTED_MODES} lenses; check the ng test output:`);
  console.error(output.split('\n').slice(-40).join('\n'));
  process.exit(1);
}
