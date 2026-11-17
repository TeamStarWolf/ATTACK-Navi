#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Losslessly minify the JSON data assets in a BUILT output directory: parse
// each file and re-serialize it without the pretty-print whitespace. The
// parsed value is identical, so the app reads exactly the same data; only the
// bytes shrink. The upstream ATT&CK STIX bundles under src/assets/data are the
// big ones (enterprise-attack.json alone ships ~55 MB of 4-space-indented
// JSON), and they are offline fallbacks the app fetches when the live MITRE
// feed is blocked (common on SOC networks that block raw.githubusercontent.com),
// so slimming the deployed copy is a real transfer / parse / IndexedDB win.
//
// This runs against the BUILD OUTPUT only — the source files stay exactly as
// MITRE publishes them (pretty-printed), so the refresh-data pipeline and the
// data-asset checks are untouched and the source diff stays reviewable.
//
//   node scripts/minify-build-assets.mjs <dir>
//
// <dir> is a built assets/data directory, e.g.
//   dist/mitre-mitigation-navigator/browser/assets/data
// Every *.json under it is minified in place. Invalid JSON is a hard error
// (a corrupt data asset should fail the build, not ship).

import { readdirSync, statSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

/** Every *.json file under dir, recursively, in sorted order. */
export function findJsonFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...findJsonFiles(full));
    else if (name.endsWith('.json')) out.push(full);
  }
  return out;
}

/**
 * Minify one JSON file in place. Returns { before, after, changed }.
 * Throws if the file is not valid JSON.
 */
export function minifyJsonFile(file) {
  const raw = readFileSync(file, 'utf8');
  const before = Buffer.byteLength(raw);
  let min;
  try {
    min = JSON.stringify(JSON.parse(raw));
  } catch (err) {
    throw new Error(`Invalid JSON in ${file}: ${err.message}`);
  }
  const after = Buffer.byteLength(min);
  // Only rewrite when it actually gets smaller (already-minified files are left
  // byte-for-byte alone, so the step is idempotent).
  if (after < before) {
    writeFileSync(file, min);
    return { before, after, changed: true };
  }
  return { before, after: before, changed: false };
}

/** Minify every *.json under dir. Returns a summary. */
export function minifyDir(dir) {
  const files = findJsonFiles(dir);
  let before = 0;
  let after = 0;
  let changed = 0;
  const biggest = [];
  for (const file of files) {
    const r = minifyJsonFile(file);
    before += r.before;
    after += r.after;
    if (r.changed) {
      changed++;
      biggest.push({ file, saved: r.before - r.after, before: r.before, after: r.after });
    }
  }
  biggest.sort((a, b) => b.saved - a.saved);
  return { count: files.length, changed, before, after, biggest };
}

const mb = (n) => `${(n / 1_048_576).toFixed(2)} MB`;

function main(argv) {
  const dir = argv[0];
  if (!dir) {
    console.error('usage: node scripts/minify-build-assets.mjs <built-assets/data-dir>');
    return 2;
  }
  let stat;
  try {
    stat = statSync(dir);
  } catch {
    console.error(`minify-build-assets: directory not found: ${dir}`);
    return 1;
  }
  if (!stat.isDirectory()) {
    console.error(`minify-build-assets: not a directory: ${dir}`);
    return 1;
  }

  const { count, changed, before, after, biggest } = minifyDir(dir);
  const saved = before - after;
  const pct = before > 0 ? ((saved / before) * 100).toFixed(1) : '0.0';

  for (const b of biggest.slice(0, 5)) {
    console.log(`  ${mb(b.before)} -> ${mb(b.after)}  ${b.file}`);
  }
  console.log(
    `minify-build-assets: ${changed}/${count} JSON assets minified in ${dir}; ` +
      `${mb(before)} -> ${mb(after)} (saved ${mb(saved)}, ${pct}%)`,
  );
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exit(main(process.argv.slice(2)));
}
