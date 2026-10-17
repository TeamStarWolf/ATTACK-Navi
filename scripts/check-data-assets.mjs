#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Fails when a file or folder directly under src/assets/data ships in the build
// but no application code reads it. An entry counts as read when a non-spec
// TypeScript file under src/app names it in a string literal as
// `assets/data/<entry>`. The source inventory (services/source-inventory.ts)
// and the test helpers under src/app/testing do not count: they describe an
// asset, they do not load it.
//
// An entry the app serves for a person to fetch by hand, rather than one it
// reads itself, goes in SERVED_UNREAD with the reason. A listed entry that
// the code starts to read, or that no longer exists, also fails, so the list
// stays current.
//
//   node scripts/check-data-assets.mjs              check this repository
//   node scripts/check-data-assets.mjs --root DIR   check DIR instead

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, dirname, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const DATA_DIR = 'src/assets/data';
export const CODE_DIR = 'src/app';

/** Entries shipped for a person to import by hand, each with where that is documented. */
export const SERVED_UNREAD = {
  'lylat-mission-layers':
    'per-mission ATT&CK Navigator layers served for manual Import Layer (docs/LIBRARY_LAYERS.md)',
};

const EXCLUDED_CODE = new Set(['src/app/services/source-inventory.ts']);

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

const posix = (p) => p.split(sep).join('/');
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Non-spec application TypeScript that can load an asset. */
export function codeFiles(root) {
  return walk(join(root, CODE_DIR))
    .map((f) => posix(relative(root, f)))
    .filter((f) => f.endsWith('.ts') && !f.endsWith('.spec.ts'))
    .filter((f) => !f.startsWith(`${CODE_DIR}/testing/`) && !EXCLUDED_CODE.has(f));
}

/** Entries under src/assets/data, each with the code files that read it. */
export function scanAssets(root) {
  const entries = readdirSync(join(root, DATA_DIR)).sort();
  const code = codeFiles(root).map((f) => ({ file: f, text: readFileSync(join(root, f), 'utf8') }));
  return entries.map((entry) => {
    // A string literal (quote or backtick) whose text names assets/data/<entry>
    // as a whole path segment.
    const re = new RegExp(`['"\`][^'"\`\\n]*assets/data/${escape(entry)}(?![A-Za-z0-9._-])`);
    return { entry, readBy: code.filter((c) => re.test(c.text)).map((c) => c.file) };
  });
}

/** Problems: unread entries not in SERVED_UNREAD, and SERVED_UNREAD rows that are stale. */
export function checkAssets(root, servedUnread = SERVED_UNREAD) {
  const scanned = scanAssets(root);
  const names = new Set(scanned.map((s) => s.entry));
  const problems = [];
  for (const { entry, readBy } of scanned) {
    if (!readBy.length && !(entry in servedUnread)) {
      problems.push(`${DATA_DIR}/${entry} ships but no code under ${CODE_DIR} reads it: delete it, or list it in SERVED_UNREAD with the reason`);
    }
    if (readBy.length && entry in servedUnread) {
      problems.push(`${DATA_DIR}/${entry} is read by ${readBy.join(', ')}: remove it from SERVED_UNREAD`);
    }
  }
  for (const entry of Object.keys(servedUnread)) {
    if (!names.has(entry)) problems.push(`SERVED_UNREAD names ${DATA_DIR}/${entry}, which does not exist`);
  }
  return { scanned, problems };
}

function main(argv) {
  const at = argv.indexOf('--root');
  const root = at >= 0 ? resolve(argv[at + 1]) : resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const { scanned, problems } = checkAssets(root);
  if (problems.length) {
    for (const p of problems) console.error(`check-data-assets: ${p}`);
    return 1;
  }
  console.log(`check-data-assets: ${scanned.length} entries under ${DATA_DIR}, each read by app code or listed as served for manual import`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) process.exit(main(process.argv.slice(2)));
