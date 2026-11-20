// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Offline gate for the vendored TeamStarWolf platform menu
// (`src/assets/platform-nav.json`, a byte-identical copy of the canonical file the
// front site publishes). It runs beside gen-facts/check-facts in CI and asserts:
//   1. the file is valid JSON, ASCII-only, LF line endings (so it stays byte-identical
//      to the canonical LF/ASCII file);
//   2. sub-menus are one level deep and no deeper;
//   3. the ATT&CK-Navi block equals the nav rail's workspace catalog, in order
//      (label and the `#/route` deep-link), so a renamed or reordered workspace is caught;
//   4. every `pending` entry is enumerated (printed), and the render filter that drops
//      them is wired (`visiblePlatformItems` in models/platform-nav.ts). The unit spec
//      proves at the DOM level that no pending entry reaches the template.
//
// It does NOT reach the network. Drift between this copy and the canonical published
// file is caught by the scheduled workflow (.github/workflows/platform-nav-sync.yml),
// which fetches the URL, compares, and opens a pull request on drift.
//
// Usage: node scripts/check-platform-nav.mjs [--root DIR]

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ASSET = 'src/assets/platform-nav.json';
const RAIL = 'src/app/components/nav-rail/nav-rail.component.ts';
const MODEL = 'src/app/models/platform-nav.ts';

/** Parse the nav rail's CATALOG into [{ route, label }] in file order. */
export function extractRailCatalog(railSource) {
  const re = /'(\/[a-z0-9-]+)':\s*\{\s*route:\s*'\/[a-z0-9-]+',\s*icon:\s*'[^']*',\s*label:\s*'([^']+)'\s*\}/g;
  const out = [];
  let m;
  while ((m = re.exec(railSource)) !== null) out.push({ route: m[1], label: m[2] });
  return out;
}

/** Collect every entry (any level) that carries a `pending` note. */
export function collectPending(nav) {
  const out = [];
  for (const item of nav.items ?? []) {
    for (const entry of item.menu ?? []) {
      if (entry.pending !== undefined) out.push(`${item.label} > ${entry.label}`);
      for (const sub of entry.menu ?? []) {
        if (sub.pending !== undefined) out.push(`${item.label} > ${entry.label} > ${sub.label}`);
      }
    }
  }
  return out;
}

export function checkPlatformNav(root = '.') {
  const errors = [];
  const abs = (p) => join(root, p);

  // 1. bytes: ASCII, LF, valid JSON
  const raw = readFileSync(abs(ASSET));
  if (raw.includes(0x0d)) errors.push(`${ASSET}: contains CR (must be LF-only to stay byte-identical to the canonical file)`);
  const nonAscii = raw.find((b) => b > 0x7f);
  if (nonAscii !== undefined) errors.push(`${ASSET}: contains a non-ASCII byte (the canonical file is ASCII; percent-encode non-ASCII in addresses)`);
  let nav;
  try {
    nav = JSON.parse(raw.toString('utf8'));
  } catch (e) {
    return { ok: false, errors: [`${ASSET}: invalid JSON — ${e.message}`], pending: [] };
  }
  if (typeof nav.version !== 'number') errors.push(`${ASSET}: missing numeric "version"`);
  if (!Array.isArray(nav.items)) errors.push(`${ASSET}: missing "items" array`);

  // 2. nesting one level deep and no deeper; no menu longer than the cap (panels do not
  //    scroll, so a menu must fit — the front site's schema test caps it at the same number)
  const MAX_ENTRIES = 14;
  for (const item of nav.items ?? []) {
    if ((item.menu ?? []).length > MAX_ENTRIES) {
      errors.push(`${ASSET}: "${item.label}" has ${item.menu.length} entries (cap ${MAX_ENTRIES}; panels do not scroll)`);
    }
    for (const entry of item.menu ?? []) {
      if ((entry.menu ?? []).length > MAX_ENTRIES) {
        errors.push(`${ASSET}: "${item.label} > ${entry.label}" has ${entry.menu.length} sub-entries (cap ${MAX_ENTRIES})`);
      }
      for (const sub of entry.menu ?? []) {
        if (Array.isArray(sub.menu)) {
          errors.push(`${ASSET}: "${item.label} > ${entry.label} > ${sub.label}" nests deeper than one level`);
        }
      }
    }
  }

  // 3. ATT&CK-Navi block equals the rail catalog, in order
  const catalog = extractRailCatalog(readFileSync(abs(RAIL), 'utf8'));
  const navi = (nav.items ?? []).find((i) => i.id === 'navi');
  if (!navi) {
    errors.push(`${ASSET}: no item with id "navi"`);
  } else if (catalog.length === 0) {
    errors.push(`${RAIL}: could not parse the workspace CATALOG`);
  } else {
    const menu = navi.menu ?? [];
    if (menu.length !== catalog.length) {
      errors.push(`Navi block has ${menu.length} entries; the rail catalog has ${catalog.length}`);
    }
    const n = Math.min(menu.length, catalog.length);
    for (let i = 0; i < n; i++) {
      if (menu[i].label !== catalog[i].label) {
        errors.push(`Navi entry ${i + 1}: label "${menu[i].label}" != rail "${catalog[i].label}"`);
      }
      const wantSuffix = `#${catalog[i].route}`;
      if (typeof menu[i].href !== 'string' || !menu[i].href.endsWith(wantSuffix)) {
        errors.push(`Navi entry "${menu[i].label}": href "${menu[i].href}" should end with "${wantSuffix}"`);
      }
    }
  }

  // 4. the render filter is wired (the spec proves the DOM-level result)
  const model = readFileSync(abs(MODEL), 'utf8');
  if (!/pending\s*===\s*undefined/.test(model) || !/export function visiblePlatformItems/.test(model)) {
    errors.push(`${MODEL}: the pending-entry filter (visiblePlatformItems / pending === undefined) is missing`);
  }

  const pending = collectPending(nav);
  return { ok: errors.length === 0, errors, pending };
}

// CLI
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const rootIdx = process.argv.indexOf('--root');
  const root = rootIdx !== -1 ? process.argv[rootIdx + 1] : '.';
  const { ok, errors, pending } = checkPlatformNav(root);
  if (pending.length) {
    console.log(`check-platform-nav: ${pending.length} pending entr${pending.length === 1 ? 'y is' : 'ies are'} held back (not shipped): ${pending.join('; ')}`);
  }
  if (ok) {
    console.log('check-platform-nav: src/assets/platform-nav.json is ASCII/LF, nests one level, and its ATT&CK-Navi block matches the rail catalog.');
    process.exit(0);
  }
  console.error('check-platform-nav: FAILED');
  for (const e of errors) console.error('  - ' + e);
  process.exit(1);
}
