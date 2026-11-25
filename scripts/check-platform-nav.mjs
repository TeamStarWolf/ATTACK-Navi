// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Offline gate for the vendored TeamStarWolf platform menu
// (`src/assets/platform-nav.json`, a byte-identical copy of the canonical file the
// front site publishes). It runs beside gen-facts/check-facts in CI and asserts:
//   1. the file is valid JSON, ASCII-only, LF line endings (so it stays byte-identical
//      to the canonical LF/ASCII file);
//   2. nesting: the `bookmarks` item may nest two levels of sub-entries (category, then
//      either links or a subsection, then links); every other item stays one level deep.
//      Each bookmarks list is capped at 16 entries, every other menu at 14;
//   3. addresses: every href that is NOT an external bookmarks leaf obeys the four-host
//      rule (https on teamstarwolf.com / library.teamstarwolf.com / teamstarwolf.github.io
//      / github.com, github.com only under /TeamStarWolf); an external bookmarks leaf
//      (a leaf flagged `"external": true` with no `menu`) obeys the outside-link rule.
//      The external flag is allowed ONLY on a bookmarks leaf;
//   4. the ATT&CK-Navi block equals the nav rail's workspace catalog, in order
//      (label and the `#/route` deep-link), so a renamed or reordered workspace is caught;
//   5. every `pending` entry is enumerated (printed), and the render filter that drops
//      them is wired (`visiblePlatformItems` in models/platform-nav.ts). The unit spec
//      proves at the DOM level that no pending entry reaches the template.
//
// It does NOT reach the network, and it does NOT probe the 291 outside addresses: it only
// validates their shape on the raw string. Drift between this copy and the canonical
// published file is caught by the scheduled workflow (.github/workflows/platform-nav-sync.yml),
// which fetches the URL, compares byte-for-byte, and opens a pull request on drift.
//
// Usage: node scripts/check-platform-nav.mjs [--root DIR]

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ASSET = 'src/assets/platform-nav.json';
const RAIL = 'src/app/components/nav-rail/nav-rail.component.ts';
const MODEL = 'src/app/models/platform-nav.ts';

// Address allow-list for every internal href. https only; host must be one of these; a
// github.com link must be under the TeamStarWolf org.
const ALLOWED_HOSTS = new Set(['teamstarwolf.com', 'library.teamstarwolf.com', 'teamstarwolf.github.io', 'github.com']);

// Panel caps: a bookmarks list may hold up to 16 entries (the generator fails above it);
// every other menu stays at 14 (panels do not scroll above the fold).
const BOOKMARKS_CAP = 16;
const MENU_CAP = 14;

/**
 * True if the RAW href's path (before ? or #) has a "." or ".." segment, plain or
 * percent-encoded (%2e / %2E, in any mix). Checked on the raw string, not the URL
 * constructor's normalised pathname, so the file never carries a traversal form that a
 * browser would resolve in a way that slips past the github.com path-prefix test
 * (e.g. `/TeamStarWolf/./repo` normalises to `/TeamStarWolf/repo`).
 */
export function hasDotSegment(href) {
  const beforeFragment = href.split('#')[0].split('?')[0];
  const schemeEnd = beforeFragment.indexOf('://');
  if (schemeEnd < 0) return false;
  const afterAuthorityStart = beforeFragment.indexOf('/', schemeEnd + 3);
  if (afterAuthorityStart < 0) return false;
  const rawPath = beforeFragment.slice(afterAuthorityStart);
  for (const seg of rawPath.split('/')) {
    const decoded = seg.replace(/%2e/gi, '.');
    if (decoded === '.' || decoded === '..') return true;
  }
  return false;
}

/**
 * True if a host has a malformed DNS label: an empty label (a double dot or a trailing dot),
 * or a label that starts or ends with a hyphen. `new URL` keeps all of these verbatim, so
 * both address rules must reject them.
 */
export function badHostLabels(host) {
  for (const label of host.split('.')) {
    if (label === '') return true;
    if (label.startsWith('-') || label.endsWith('-')) return true;
  }
  return false;
}

/**
 * Returns an error string if an href is not an allowed INTERNAL address, else null.
 * Unchanged from version 5: every href that is not an external bookmarks leaf goes
 * through this exact rule.
 */
export function hrefError(href) {
  if (typeof href !== 'string') return `not a string: ${String(href)}`;
  // A backslash anywhere is rejected: browsers treat "\" as "/" for special schemes, which
  // can rewrite the authority or path. The file must never carry one.
  if (href.includes('\\')) return `backslash in address: ${href}`;
  let u;
  try {
    u = new URL(href);
  } catch {
    return `not a valid URL: ${href}`;
  }
  if (u.protocol !== 'https:') return `not https: ${href}`;
  // Userinfo ("user:pass@host") can disguise the real host; disallow it outright.
  if (u.username !== '' || u.password !== '') return `credentials in address: ${href}`;
  // An explicit port is a different origin.
  if (u.port !== '') return `explicit port not allowed: ${href}`;
  if (badHostLabels(u.hostname)) return `malformed host label: ${href}`;
  if (!ALLOWED_HOSTS.has(u.hostname)) return `host not allowed (${u.hostname}): ${href}`;
  if (hasDotSegment(href)) return `dot path segment not allowed: ${href}`;
  if (u.hostname === 'github.com' && u.pathname !== '/TeamStarWolf' && !u.pathname.startsWith('/TeamStarWolf/')) {
    return `github.com path must be /TeamStarWolf or under /TeamStarWolf/: ${href}`;
  }
  return null;
}

/**
 * Returns an error string if an href is not an allowed EXTERNAL bookmarks leaf, else null.
 * The outside-link rule (version 6): https; no userinfo, no port, no backslash, no
 * whitespace or control character; no `.`/`..` path segment (plain or `%2e`), and no `%2f`
 * or `%5c` in the path, tested on the path alone; an ASCII DNS host with at least one dot
 * (no IP literal, no single-label host, no punycode); at most 512 characters; and NOT an
 * address the internal four-host rule would accept (an internal address wearing the flag
 * is rejected as external).
 */
export function hrefErrorExternal(href) {
  if (typeof href !== 'string') return `not a string: ${String(href)}`;
  if (href.length > 512) return `address longer than 512 characters: ${href.slice(0, 60)}...`;
  if (href.includes('\\')) return `backslash in address: ${href}`;
  // No whitespace or control character anywhere (space, tab, CR, LF, other C0, DEL).
  if (/[\u0000- \u007f]/.test(href)) return `whitespace or control character in address: ${JSON.stringify(href)}`;
  // No character above 0x7e anywhere. The file is ASCII, but a `\u` escape can still put a
  // non-ASCII character into the parsed string; reject it on the parsed value.
  if ([...href].some((ch) => ch.codePointAt(0) > 0x7e)) return `non-ASCII character in address: ${JSON.stringify(href)}`;
  // Hosts a browser reads as an IP address. Checked on the RAW host (before new URL, which
  // normalises some shorthands and rejects others), so the rule holds across stacks that
  // parse differently: a real host ends in an alphabetic label, never one that is all digits
  // or begins "0x" (so 127.1, 0x7f.0.0.1, 1.2.3, 1.2.3.0x7f and the like are all rejected).
  const rawAuthority = href.slice(href.indexOf('://') + 3).split(/[/?#]/)[0];
  const rawHost = (rawAuthority.split('@').pop() ?? '').replace(/:[0-9]*$/, '');
  const rawLast = rawHost.split('.').pop() ?? '';
  if (/^\d+$/.test(rawLast) || /^0x/i.test(rawLast)) return `host a browser reads as an IP address: ${href}`;
  let u;
  try {
    u = new URL(href);
  } catch {
    return `not a valid URL: ${href}`;
  }
  if (u.protocol !== 'https:') return `not https: ${href}`;
  if (u.username !== '' || u.password !== '') return `credentials in address: ${href}`;
  if (u.port !== '') return `explicit port not allowed: ${href}`;
  if (hasDotSegment(href)) return `dot path segment not allowed: ${href}`;
  // %2f (encoded "/") and %5c (encoded "\") in the path can smuggle a segment boundary.
  const rawPath = href.split('#')[0].split('?')[0].slice(href.indexOf('://') + 3);
  const pathOnly = rawPath.slice(rawPath.indexOf('/') >= 0 ? rawPath.indexOf('/') : rawPath.length);
  if (/%2f/i.test(pathOnly) || /%5c/i.test(pathOnly)) return `encoded slash/backslash in path not allowed: ${href}`;
  // Host: an ASCII DNS name with at least one dot. No IP literal, no single label, no punycode.
  const host = u.hostname;
  if (u.href.includes('[') || host.includes(':')) return `IP literal host not allowed: ${href}`;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return `IP literal host not allowed: ${href}`;
  if (!/^[a-z0-9.-]+$/i.test(host)) return `non-ASCII or invalid host: ${href}`;
  if (badHostLabels(host)) return `malformed host label: ${href}`;
  if (!host.includes('.')) return `single-label host not allowed: ${href}`;
  if (host.split('.').some((label) => label.toLowerCase().startsWith('xn--'))) return `punycode host not allowed: ${href}`;
  // And it must NOT be an address the internal four-host rule would accept.
  if (hrefError(href) === null) return `internal address wearing the external flag: ${href}`;
  return null;
}

/** Every href in the menu, including `home`, in document order (used by callers/tests). */
export function allHrefs(nav) {
  const out = [];
  if (nav.home?.href !== undefined) out.push(nav.home.href);
  const walk = (entries) => {
    for (const e of entries ?? []) {
      if (e.href !== undefined) out.push(e.href);
      walk(e.menu);
    }
  };
  for (const item of nav.items ?? []) {
    if (item.href !== undefined) out.push(item.href);
    walk(item.menu);
  }
  return out;
}

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
  const walk = (entries, trail) => {
    for (const e of entries ?? []) {
      if (e.pending !== undefined) out.push([...trail, e.label].join(' > '));
      walk(e.menu, [...trail, e.label]);
    }
  };
  for (const item of nav.items ?? []) walk(item.menu, [item.label]);
  return out;
}

/**
 * Walk every item's menu and return structural + address errors:
 *   - the external flag only on a bookmarks leaf (not elsewhere, not on a parent);
 *   - nesting depth (bookmarks up to a leaf at level 3; every other item up to level 2);
 *   - the per-list cap (16 inside bookmarks, 14 elsewhere);
 *   - each href by the rule that applies to it (internal, or the external-leaf rule for a
 *     flagged bookmarks leaf).
 * Pure: takes the parsed nav, so the tests can feed hostile fixtures without touching disk.
 */
export function collectMenuErrors(nav) {
  const errors = [];
  for (const item of nav.items ?? []) {
    const isBookmarks = item.id === 'bookmarks';
    const cap = isBookmarks ? BOOKMARKS_CAP : MENU_CAP;
    const maxDepth = isBookmarks ? 3 : 2; // the deepest level that may still hold entries

    if (typeof item.href === 'string') {
      const e = hrefError(item.href);
      if (e) errors.push(`"${item.label}": ${e}`);
    }

    const walk = (entries, depth, trail) => {
      if (!Array.isArray(entries)) return;
      if (entries.length > cap) {
        errors.push(`"${trail}" has ${entries.length} entries (cap ${cap})`);
      }
      for (const entry of entries) {
        const here = `${trail} > ${entry.label}`;
        const hasChildren = Array.isArray(entry.menu);

        // The external flag is allowed only on a bookmarks LEAF.
        if (entry.external === true) {
          if (!isBookmarks) errors.push(`"${here}" is flagged external outside Bookmarks`);
          else if (hasChildren) errors.push(`"${here}" is flagged external but has children`);
        }

        // Nesting depth.
        if (hasChildren) {
          if (depth >= maxDepth) errors.push(`"${here}" nests deeper than allowed for this item`);
          else walk(entry.menu, depth + 1, here);
        }

        // Address: the external-leaf rule for a flagged bookmarks leaf, else the internal rule.
        const isExternalLeaf = isBookmarks && entry.external === true && !hasChildren;
        const err = isExternalLeaf ? hrefErrorExternal(entry.href) : hrefError(entry.href);
        if (err) errors.push(`${isExternalLeaf ? 'external ' : ''}"${here}": ${err}`);
      }
    };

    walk(item.menu ?? [], 1, item.label);
  }
  return errors;
}

/**
 * Byte-level errors: a CR (the file must be LF-only — the canonical URL is at times served
 * with CRLF from a Windows deploy, and the scheduled sync must never copy that in) or any
 * non-ASCII byte. Returns an array of messages.
 */
export function rawBytesErrors(raw) {
  const out = [];
  if (raw.includes(0x0d)) out.push('contains CR (must be LF-only to stay byte-identical to the canonical file)');
  if (raw.find((b) => b > 0x7f) !== undefined) {
    out.push('contains a non-ASCII byte (the canonical file is ASCII; percent-encode non-ASCII in addresses)');
  }
  return out;
}

export function checkPlatformNav(root = '.') {
  const errors = [];
  const abs = (p) => join(root, p);

  // 1. bytes: ASCII, LF, valid JSON
  const raw = readFileSync(abs(ASSET));
  for (const m of rawBytesErrors(raw)) errors.push(`${ASSET}: ${m}`);
  let nav;
  try {
    nav = JSON.parse(raw.toString('utf8'));
  } catch (e) {
    return { ok: false, errors: [`${ASSET}: invalid JSON — ${e.message}`], pending: [] };
  }
  if (typeof nav.version !== 'number') errors.push(`${ASSET}: missing numeric "version"`);
  if (!Array.isArray(nav.items)) errors.push(`${ASSET}: missing "items" array`);

  // 2-3. nesting, caps, external placement, and every address by its applicable rule.
  for (const e of collectMenuErrors(nav)) errors.push(`${ASSET}: ${e}`);
  // `home` is always an internal address.
  if (nav.home?.href !== undefined) {
    const he = hrefError(nav.home.href);
    if (he) errors.push(`${ASSET}: home: ${he}`);
  }

  // 4. ATT&CK-Navi block equals the rail catalog, in order
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

  // 5. the render filter is wired (the spec proves the DOM-level result)
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
    console.log('check-platform-nav: src/assets/platform-nav.json is ASCII/LF, nests within the rule (bookmarks two levels, others one), every address passes its rule, and its ATT&CK-Navi block matches the rail catalog.');
    process.exit(0);
  }
  console.error('check-platform-nav: FAILED');
  for (const e of errors) console.error('  - ' + e);
  process.exit(1);
}
