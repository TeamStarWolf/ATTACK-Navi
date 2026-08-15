// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * Pre-bootstrap migration of legacy share links to router URLs.
 *
 * Before the router existed, filter state lived directly in location.hash
 * (e.g. `#tech=T1059`, `#heat=kev&grp=G0016`). Under hash routing those
 * hashes would be parsed as (invalid) route paths and lost. This shim runs
 * synchronously in main.ts BEFORE bootstrapApplication so the router's
 * initial navigation sees a well-formed `#/path?query` URL.
 *
 * A hash is "legacy" iff it is non-empty and does not start with `#/`.
 * The e2e contract `#tech=T1059` → technique auto-select must keep working.
 */
export function rewriteLegacyHash(hash: string, storedViewMode: string | null): string | null {
  if (!hash || hash === '#') {
    // No hash at all: honour the pre-router library view-mode persistence once.
    return storedViewMode === 'library' ? '#/library' : null;
  }
  if (hash.startsWith('#/')) return null; // already a routed URL
  const legacyParams = hash.startsWith('#') ? hash.slice(1) : hash;
  // Shared-collection links (`#import=<base64>`) land on the collections
  // page, whose component offers the import dialog on init.
  if (/(^|&)import=/.test(legacyParams)) {
    return `#/library/collections?${legacyParams}`;
  }
  return `#/matrix?${legacyParams}`;
}

/** Storage key retired along with ViewModeService (library became a route). */
export const LEGACY_VIEW_MODE_KEY = 'attacknavi.viewMode';

/**
 * Apply the rewrite to the live URL. Returns true if a rewrite happened.
 * Uses history.replaceState so no extra history entry is created.
 */
export function applyLegacyHashShim(migrateViewMode = false): boolean {
  let storedViewMode: string | null = null;
  if (migrateViewMode) {
    try {
      storedViewMode = localStorage.getItem(LEGACY_VIEW_MODE_KEY);
    } catch {
      storedViewMode = null;
    }
  }
  const rewritten = rewriteLegacyHash(window.location.hash, storedViewMode);
  if (rewritten === null) return false;
  history.replaceState(null, '', window.location.pathname + window.location.search + rewritten);
  if (migrateViewMode && rewritten === '#/library') {
    try {
      localStorage.removeItem(LEGACY_VIEW_MODE_KEY);
    } catch {
      /* storage unavailable */
    }
  }
  return true;
}
