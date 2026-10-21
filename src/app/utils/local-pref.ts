// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * Per-browser shell preferences (drawer width, rail collapsed), stored the same
 * way the nav rail stores its workspace order: one localStorage key each, every
 * access wrapped in try/catch. Storage can be blocked (private mode, disabled
 * site data); a failed read returns null so the caller falls back to its
 * default, and a failed write leaves the in-memory value in place.
 */
export function readPref(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

/** Write a preference; `null` removes the key (the default applies again). */
export function writePref(key: string, value: string | null): void {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    /* storage unavailable: the value stays in memory for this session */
  }
}
