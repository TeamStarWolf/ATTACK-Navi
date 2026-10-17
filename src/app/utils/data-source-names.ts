// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// ATT&CK v18+ names a data component's source by its log sources
// (x_mitre_log_sources[].name), and the upstream bundles spell some of them
// two ways: 'macos:unifiedlog' on hundreds of entries and 'macOS:unifiedlog'
// on one, 'NSM:Flow' and 'NSM:FLow', and so on. Read literally, one source
// shows up twice in the data-source filter and the data-source panel, and a
// filter on one spelling misses the components filed under the other. The
// names are therefore compared case-insensitively and each one is shown in a
// single spelling (plan epic E1.6).

/** The case-insensitive identity of a data-source name. */
export function dataSourceKey(name: string): string {
  return name.trim().toLowerCase();
}

/** True when two data-source names denote the same source. */
export function sameDataSource(a: string | null | undefined, b: string | null | undefined): boolean {
  if (a == null || b == null) return false;
  return dataSourceKey(a) === dataSourceKey(b);
}

/**
 * One spelling per case-insensitive name: the spelling that occurs most often in
 * `names` (every occurrence counts), ties broken by ordinal string order so the
 * choice never depends on the order of the bundle. Empty names are ignored.
 * Returns a map from {@link dataSourceKey} to that spelling.
 */
export function canonicalDataSourceSpellings(names: Iterable<string>): Map<string, string> {
  const counts = new Map<string, Map<string, number>>();
  for (const raw of names) {
    const name = (raw ?? '').trim();
    if (!name) continue;
    const key = dataSourceKey(name);
    let spellings = counts.get(key);
    if (!spellings) counts.set(key, (spellings = new Map()));
    spellings.set(name, (spellings.get(name) ?? 0) + 1);
  }
  const canonical = new Map<string, string>();
  for (const [key, spellings] of counts) {
    let best = '';
    let bestCount = -1;
    for (const [spelling, count] of spellings) {
      if (count > bestCount || (count === bestCount && spelling < best)) {
        best = spelling;
        bestCount = count;
      }
    }
    canonical.set(key, best);
  }
  return canonical;
}

/** The distinct data-source names in `names`, one per case-insensitive name, in canonical spelling, in ordinal order. */
export function distinctDataSourceNames(names: Iterable<string>): string[] {
  return [...canonicalDataSourceSpellings(names).values()].sort();
}
