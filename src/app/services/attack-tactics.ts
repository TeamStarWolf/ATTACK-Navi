// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Tactic-currency helpers shared by every service that keys content on an
// ATT&CK tactic shortname.
//
// ATT&CK Enterprise v19 split `defense-evasion` (TA0005) into `stealth`
// (TA0005) and `defense-impairment` (TA0112). The bundled Mobile 18.1 matrix
// still uses `defense-evasion` and ICS uses `evasion`, so a static Enterprise
// list can never be right for every loaded domain. The rule is therefore:
// derive order and display names from the loaded `Domain.tactics` (which
// data.service sorts by the matrix `tactic_refs`), and resolve hand-written
// content tables through the alias map below so a table keyed on either
// generation of slugs serves every bundle.
import { Domain } from '../models/domain';

/** Enterprise ATT&CK v19 kill-chain order; used only when no Domain is loaded. */
export const ENTERPRISE_TACTIC_ORDER: readonly string[] = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'stealth',
  'defense-impairment',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

/**
 * Tactic shortnames that describe the same adversary objective across ATT&CK
 * generations and domains. Each entry lists every slug in the equivalence
 * class; lookups resolve in list order, so the current Enterprise slug wins.
 */
const TACTIC_EQUIVALENCE: readonly (readonly string[])[] = [
  // Enterprise <= v18 / Mobile 18.1 `defense-evasion` and ICS `evasion` were
  // split into `stealth` + `defense-impairment` in Enterprise v19.
  ['stealth', 'defense-impairment', 'defense-evasion', 'evasion'],
];

const ALIAS_INDEX: ReadonlyMap<string, readonly string[]> = (() => {
  const m = new Map<string, readonly string[]>();
  for (const group of TACTIC_EQUIVALENCE) {
    for (const slug of group) m.set(slug, group);
  }
  return m;
})();

/**
 * Every shortname that carries the same content as `slug`, starting with
 * `slug` itself. Unknown slugs resolve to themselves only.
 */
export function tacticAliases(slug: string): string[] {
  const group = ALIAS_INDEX.get(slug);
  if (!group) return [slug];
  return [slug, ...group.filter(s => s !== slug)];
}

/** True when the two shortnames name the same objective (directly or via alias). */
export function tacticsEquivalent(a: string, b: string): boolean {
  return a === b || tacticAliases(a).includes(b);
}

/**
 * Looks `slug` up in a content table keyed by tactic shortname, falling back
 * to any alias of the slug. Returns the matching key alongside the value so
 * callers can tell which generation of slug the table was written for.
 */
export function resolveTacticEntry<T>(
  table: Record<string, T>,
  slug: string,
): { key: string; value: T } | undefined {
  for (const candidate of tacticAliases(slug)) {
    if (Object.prototype.hasOwnProperty.call(table, candidate)) {
      return { key: candidate, value: table[candidate] };
    }
  }
  return undefined;
}

/**
 * Kill-chain order for the loaded domain: the matrix `tactic_refs` order as
 * parsed by data.service. Falls back to the Enterprise v19 list when no domain
 * is loaded (or the domain carries no tactics).
 */
export function tacticOrderFor(domain: Domain | null | undefined): string[] {
  const tactics = domain?.tactics ?? [];
  if (tactics.length === 0) return [...ENTERPRISE_TACTIC_ORDER];
  return [...tactics]
    .sort((a, b) => a.order - b.order)
    .map(t => t.shortname)
    .filter(s => !!s);
}

/**
 * Position of `slug` in `order`, resolving through aliases so a technique
 * tagged with a previous-generation slug still sorts into the right column.
 * Returns -1 when neither the slug nor any alias is in the order.
 */
export function tacticIndex(order: readonly string[], slug: string): number {
  for (const candidate of tacticAliases(slug)) {
    const idx = order.indexOf(candidate);
    if (idx >= 0) return idx;
  }
  return -1;
}

/** "credential-access" -> "Credential Access". */
export function tacticLabel(slug: string): string {
  return slug
    .split('-')
    .filter(w => w.length > 0)
    .map(w => w[0].toUpperCase() + w.slice(1))
    .join(' ');
}

/**
 * Display name for a tactic: the loaded domain's `x-mitre-tactic` name when
 * the slug (or an alias of it) is in the domain, otherwise a title-cased slug.
 */
export function tacticDisplayName(domain: Domain | null | undefined, slug: string): string {
  const tactics = domain?.tactics ?? [];
  for (const candidate of tacticAliases(slug)) {
    const hit = tactics.find(t => t.shortname === candidate);
    if (hit?.name) return hit.name;
  }
  return tacticLabel(slug);
}

/**
 * Whether a technique tagged with `techniqueTactics` belongs in the matrix
 * column `columnShortname`. A direct match always wins; a tag the loaded
 * domain does not know (e.g. `defense-evasion` saved under Enterprise v18)
 * is placed through its aliases, so legacy custom techniques land in the
 * Stealth and Defense Impairment columns instead of vanishing.
 */
export function techniqueBelongsToColumn(
  techniqueTactics: readonly string[],
  columnShortname: string,
  domainShortnames: ReadonlySet<string>,
): boolean {
  if (techniqueTactics.includes(columnShortname)) return true;
  return techniqueTactics.some(
    t => !domainShortnames.has(t) && tacticAliases(t).includes(columnShortname),
  );
}
