// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * The shared TeamStarWolf platform menu, vendored as `src/assets/platform-nav.json`
 * (a byte-identical copy of the canonical file the front site publishes). The menu
 * is edited at the source first, then re-copied here; `scripts/check-platform-nav.mjs`
 * gates the copy (byte-identical, ASCII, nesting one level deep, the ATT&CK-Navi block
 * equal to the nav rail's catalog, and the pending entries enumerated).
 *
 * An entry with a `pending` note is agreed but not yet reachable; a site must not ship
 * it until the note is removed. Sub-menus are one level deep and no deeper.
 */

export interface PlatformSubEntry {
  label: string;
  href: string;
  pending?: string;
}

export interface PlatformEntry {
  label: string;
  href: string;
  pending?: string;
  menu?: PlatformSubEntry[];
}

export interface PlatformItem {
  id: string;
  label: string;
  href: string;
  /** A documentation note in the source file; not rendered. */
  menu_source?: string;
  menu?: PlatformEntry[];
}

export interface PlatformNav {
  about: string;
  version: number;
  home: { label: string; href: string; note?: string };
  items: PlatformItem[];
}

/** A sub-entry ready for the template. */
export interface ViewSubEntry {
  label: string;
  href: string;
}

/** A menu entry ready for the template, with its (already filtered) sub-entries. */
export interface ViewEntry {
  label: string;
  href: string;
  children: ViewSubEntry[];
}

/** A top-level bar item ready for the template. */
export interface ViewItem {
  id: string;
  label: string;
  href: string;
  entries: ViewEntry[];
}

const shippable = (e: { pending?: string }): boolean => e.pending === undefined;

/**
 * The menu the bar renders: every `pending` entry removed at both levels, and nesting
 * capped at one level (a sub-entry's own `menu`, were one ever added, is ignored). Pure,
 * so the component and the unit spec agree on exactly what reaches the template.
 */
export function visiblePlatformItems(nav: PlatformNav): ViewItem[] {
  return nav.items.map((item) => ({
    id: item.id,
    label: item.label,
    href: item.href,
    entries: (item.menu ?? []).filter(shippable).map((entry) => ({
      label: entry.label,
      href: entry.href,
      children: (entry.menu ?? []).filter(shippable).map((sub) => ({
        label: sub.label,
        href: sub.href,
      })),
    })),
  }));
}

/** Labels held back by a `pending` note, at either level — for the check and the spec. */
export function pendingLabels(nav: PlatformNav): string[] {
  const out: string[] = [];
  for (const item of nav.items) {
    for (const entry of item.menu ?? []) {
      if (entry.pending !== undefined) out.push(entry.label);
      for (const sub of entry.menu ?? []) {
        if (sub.pending !== undefined) out.push(sub.label);
      }
    }
  }
  return out;
}
