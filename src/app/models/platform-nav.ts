// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * The shared TeamStarWolf platform menu, vendored as `src/assets/platform-nav.json`
 * (a byte-identical copy of the canonical file the front site publishes). The menu
 * is edited at the source first, then re-copied here; `scripts/check-platform-nav.mjs`
 * gates the copy (byte-identical, ASCII, the nesting rule, the address rules, the
 * ATT&CK-Navi block equal to the nav rail's catalog, and the pending entries enumerated).
 *
 * Menu version 6: the item whose id is `bookmarks` nests two levels of sub-entries
 * (category, then either links or a subsection, then links); every other item stays one
 * level deep. A leaf inside bookmarks may point at an outside resource when it carries
 * `"external": true`; no other entry is external. An entry with a `pending` note is agreed
 * but not yet reachable and a site must not ship it until the note is removed.
 */

/** A menu entry at any depth. Only `bookmarks` leaves carry `external`. */
export interface PlatformSubEntry {
  label: string;
  href: string;
  pending?: string;
  external?: boolean;
  menu?: PlatformSubEntry[];
}

export interface PlatformEntry {
  label: string;
  href: string;
  pending?: string;
  external?: boolean;
  menu?: PlatformSubEntry[];
}

/** The `source` the bookmarks item records: the public snapshot it was generated from. */
export interface PlatformSource {
  repo: string;
  path: string;
  commit: string;
}

export interface PlatformItem {
  id: string;
  label: string;
  href: string;
  /** A documentation note in the source file; not rendered. */
  menu_source?: string;
  /** Only on the bookmarks item: the snapshot the subtree was generated from. Not rendered. */
  source?: PlatformSource;
  menu?: PlatformEntry[];
}

export interface PlatformNav {
  about: string;
  version: number;
  home: { label: string; href: string; note?: string };
  items: PlatformItem[];
}

/**
 * A node of the menu ready for the template, at any depth. `children` is empty for a leaf;
 * `external` is true only for an outside bookmarks leaf (rendered with target/rel/marker).
 */
export interface ViewNode {
  label: string;
  href: string;
  external: boolean;
  children: ViewNode[];
}

/** A top-level bar item ready for the template, with its (filtered) menu tree. */
export interface ViewItem {
  id: string;
  label: string;
  href: string;
  entries: ViewNode[];
}

const shippable = (e: { pending?: string }): boolean => e.pending === undefined;

/** Build one view node and its subtree, dropping every `pending` descendant. */
function toNode(entry: PlatformSubEntry): ViewNode {
  return {
    label: entry.label,
    href: entry.href,
    external: entry.external === true,
    children: (entry.menu ?? []).filter(shippable).map(toNode),
  };
}

/**
 * The menu the bar renders: every `pending` entry removed at every level. The full tree is
 * kept (bookmarks nests two levels; the `check-platform-nav` gate is what enforces that no
 * other item nests deeper). Pure, so the component and the unit spec agree on exactly what
 * reaches the template.
 */
export function visiblePlatformItems(nav: PlatformNav): ViewItem[] {
  return nav.items.map((item) => ({
    id: item.id,
    label: item.label,
    href: item.href,
    entries: (item.menu ?? []).filter(shippable).map(toNode),
  }));
}

/** Labels held back by a `pending` note, at any level — for the check and the spec. */
export function pendingLabels(nav: PlatformNav): string[] {
  const out: string[] = [];
  const walk = (entries: PlatformSubEntry[] | undefined): void => {
    for (const e of entries ?? []) {
      if (e.pending !== undefined) out.push(e.label);
      walk(e.menu);
    }
  };
  for (const item of nav.items) walk(item.menu);
  return out;
}
