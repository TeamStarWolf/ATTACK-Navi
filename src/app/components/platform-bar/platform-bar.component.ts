// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, ElementRef, HostListener, inject, signal } from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { IconComponent } from '../../shared/icons/icon.component';
import navData from '../../../assets/platform-nav.json';
import { PlatformNav, ViewItem, ViewNode, visiblePlatformItems } from '../../models/platform-nav';

/**
 * The universal TeamStarWolf platform bar (menu version 6): one menu every site shows in
 * its own stack, rendered here above the app toolbar. Menu only (no search, theme toggle
 * or app controls); its own `tsw-bar__` class names keep the app toolbar's `.brand-link`
 * and `.theme-btn` unique.
 *
 * Nesting: every item is one level deep except `bookmarks`, which nests two levels of
 * sub-entries (category, then either links or a subsection, then links). The template is
 * recursive over `ViewNode`, so a category and a subsection are built alike; the
 * `check-platform-nav` gate is what holds the data to the allowed depth.
 *
 * Desktop (>= 761px): a top-level menu opens on hover (and its own caret button with
 * aria-expanded opens it for keyboard/click); a node with children shows a right chevron
 * and opens them as a fly-out to the side. Only one path is open at a time; opening a
 * sibling closes the others. A fly-out flips left when its right edge would cross the
 * viewport and is pulled up (then scrolls inside itself) when its bottom would, at each
 * level independently. Keyboard: ArrowRight opens a fly-out and enters it; Escape closes
 * the deepest open level and returns focus to its caret, so repeated Escape walks out.
 * Mobile (<= 760px): one button opens an inline accordion; every level drops inline with
 * the same real-link-plus-caret split, the third level included.
 *
 * An external leaf (bookmarks only) is rendered with target="_blank",
 * rel="noopener noreferrer", a silent arrow marker and a visually hidden note, so its
 * accessible name ends "(opens in a new tab on an external site)".
 *
 * Source of record: `src/assets/platform-nav.json`, a byte-identical copy of the canonical
 * file the front site publishes; every `pending` entry is filtered before render
 * (`visiblePlatformItems`), which the spec and `scripts/check-platform-nav.mjs` assert.
 */

// Hover close delay (ms): close waits so a diagonal move into a fly-out does not shut it.
// It is timing, not motion, so it stands under prefers-reduced-motion. Open is immediate.
const OPEN_DELAY_MS = 0;
const CLOSE_DELAY_MS = 220;

// The leading "TeamStarWolf" wordmark before the Home item. Off for now to match the
// reference band (which starts at Home) and the owner's removal of the brand from the
// front-page header; the owner has not settled it, so the flag stays. The Home menu item
// is always present as the way back regardless.
const SHOW_WORDMARK = false;

/** How a fly-out is placed after measuring, keyed by its DOM id. */
interface FlyPlacement {
  left: boolean;
  up: number;
  maxH: number | null;
}

@Component({
  selector: 'app-platform-bar',
  standalone: true,
  imports: [IconComponent, NgTemplateOutlet],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './platform-bar.component.html',
  styleUrl: './platform-bar.component.scss',
})
export class PlatformBarComponent {
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);

  private readonly nav = navData as PlatformNav;
  /** The home brand target; the Home item in the menu is the always-present way back. */
  readonly home = this.nav.home;
  /** Whether the band shows the leading "TeamStarWolf" wordmark (open point; see flag). */
  readonly showWordmark = SHOW_WORDMARK;
  /** The menu, with pending entries removed, as a tree of nodes. */
  readonly items: ViewItem[] = visiblePlatformItems(this.nav);

  /** Which top-level panel is open on desktop (id), or null. */
  readonly openId = signal<string | null>(null);
  /**
   * The open fly-out chain under the current panel, as child indices. `[1]` = category 1's
   * fly-out is open; `[1, 2]` = category 1 then its subsection 2. A node's fly-out is open
   * when its path is a prefix of this, so one path shows at a time at every level.
   */
  readonly flyPath = signal<number[]>([]);
  /** Per-fly-out placement after measuring (flip-left, pull-up, scroll), keyed by DOM id. */
  readonly placement = signal<Record<string, FlyPlacement>>({});
  /** Whether the mobile drawer is open. */
  readonly mobileOpen = signal(false);
  /** Which mobile accordion sections are expanded, as a set of path keys (see mobileKey). */
  readonly mobilePaths = signal<Set<string>>(new Set());

  private openTimer?: ReturnType<typeof setTimeout>;
  private closeTimer?: ReturnType<typeof setTimeout>;

  panelId(id: string): string { return `tsw-panel-${id}`; }
  caretId(id: string): string { return `tsw-caret-${id}`; }
  flyoutId(itemId: string, path: number[]): string { return `tsw-flyout-${itemId}-${path.join('-')}`; }
  mobileSectionId(key: string): string { return `tsw-ms-${key}`; }

  isOpen(id: string): boolean { return this.openId() === id; }

  /** True when the fly-out owned by the node at `path` is on the open chain. */
  isFlyOpen(path: number[]): boolean {
    if (path.length === 0) return false;
    const chain = this.flyPath();
    if (path.length > chain.length) return false;
    return path.every((v, i) => chain[i] === v);
  }

  /** True when the node at `path` is the deepest open fly-out (its caret owns the tip). */
  private isFlyTip(path: number[]): boolean {
    const chain = this.flyPath();
    return chain.length === path.length && path.every((v, i) => chain[i] === v);
  }

  /** Hover is ignored on a coarse pointer (touch); taps carry it there via the buttons. */
  private hoverCapable(): boolean {
    return typeof window !== 'undefined' && (window.matchMedia ? window.matchMedia('(hover: hover)').matches : true);
  }

  // --- Desktop hover (fine pointers only) ---
  onItemEnter(id: string): void {
    if (!this.hoverCapable()) return;
    clearTimeout(this.closeTimer);
    this.openTimer = setTimeout(() => this.openMenu(id), OPEN_DELAY_MS);
  }

  onItemLeave(): void {
    if (!this.hoverCapable()) return;
    clearTimeout(this.openTimer);
    this.closeTimer = setTimeout(() => this.closeAll(), CLOSE_DELAY_MS);
  }

  /**
   * Hovering a node opens its fly-out (closing siblings and anything deeper); hovering a
   * leaf closes any fly-out open at the leaf's own level. Fine pointers only.
   */
  onNodeEnter(path: number[], hasChildren: boolean): void {
    if (!this.hoverCapable()) return;
    if (hasChildren) this.openFly(path);
    else this.flyPath.set(path.slice(0, -1));
  }

  /** Tap/click on a node's chevron (carries touch at desktop width). */
  toggleFly(path: number[]): void {
    if (this.isFlyOpen(path)) this.flyPath.set(path.slice(0, -1));
    else this.openFly(path);
  }

  // --- Open / close ---
  openMenu(id: string): void {
    this.openId.set(id);
    this.flyPath.set([]);
    this.placement.set({});
  }

  closeAll(): void {
    this.openId.set(null);
    this.flyPath.set([]);
    this.placement.set({});
  }

  /** Click/keyboard toggle on the top-level caret button. */
  toggle(id: string): void {
    clearTimeout(this.openTimer);
    clearTimeout(this.closeTimer);
    if (this.isOpen(id)) this.closeAll();
    else this.openMenu(id);
  }

  /** Open the fly-out of the node at `path`; then measure every open fly-out and place it. */
  openFly(path: number[]): void {
    this.flyPath.set([...path]);
    this.placement.set({}); // measure from the natural position
    setTimeout(() => this.measureFlyouts(), 0);
  }

  /**
   * Measure every open fly-out and record how to keep it on screen, each level independently:
   * flip left if its right edge crosses the viewport; pull it up if its bottom does; and
   * only if it still does not fit, let it scroll inside itself. At a viewport >= 600px high
   * nothing scrolls (the longest leaf list fits).
   */
  private measureFlyouts(): void {
    const next: Record<string, FlyPlacement> = {};
    const flyouts = this.host.nativeElement.querySelectorAll<HTMLElement>('.tsw-bar__flyout');
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    for (const fly of Array.from(flyouts)) {
      const rect = fly.getBoundingClientRect();
      const left = rect.right > vw - 8;
      let up = 0;
      let maxH: number | null = null;
      if (rect.bottom > vh - 8) {
        up = Math.ceil(rect.bottom - (vh - 8));
        if (rect.height > vh - 16) {
          up = Math.max(0, Math.ceil(rect.top) - 8);
          maxH = vh - 16;
        }
      }
      next[fly.id] = { left, up, maxH };
    }
    this.placement.set(next);
  }

  placementFor(id: string): FlyPlacement {
    return this.placement()[id] ?? { left: false, up: 0, maxH: null };
  }

  // --- Keyboard ---
  onCaretKeydown(event: KeyboardEvent, id: string): void {
    switch (event.key) {
      case 'ArrowDown':
      case 'Enter':
      case ' ':
        event.preventDefault();
        if (!this.isOpen(id)) this.openMenu(id);
        setTimeout(() => this.focusFirstInLevel(this.panelId(id)), 0);
        break;
      case 'Escape':
        if (this.isOpen(id)) { event.preventDefault(); this.closeAll(); }
        break;
    }
  }

  /**
   * Keys inside a level (the top panel, or any fly-out). `path` is the fly-out's own path
   * (`[]` for the top panel). Stops propagation so only the deepest level acts.
   */
  onLevelKeydown(event: KeyboardEvent, itemId: string, path: number[]): void {
    const containerId = path.length === 0 ? this.panelId(itemId) : this.flyoutId(itemId, path);
    switch (event.key) {
      case 'Escape':
        event.preventDefault();
        event.stopPropagation();
        if (path.length === 0) {
          this.closeAll();
          this.focusEl(this.caretId(itemId));
        } else {
          this.flyPath.set(path.slice(0, -1));
          this.focusChildCaret(itemId, path); // the caret that owns the level just closed
        }
        break;
      case 'ArrowDown':
        event.preventDefault();
        event.stopPropagation();
        this.stepLevel(containerId, 1);
        break;
      case 'ArrowUp':
        event.preventDefault();
        event.stopPropagation();
        this.stepLevel(containerId, -1);
        break;
      case 'ArrowLeft':
        if (path.length > 0) {
          event.preventDefault();
          event.stopPropagation();
          this.flyPath.set(path.slice(0, -1));
          this.focusChildCaret(itemId, path);
        }
        break;
      case 'ArrowRight': {
        const el = document.activeElement as HTMLElement | null;
        const cp = el?.getAttribute('data-childpath');
        if (cp) {
          event.preventDefault();
          event.stopPropagation();
          const childPath = cp.split('-').map(Number);
          this.openFly(childPath);
          setTimeout(() => this.focusFirstInLevel(this.flyoutId(itemId, childPath)), 0);
        }
        break;
      }
    }
  }

  // --- Mobile ---
  toggleMobile(): void { this.mobileOpen.update((v) => !v); }

  mobileKey(parent: string, i: number): string { return parent === '' ? String(i) : `${parent}.${i}`; }
  isMobileOpen(key: string): boolean { return this.mobilePaths().has(key); }
  toggleMobilePath(key: string): void {
    this.mobilePaths.update((set) => {
      const next = new Set(set);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  // --- Focus helpers ---
  /** The focusable links/buttons that belong directly to one level (not its descendants). */
  private levelItems(containerId: string): HTMLElement[] {
    const container = this.host.nativeElement.querySelector(`#${containerId}`) as HTMLElement | null;
    if (!container) return [];
    const all = Array.from(container.querySelectorAll<HTMLElement>('[data-nav]'));
    return all.filter((el) => {
      const owner = el.closest('.tsw-bar__panel, .tsw-bar__flyout') as HTMLElement | null;
      return owner === container;
    });
  }

  private stepLevel(containerId: string, dir: 1 | -1): void {
    const items = this.levelItems(containerId);
    if (!items.length) return;
    const active = document.activeElement as HTMLElement | null;
    const idx = active ? items.indexOf(active) : -1;
    const next = idx < 0 ? (dir === 1 ? 0 : items.length - 1) : (idx + dir + items.length) % items.length;
    items[next]?.focus();
  }

  private focusFirstInLevel(containerId: string): void {
    this.levelItems(containerId)[0]?.focus();
  }

  private focusEl(id: string): void {
    (this.host.nativeElement.querySelector(`#${id}`) as HTMLElement | null)?.focus();
  }

  /** Focus the caret of the node at `path` (its owning parent level is still open). */
  private focusChildCaret(itemId: string, path: number[]): void {
    const sel = `[data-caretpath="${path.join('-')}"]`;
    (this.host.nativeElement.querySelector(sel) as HTMLElement | null)?.focus();
  }

  // --- Dismissal ---
  @HostListener('document:click', ['$event'])
  onDocumentClick(event: MouseEvent): void {
    if (this.openId() === null) return;
    if (!this.host.nativeElement.contains(event.target as Node)) this.closeAll();
  }

  @HostListener('focusout', ['$event'])
  onFocusOut(event: FocusEvent): void {
    if (this.openId() === null) return;
    const next = event.relatedTarget as Node | null;
    if (next && !this.host.nativeElement.contains(next)) this.closeAll();
  }

  /** Narrowing helper for the template's `@let`. */
  childPath(path: number[], i: number): number[] { return [...path, i]; }

  /** Used by the template to decide whether a node is a branch or a leaf. */
  hasChildren(node: ViewNode): boolean { return node.children.length > 0; }
}
