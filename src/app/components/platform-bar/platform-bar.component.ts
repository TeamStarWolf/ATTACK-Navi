// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, ElementRef, HostListener, inject, signal } from '@angular/core';
import { IconComponent } from '../../shared/icons/icon.component';
import navData from '../../../assets/platform-nav.json';
import { PlatformNav, ViewItem, visiblePlatformItems } from '../../models/platform-nav';

/**
 * The universal TeamStarWolf platform bar: one menu every site shows in its own stack,
 * rendered here above the app toolbar. Menu only (no search, theme toggle or app
 * controls); its own `tsw-bar__` class names keep the app toolbar's `.brand-link` and
 * `.theme-btn` unique.
 *
 * Desktop (>= 761px): a top-level menu opens on hover (and its own button with
 * aria-expanded opens it for keyboard/click); an entry with sub-entries shows a right
 * chevron and opens them as a fly-out panel to the side. Keyboard: ArrowRight opens the
 * fly-out and enters it, Escape/ArrowLeft returns.
 * Mobile (<= 760px): one button opens an inline accordion; sub-entries drop inline.
 *
 * Source of record: `src/assets/platform-nav.json`, a byte-identical copy of the canonical
 * file the front site publishes; every `pending` entry is filtered before render
 * (`visiblePlatformItems`), which the spec and `scripts/check-platform-nav.mjs` assert.
 */

// Hover open/close delays (ms), from the Website session's reference build: open is
// immediate; close waits so a diagonal move into a fly-out does not shut the menu. Kept
// here so they stay a one-line change. The close delay is timing, not motion, so it
// stands under prefers-reduced-motion.
const OPEN_DELAY_MS = 0;
const CLOSE_DELAY_MS = 220;

// The leading "TeamStarWolf" wordmark before the Home item. The owner had the brand
// removed from the front-page header, and whether the band carries it is still open with
// the Website session; kept behind this one flag so it can go either way. The Home menu
// item is always present as the way back regardless.
const SHOW_WORDMARK = true;

@Component({
  selector: 'app-platform-bar',
  standalone: true,
  imports: [IconComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './platform-bar.component.html',
  styleUrl: './platform-bar.component.scss',
})
export class PlatformBarComponent {
  private readonly host = inject(ElementRef<HTMLElement>);

  private readonly nav = navData as PlatformNav;
  /** The home brand target; the Home item in the menu is the always-present way back. */
  readonly home = this.nav.home;
  /** Whether the band shows the leading "TeamStarWolf" wordmark (open point; see flag). */
  readonly showWordmark = SHOW_WORDMARK;
  /** The menu, with pending entries removed and nesting capped at one level. */
  readonly items: ViewItem[] = visiblePlatformItems(this.nav);

  /** Which top-level panel is open on desktop (id), or null. */
  readonly openId = signal<string | null>(null);
  /** Which entry's fly-out is open, as `${itemId}#${entryIndex}`, or null. */
  readonly flyoutKey = signal<string | null>(null);
  /** Whether a fly-out opens to the left (set when it would overflow the right edge). */
  readonly flyoutLeft = signal(false);
  /** Whether the mobile drawer is open. */
  readonly mobileOpen = signal(false);
  /** Which mobile accordion section is expanded (id), or null. */
  readonly mobileSection = signal<string | null>(null);

  private openTimer?: ReturnType<typeof setTimeout>;
  private closeTimer?: ReturnType<typeof setTimeout>;

  panelId(id: string): string { return `tsw-panel-${id}`; }
  caretId(id: string): string { return `tsw-caret-${id}`; }
  flyoutId(itemId: string, i: number): string { return `tsw-flyout-${itemId}-${i}`; }
  mobileSectionId(id: string): string { return `tsw-ms-${id}`; }
  private flyKey(itemId: string, i: number): string { return `${itemId}#${i}`; }

  isOpen(id: string): boolean { return this.openId() === id; }
  isFlyoutOpen(itemId: string, i: number): boolean { return this.flyoutKey() === this.flyKey(itemId, i); }

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

  /** Hovering an entry opens its fly-out; hovering a childless entry closes any open one.
   *  Only one fly-out is open at a time, so this swaps it. Fine pointers only. */
  onEntryEnter(itemId: string, i: number, hasChildren: boolean): void {
    if (!this.hoverCapable()) return;
    if (hasChildren) this.openFlyout(itemId, i);
    else this.flyoutKey.set(null);
  }

  /** Tap/click on a category's chevron (carries touch at desktop width). */
  toggleFlyout(itemId: string, i: number): void {
    if (this.isFlyoutOpen(itemId, i)) this.closeFlyout();
    else this.openFlyout(itemId, i);
  }

  // --- Open / close ---
  openMenu(id: string): void {
    this.openId.set(id);
    this.flyoutKey.set(null);
  }

  closeAll(): void {
    this.openId.set(null);
    this.flyoutKey.set(null);
  }

  /** Click/keyboard toggle on the caret button. */
  toggle(id: string): void {
    clearTimeout(this.openTimer);
    clearTimeout(this.closeTimer);
    if (this.isOpen(id)) this.closeAll();
    else this.openMenu(id);
  }

  openFlyout(itemId: string, i: number): void {
    this.flyoutLeft.set(false); // measure from the default right-opening position
    this.flyoutKey.set(this.flyKey(itemId, i));
    // A fly-out opens to the right; if its right edge would cross the viewport, open it
    // to the left instead (reference: flips at ~840px, opens right at 1280px).
    setTimeout(() => {
      const fly = this.host.nativeElement.querySelector(`#${this.flyoutId(itemId, i)}`) as HTMLElement | null;
      if (!fly) return;
      const rect = fly.getBoundingClientRect();
      this.flyoutLeft.set(rect.right > window.innerWidth - 8);
    }, 0);
  }

  closeFlyout(): void {
    this.flyoutKey.set(null);
  }

  // --- Keyboard ---
  onCaretKeydown(event: KeyboardEvent, id: string): void {
    switch (event.key) {
      case 'ArrowDown':
      case 'Enter':
      case ' ':
        event.preventDefault();
        if (!this.isOpen(id)) this.openMenu(id);
        setTimeout(() => this.focusInPanel(id, 'first'), 0);
        break;
      case 'Escape':
        if (this.isOpen(id)) { event.preventDefault(); this.closeAll(); }
        break;
    }
  }

  /** Keys in the main panel: move among entries, enter a fly-out, or close. */
  onPanelKeydown(event: KeyboardEvent, id: string): void {
    switch (event.key) {
      case 'Escape':
        event.preventDefault();
        this.closeAll();
        this.focusCaret(id);
        break;
      case 'ArrowDown':
        event.preventDefault();
        this.focusInPanel(id, 1);
        break;
      case 'ArrowUp':
        event.preventDefault();
        this.focusInPanel(id, -1);
        break;
      case 'ArrowRight': {
        const el = document.activeElement as HTMLElement | null;
        const i = el?.getAttribute('data-flyindex');
        if (i !== null && i !== undefined) {
          event.preventDefault();
          this.openFlyout(id, Number(i));
          setTimeout(() => this.focusInFlyout(id, Number(i), 'first'), 0);
        }
        break;
      }
    }
  }

  /** Keys in a fly-out: move among sub-entries, or return to the parent entry.
   *  Stops propagation so the parent panel's handler does not also act. */
  onFlyoutKeydown(event: KeyboardEvent, itemId: string, i: number): void {
    switch (event.key) {
      case 'Escape':
      case 'ArrowLeft':
        event.preventDefault();
        event.stopPropagation();
        this.closeFlyout();
        this.focusEntry(itemId, i);
        break;
      case 'ArrowDown':
        event.preventDefault();
        event.stopPropagation();
        this.focusInFlyout(itemId, i, 1);
        break;
      case 'ArrowUp':
        event.preventDefault();
        event.stopPropagation();
        this.focusInFlyout(itemId, i, -1);
        break;
    }
  }

  // --- Mobile ---
  toggleMobile(): void { this.mobileOpen.update((v) => !v); }
  toggleSection(id: string): void { this.mobileSection.update((cur) => (cur === id ? null : id)); }

  // --- Focus helpers ---
  private step(items: HTMLElement[], where: 1 | -1 | 'first' | 'last'): void {
    if (!items.length) return;
    const active = document.activeElement as HTMLElement | null;
    let idx = active ? items.indexOf(active) : -1;
    if (where === 'first') idx = 0;
    else if (where === 'last') idx = items.length - 1;
    else idx = idx < 0 ? (where === 1 ? 0 : items.length - 1) : (idx + where + items.length) % items.length;
    items[idx]?.focus();
  }

  private focusInPanel(id: string, where: 1 | -1 | 'first' | 'last'): void {
    const panel = this.host.nativeElement.querySelector(`#${this.panelId(id)}`) as HTMLElement | null;
    if (!panel) return;
    this.step(Array.from(panel.querySelectorAll<HTMLElement>('[data-menuitem]')), where);
  }

  private focusInFlyout(itemId: string, i: number, where: 1 | -1 | 'first' | 'last'): void {
    const fly = this.host.nativeElement.querySelector(`#${this.flyoutId(itemId, i)}`) as HTMLElement | null;
    if (!fly) return;
    this.step(Array.from(fly.querySelectorAll<HTMLElement>('[data-flyitem]')), where);
  }

  private focusCaret(id: string): void {
    (this.host.nativeElement.querySelector(`#${this.caretId(id)}`) as HTMLElement | null)?.focus();
  }

  private focusEntry(itemId: string, i: number): void {
    (this.host.nativeElement.querySelector(`[data-menuitem][data-entry="${itemId}#${i}"]`) as HTMLElement | null)?.focus();
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
}
