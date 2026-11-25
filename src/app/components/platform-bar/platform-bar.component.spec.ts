// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PlatformBarComponent } from './platform-bar.component';
import navData from '../../../assets/platform-nav.json';
import { PlatformNav, ViewNode, pendingLabels, visiblePlatformItems } from '../../models/platform-nav';

const NAV = navData as PlatformNav;

/** Flatten every node label in the visible tree (any depth). */
function allLabels(nodes: ViewNode[]): string[] {
  return nodes.flatMap((n) => [n.label, ...allLabels(n.children)]);
}
/** Every external leaf in the visible tree (any depth). */
function externalLeaves(nodes: ViewNode[]): ViewNode[] {
  return nodes.flatMap((n) => (n.external && n.children.length === 0 ? [n] : externalLeaves(n.children)));
}

describe('platform-nav model', () => {
  // The real file may carry no pending entry (version 7 has none), so the filter is tested on a
  // fixture, not the vendored file; a future entry may be pending again and must still be dropped.
  it('drops every pending entry from the visible menu (filter tested on a fixture)', () => {
    const fixture: PlatformNav = {
      about: '', version: 7, home: { label: 'Home', href: 'https://teamstarwolf.com/' },
      items: [
        { id: 'x', label: 'X', href: 'https://teamstarwolf.com/', menu: [
          { label: 'A', href: 'https://teamstarwolf.com/a' },
          { label: 'B', href: 'https://teamstarwolf.com/b', pending: 'later',
            menu: [{ label: 'C', href: 'https://teamstarwolf.com/c', pending: 'later' }] },
        ] },
      ],
    };
    const held = pendingLabels(fixture);
    expect(held).toEqual(jasmine.arrayWithExactContents(['B', 'C']));
    const visible = visiblePlatformItems(fixture).flatMap((i) => allLabels(i.entries));
    for (const label of held) expect(visible).not.toContain(label);
  });

  it('maps a top-level item with no menu, or an empty menu, to empty entries', () => {
    const nav = {
      about: '', version: 7, home: { label: 'H', href: 'https://teamstarwolf.com/' },
      items: [
        { id: 'a', label: 'A', href: 'https://teamstarwolf.com/' },            // no menu key
        { id: 'b', label: 'B', href: 'https://teamstarwolf.com/', menu: [] },  // empty menu
      ],
    } as PlatformNav;
    const items = visiblePlatformItems(nav);
    expect(items[0].entries).toEqual([]);
    expect(items[1].entries).toEqual([]);
  });

  it('nests two levels inside bookmarks and one level elsewhere', () => {
    const items = visiblePlatformItems(NAV);
    const depth = (nodes: ViewNode[]): number =>
      nodes.length === 0 ? 0 : 1 + Math.max(...nodes.map((n) => depth(n.children)));
    for (const item of items) {
      const d = depth(item.entries);
      if (item.id === 'bookmarks') expect(d).toBe(3); // category > subsection > leaf (and category > leaf)
      else expect(d).toBeLessThanOrEqual(2); // entry > leaf at most
    }
  });

  it('carries 291 external leaves, all inside bookmarks', () => {
    const items = visiblePlatformItems(NAV);
    const all = items.flatMap((i) => externalLeaves(i.entries));
    expect(all.length).toBe(291);
    const bookmarks = items.find((i) => i.id === 'bookmarks');
    expect(externalLeaves(bookmarks!.entries).length).toBe(291);
  });

  it('keeps the ATT&CK-Navi block as the nine workspaces in rail order', () => {
    const navi = visiblePlatformItems(NAV).find((i) => i.id === 'navi');
    expect(navi?.entries.map((e) => e.label)).toEqual([
      'Matrix', 'Exposure', 'Intel', 'Detect', 'Coverage', 'Dashboard', 'Reports', 'Library', 'Status',
    ]);
  });
});

describe('PlatformBarComponent', () => {
  let fixture: ComponentFixture<PlatformBarComponent>;
  let component: PlatformBarComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [PlatformBarComponent] }).compileComponents();
    fixture = TestBed.createComponent(PlatformBarComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('creates and renders one labelled nav landmark', () => {
    const nav = fixture.nativeElement.querySelector('nav.tsw-bar');
    expect(nav).toBeTruthy();
    expect(nav.getAttribute('aria-label')).toBe('TeamStarWolf platform');
  });

  it('never renders a pending entry', () => {
    // The vendored file may hold no pending entry (version 7 has none); this still asserts that
    // whatever pending labels it does hold never reach the DOM.
    const text: string = fixture.nativeElement.textContent ?? '';
    expect(pendingLabels(NAV).every((label) => !text.includes(label))).toBe(true);
  });

  it('uses its own class names so the app toolbar selectors stay unique', () => {
    const host: HTMLElement = fixture.nativeElement;
    expect(host.querySelector('.brand-link')).toBeNull();
    expect(host.querySelector('.theme-btn')).toBeNull();
  });

  it('toggles a panel from the caret with aria-expanded', () => {
    const caret: HTMLButtonElement = fixture.nativeElement.querySelector('.tsw-bar__caret');
    expect(caret.getAttribute('aria-expanded')).toBe('false');
    caret.click();
    fixture.detectChanges();
    expect(caret.getAttribute('aria-expanded')).toBe('true');
    expect(fixture.nativeElement.querySelector('.tsw-bar__panel')).toBeTruthy();
  });

  it('closes the open panel on Escape', () => {
    // The first item with a menu (version 7's Home has none, so it owns no panel).
    const firstId = component.items.find((i) => i.entries.length > 0)!.id;
    component.openId.set(firstId);
    fixture.detectChanges();
    const panel: HTMLElement = fixture.nativeElement.querySelector('.tsw-bar__panel');
    panel.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    fixture.detectChanges();
    expect(component.openId()).toBeNull();
    expect(fixture.nativeElement.querySelector('.tsw-bar__panel')).toBeNull();
  });

  it('splits a nested category into a real link plus a chevron button', () => {
    component.openMenu('bookmarks');
    fixture.detectChanges();
    const row = fixture.nativeElement.querySelector('.tsw-bar__entry-row');
    expect(row).toBeTruthy();
    const label: HTMLAnchorElement = row.querySelector('.tsw-bar__entry-label');
    expect(label.tagName).toBe('A');
    expect(label.getAttribute('href')).toContain('cybersecurity-resources');
    const caret: HTMLButtonElement = row.querySelector('.tsw-bar__fly-caret');
    expect(caret.tagName).toBe('BUTTON');
    expect(caret.getAttribute('aria-expanded')).toBe('false');
    expect(caret.getAttribute('aria-controls')).toBeTruthy();
  });

  it('opens a category fly-out from the chevron button (touch/click path)', () => {
    component.openMenu('bookmarks');
    fixture.detectChanges();
    const caret: HTMLButtonElement = fixture.nativeElement.querySelector('.tsw-bar__fly-caret');
    caret.click();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.tsw-bar__flyout')).toBeTruthy();
  });

  it('opens three levels: category then its subsection, nested fly-out inside fly-out', () => {
    // Category index 1 ("Vulnerability Management") has subsections.
    const bm = component.items.find((i) => i.id === 'bookmarks')!;
    const catIdx = bm.entries.findIndex((c) => c.children.some((s) => s.children.length > 0));
    expect(catIdx).toBeGreaterThanOrEqual(0);
    const subIdx = bm.entries[catIdx].children.findIndex((s) => s.children.length > 0);

    component.openMenu('bookmarks');
    component.openFly([catIdx, subIdx]);
    fixture.detectChanges();

    expect(component.isFlyOpen([catIdx])).toBe(true);
    expect(component.isFlyOpen([catIdx, subIdx])).toBe(true);
    const outer = fixture.nativeElement.querySelector(`#tsw-flyout-bookmarks-${catIdx}`);
    const inner = fixture.nativeElement.querySelector(`#tsw-flyout-bookmarks-${catIdx}-${subIdx}`);
    expect(outer).toBeTruthy();
    expect(inner).toBeTruthy();
    expect(inner.getAttribute('role')).toBe('group');
    // The inner fly-out holds the subsection's leaves.
    expect(inner.querySelectorAll('.tsw-bar__menu-link').length).toBe(bm.entries[catIdx].children[subIdx].children.length);
  });

  it('keeps only one path open at a time at each level', () => {
    component.openMenu('bookmarks');
    component.openFly([1]);
    expect(component.isFlyOpen([1])).toBe(true);
    component.openFly([2]);
    expect(component.isFlyOpen([1])).toBe(false);
    expect(component.isFlyOpen([2])).toBe(true);
  });

  it('toggleFly closes an already-open fly-out', () => {
    component.openMenu('bookmarks');
    component.toggleFly([1]);
    expect(component.isFlyOpen([1])).toBe(true);
    component.toggleFly([1]);
    expect(component.flyPath().length).toBe(0);
  });

  it('renders every external leaf with the new-tab attributes, a silent marker and the note', () => {
    const bm = component.items.find((i) => i.id === 'bookmarks')!;
    const catIdx = bm.entries.findIndex((c) => c.children.some((s) => s.children.length > 0));
    const subIdx = bm.entries[catIdx].children.findIndex((s) => s.children.length > 0);
    component.openMenu('bookmarks');
    component.openFly([catIdx, subIdx]);
    fixture.detectChanges();

    const ext: HTMLAnchorElement = fixture.nativeElement.querySelector(
      `#tsw-flyout-bookmarks-${catIdx}-${subIdx} .tsw-bar__menu-link--ext`,
    );
    expect(ext).toBeTruthy();
    expect(ext.getAttribute('target')).toBe('_blank');
    expect(ext.getAttribute('rel')).toBe('noopener noreferrer');
    const marker = ext.querySelector('.tsw-bar__ext');
    expect(marker?.getAttribute('aria-hidden')).toBe('true');
    const sr = ext.querySelector('.tsw-bar__sr');
    expect(sr?.textContent).toContain('opens in a new tab on an external site');
    // Accessible name ends with the note.
    expect((ext.textContent ?? '').trim().endsWith('(opens in a new tab on an external site)')).toBe(true);
  });

  it('renders a menu-less top-level item as a plain link: no caret, no panel, no aria', () => {
    // A fresh fixture whose items are overridden BEFORE the first detectChanges, so the initial
    // render uses a menu-less Home (no entries) alongside an item that has a menu. (Reassigning
    // items on an already-rendered OnPush view would not re-render.)
    const f = TestBed.createComponent(PlatformBarComponent);
    (f.componentInstance as unknown as { items: unknown }).items = [
      { id: 'plainhome', label: 'Home', href: 'https://teamstarwolf.com/', entries: [] },
      { id: 'menulib', label: 'Library', href: 'https://library.teamstarwolf.com/', entries: [
        { label: 'Index', href: 'https://library.teamstarwolf.com/#/INDEX', external: false, children: [] },
      ] },
    ];
    f.detectChanges();
    const liList = Array.from(f.nativeElement.querySelectorAll('.tsw-bar__item')) as HTMLElement[];
    const homeLi = liList.find((li) => li.querySelector('.tsw-bar__link')?.textContent?.trim() === 'Home')!;
    const libLi = liList.find((li) => li.querySelector('.tsw-bar__link')?.textContent?.trim() === 'Library')!;
    const homeLink = homeLi.querySelector('.tsw-bar__link') as HTMLAnchorElement;
    expect(homeLink.tagName).toBe('A');
    expect(homeLink.getAttribute('href')).toBe('https://teamstarwolf.com/');
    // No caret button, no aria wiring, and opening it produces no panel.
    expect(homeLi.querySelector('.tsw-bar__caret')).toBeNull();
    expect(homeLink.getAttribute('aria-expanded')).toBeNull();
    expect(homeLink.getAttribute('aria-controls')).toBeNull();
    f.componentInstance.openMenu('plainhome');
    f.detectChanges();
    expect(f.componentInstance.openId()).toBeNull();
    expect(f.nativeElement.querySelector('#tsw-panel-plainhome')).toBeNull();
    // The item that does have a menu still gets its caret.
    expect(libLi.querySelector('.tsw-bar__caret')).toBeTruthy();
  });

  it('a menu-less item closes any open menu on hover (openMenu) and on focus', () => {
    // A real menu item (not Home), plus a menu-less Home prepended; no duplicate ids.
    const withMenu = component.items.find((i) => i.id === 'bookmarks')!.id;
    (component as unknown as { items: unknown }).items = [
      { id: 'home', label: 'Home', href: 'https://teamstarwolf.com/', entries: [] },
      ...component.items.filter((i) => i.id !== 'home'),
    ];
    component.openMenu(withMenu);
    expect(component.openId()).toBe(withMenu);
    component.openMenu('home'); // the hover path; a menu-less item just closes what is open
    expect(component.openId()).toBeNull();

    component.openMenu(withMenu);
    expect(component.openId()).toBe(withMenu);
    component.onLinkFocus('home'); // focusing Home closes the open menu
    expect(component.openId()).toBeNull();
  });

  it('Escape pressed on an ancestor caret closes only the deepest level, not both', () => {
    const bm = component.items.find((i) => i.id === 'bookmarks')!;
    const catIdx = bm.entries.findIndex((c) => c.children.some((s) => s.children.length > 0));
    const subIdx = bm.entries[catIdx].children.findIndex((s) => s.children.length > 0);
    component.openMenu('bookmarks');
    component.openFly([catIdx, subIdx]);
    fixture.detectChanges();

    // Press Escape ON the CATEGORY caret (an ancestor) while its subsection fly-out is still open;
    // the event bubbles to the panel's keydown handler with the caret as its target.
    const catCaret = fixture.nativeElement.querySelector(`[data-caretpath="${catIdx}"]`) as HTMLButtonElement;
    catCaret.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    fixture.detectChanges();

    // Only the deepest (subsection) level closed; the category fly-out stays open.
    expect(component.isFlyOpen([catIdx, subIdx])).toBe(false);
    expect(component.isFlyOpen([catIdx])).toBe(true);
  });
});
