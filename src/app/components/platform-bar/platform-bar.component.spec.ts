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
  it('drops every pending entry from the visible menu', () => {
    const held = pendingLabels(NAV);
    expect(held.length).toBeGreaterThan(0); // the fixture has pending entries to filter
    const visible = visiblePlatformItems(NAV).flatMap((i) => allLabels(i.entries));
    for (const label of held) expect(visible).not.toContain(label);
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
    const text: string = fixture.nativeElement.textContent ?? '';
    for (const label of pendingLabels(NAV)) expect(text).not.toContain(label);
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
    const firstId = component.items[0].id;
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
});
