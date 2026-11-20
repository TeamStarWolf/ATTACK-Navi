// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PlatformBarComponent } from './platform-bar.component';
import navData from '../../../assets/platform-nav.json';
import { PlatformNav, pendingLabels, visiblePlatformItems } from '../../models/platform-nav';

const NAV = navData as PlatformNav;

describe('platform-nav model', () => {
  it('drops every pending entry from the visible menu', () => {
    const held = pendingLabels(NAV);
    expect(held.length).toBeGreaterThan(0); // the fixture has pending entries to filter
    const visibleLabels = visiblePlatformItems(NAV).flatMap((i) =>
      i.entries.flatMap((e) => [e.label, ...e.children.map((c) => c.label)]),
    );
    for (const label of held) {
      expect(visibleLabels).not.toContain(label);
    }
  });

  it('caps nesting at one level (sub-entries carry no further menu)', () => {
    for (const item of visiblePlatformItems(NAV)) {
      for (const entry of item.entries) {
        for (const sub of entry.children) {
          expect(Object.keys(sub)).toEqual(jasmine.arrayWithExactContents(['label', 'href']));
        }
      }
    }
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
    for (const label of pendingLabels(NAV)) {
      expect(text).not.toContain(label);
    }
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

  it('opens the fly-out from the chevron button (touch/click path)', () => {
    component.openMenu('bookmarks');
    fixture.detectChanges();
    const caret: HTMLButtonElement = fixture.nativeElement.querySelector('.tsw-bar__fly-caret');
    caret.click();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.tsw-bar__flyout')).toBeTruthy();
  });

  it('opens sub-entries as a side fly-out panel, not inline', () => {
    const bookmarks = component.items.find((i) => i.id === 'bookmarks');
    const idx = bookmarks!.entries.findIndex((e) => e.children.length > 0);
    expect(idx).toBeGreaterThanOrEqual(0);
    component.openMenu('bookmarks');
    component.openFlyout('bookmarks', idx);
    fixture.detectChanges();
    const flyout = fixture.nativeElement.querySelector('.tsw-bar__flyout');
    expect(flyout).toBeTruthy();
    expect(flyout.getAttribute('role')).toBe('group');
    expect(flyout.querySelectorAll('[data-flyitem]').length).toBe(bookmarks!.entries[idx].children.length);
    expect(component.isFlyoutOpen('bookmarks', idx)).toBe(true);
  });

  it('keeps only one fly-out open at a time', () => {
    component.openMenu('bookmarks');
    component.openFlyout('bookmarks', 1);
    expect(component.isFlyoutOpen('bookmarks', 1)).toBe(true);
    component.openFlyout('bookmarks', 2);
    expect(component.isFlyoutOpen('bookmarks', 1)).toBe(false);
    expect(component.isFlyoutOpen('bookmarks', 2)).toBe(true);
  });

  it('toggleFlyout closes an already-open fly-out', () => {
    component.openMenu('bookmarks');
    component.toggleFlyout('bookmarks', 1);
    expect(component.isFlyoutOpen('bookmarks', 1)).toBe(true);
    component.toggleFlyout('bookmarks', 1);
    expect(component.flyoutKey()).toBeNull();
  });
});
