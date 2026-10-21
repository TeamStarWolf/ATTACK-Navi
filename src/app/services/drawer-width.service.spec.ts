// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import {
  DRAWER_DEFAULT_WIDTH,
  DRAWER_MAX_WIDTH,
  DRAWER_MIN_WIDTH,
  DRAWER_WIDTH_KEY,
  DrawerWidthService,
  clampDrawerWidth,
  drawerMaxWidth,
  drawerWidthForKey,
  parseStoredDrawerWidth,
} from './drawer-width.service';

describe('drawer width: pure helpers', () => {
  it('caps the maximum at the lesser of 900 px and 60% of the viewport', () => {
    expect(drawerMaxWidth(1280)).toBe(768);
    expect(drawerMaxWidth(1440)).toBe(864);
    expect(drawerMaxWidth(2000)).toBe(DRAWER_MAX_WIDTH);
    // Never below the minimum, however narrow the window.
    expect(drawerMaxWidth(400)).toBe(DRAWER_MIN_WIDTH);
  });

  it('clamps to [320, max] and rounds to whole px', () => {
    expect(clampDrawerWidth(100, 1440)).toBe(320);
    expect(clampDrawerWidth(5000, 1440)).toBe(864);
    expect(clampDrawerWidth(5000, 2000)).toBe(900);
    expect(clampDrawerWidth(500.6, 1440)).toBe(501);
    expect(clampDrawerWidth(Number.NaN, 1440)).toBe(DRAWER_DEFAULT_WIDTH);
  });

  it('falls back to the default for missing or unusable stored values', () => {
    expect(parseStoredDrawerWidth(null)).toBe(DRAWER_DEFAULT_WIDTH);
    expect(parseStoredDrawerWidth('')).toBe(DRAWER_DEFAULT_WIDTH);
    expect(parseStoredDrawerWidth('wide')).toBe(DRAWER_DEFAULT_WIDTH);
    expect(parseStoredDrawerWidth('0')).toBe(DRAWER_DEFAULT_WIDTH);
    expect(parseStoredDrawerWidth('-40')).toBe(DRAWER_DEFAULT_WIDTH);
    expect(parseStoredDrawerWidth('Infinity')).toBe(DRAWER_DEFAULT_WIDTH);
  });

  it('pulls stored values inside the absolute bounds', () => {
    expect(parseStoredDrawerWidth('612')).toBe(612);
    expect(parseStoredDrawerWidth('100')).toBe(DRAWER_MIN_WIDTH);
    expect(parseStoredDrawerWidth('4000')).toBe(DRAWER_MAX_WIDTH);
  });

  it('maps the separator keys like a left-edge splitter: ArrowLeft widens, ArrowRight narrows, Shift 64 px, Home/End to the bounds', () => {
    // The handle is on the drawer's LEFT edge: ArrowLeft moves it left (wider),
    // the same direction as a pointer drag to the left (WAI-ARIA APG splitter).
    expect(drawerWidthForKey('ArrowLeft', false, 500, 1440)).toBe(516);
    expect(drawerWidthForKey('ArrowRight', false, 500, 1440)).toBe(484);
    expect(drawerWidthForKey('ArrowLeft', true, 500, 1440)).toBe(564);
    expect(drawerWidthForKey('ArrowRight', true, 500, 1440)).toBe(436);
    expect(drawerWidthForKey('Home', false, 500, 1440)).toBe(DRAWER_MIN_WIDTH);
    expect(drawerWidthForKey('End', false, 500, 1440)).toBe(864);
    // Steps stop at the bounds.
    expect(drawerWidthForKey('ArrowRight', true, 330, 1440)).toBe(DRAWER_MIN_WIDTH);
    expect(drawerWidthForKey('ArrowLeft', true, 860, 1440)).toBe(864);
  });

  it('ignores keys it does not use (Escape still reaches the global listener)', () => {
    expect(drawerWidthForKey('Escape', false, 500, 1440)).toBeNull();
    expect(drawerWidthForKey('ArrowUp', false, 500, 1440)).toBeNull();
    expect(drawerWidthForKey('Enter', false, 500, 1440)).toBeNull();
  });
});

describe('DrawerWidthService', () => {
  const create = (): DrawerWidthService => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({});
    const svc = TestBed.inject(DrawerWidthService);
    svc.syncViewport(1440);
    return svc;
  };

  beforeEach(() => localStorage.removeItem(DRAWER_WIDTH_KEY));
  afterEach(() => localStorage.removeItem(DRAWER_WIDTH_KEY));

  it('starts at the default width with nothing stored', () => {
    const svc = create();
    expect(svc.width()).toBe(DRAWER_DEFAULT_WIDTH);
    expect(svc.min).toBe(DRAWER_MIN_WIDTH);
    expect(svc.max()).toBe(864);
  });

  it('reads the stored width when it is created (applied on first render)', () => {
    localStorage.setItem(DRAWER_WIDTH_KEY, '620');
    expect(create().width()).toBe(620);
  });

  it('falls back to the default when storage throws', () => {
    spyOn(Storage.prototype, 'getItem').and.throwError('SecurityError');
    expect(create().width()).toBe(DRAWER_DEFAULT_WIDTH);
  });

  it('setWidth clamps and persists under one key', () => {
    const svc = create();
    svc.setWidth(5000);
    expect(svc.width()).toBe(864);
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBe('864');
    svc.setWidth(10);
    expect(svc.width()).toBe(DRAWER_MIN_WIDTH);
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBe('320');
  });

  it('preview changes the width without persisting until commit', () => {
    const svc = create();
    svc.preview(600);
    expect(svc.width()).toBe(600);
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBeNull();
    svc.commit();
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBe('600');
  });

  it('handleKey applies the keyboard map and persists; unknown keys are not consumed', () => {
    const svc = create();
    expect(svc.handleKey('ArrowRight', false)).toBeTrue();
    expect(svc.handleKey('ArrowRight', false)).toBeTrue();
    expect(svc.handleKey('ArrowRight', false)).toBeTrue();
    expect(svc.width()).toBe(DRAWER_DEFAULT_WIDTH - 48);
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBe(String(DRAWER_DEFAULT_WIDTH - 48));
    expect(svc.handleKey('ArrowLeft', false)).toBeTrue();
    expect(svc.width()).toBe(DRAWER_DEFAULT_WIDTH - 32);
    expect(svc.handleKey('End', false)).toBeTrue();
    expect(svc.width()).toBe(864);
    expect(svc.handleKey('Home', false)).toBeTrue();
    expect(svc.width()).toBe(DRAWER_MIN_WIDTH);
    expect(svc.handleKey('Escape', false)).toBeFalse();
    expect(svc.width()).toBe(DRAWER_MIN_WIDTH);
  });

  it('tracks whether the drawer is open (closed until the sidebar says so)', () => {
    const svc = create();
    expect(svc.open()).toBeFalse();
    svc.setOpen(true);
    expect(svc.open()).toBeTrue();
    svc.setOpen(false);
    expect(svc.open()).toBeFalse();
  });

  it('reset returns to the default and removes the stored key', () => {
    const svc = create();
    svc.setWidth(700);
    svc.reset();
    expect(svc.width()).toBe(DRAWER_DEFAULT_WIDTH);
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBeNull();
  });

  it('re-clamps to a narrower viewport and restores the preference when it widens', () => {
    const svc = create();
    svc.setWidth(860);
    svc.syncViewport(1280);
    expect(svc.width()).toBe(768);
    expect(svc.max()).toBe(768);
    svc.syncViewport(1440);
    expect(svc.width()).toBe(860);
  });

  it('follows window resize events', () => {
    const svc = create();
    svc.syncViewport(1);
    window.dispatchEvent(new Event('resize'));
    expect(svc.max()).toBe(Math.max(DRAWER_MIN_WIDTH, Math.min(DRAWER_MAX_WIDTH, Math.floor(window.innerWidth * 0.6))));
  });

  it('keeps working in memory when storage writes throw', () => {
    const svc = create();
    spyOn(Storage.prototype, 'setItem').and.throwError('QuotaExceededError');
    svc.setWidth(540);
    expect(svc.width()).toBe(540);
  });
});
