// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { DrawerResizeHandleComponent } from './drawer-resize-handle.component';
import {
  DRAWER_DEFAULT_WIDTH,
  DRAWER_MIN_WIDTH,
  DRAWER_WIDTH_KEY,
  DrawerWidthService,
} from '../../services/drawer-width.service';

describe('DrawerResizeHandleComponent', () => {
  let fixture: ComponentFixture<DrawerResizeHandleComponent>;
  let el: HTMLElement;
  let drawer: DrawerWidthService;

  const pointer = (type: string, clientX: number, extra: PointerEventInit = {}): void => {
    el.dispatchEvent(new PointerEvent(type, {
      bubbles: true, cancelable: true, pointerId: 7, button: 0, clientX, ...extra,
    }));
  };

  const key = (k: string, init: KeyboardEventInit = {}): KeyboardEvent => {
    const ev = new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...init });
    el.dispatchEvent(ev);
    fixture.detectChanges();
    return ev;
  };

  beforeEach(async () => {
    localStorage.removeItem(DRAWER_WIDTH_KEY);
    await TestBed.configureTestingModule({ imports: [DrawerResizeHandleComponent] }).compileComponents();
    drawer = TestBed.inject(DrawerWidthService);
    drawer.syncViewport(1440);
    fixture = TestBed.createComponent(DrawerResizeHandleComponent);
    fixture.componentRef.setInput('controls', 'technique-drawer');
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => {
    localStorage.removeItem(DRAWER_WIDTH_KEY);
    document.body.style.userSelect = '';
    document.body.style.cursor = '';
  });

  it('is a focusable vertical separator with its value in px', () => {
    expect(el.getAttribute('role')).toBe('separator');
    expect(el.getAttribute('tabindex')).toBe('0');
    expect(el.getAttribute('aria-orientation')).toBe('vertical');
    expect(el.getAttribute('aria-label')).toBe('Resize technique panel');
    expect(el.getAttribute('aria-controls')).toBe('technique-drawer');
    expect(el.getAttribute('aria-valuenow')).toBe(String(DRAWER_DEFAULT_WIDTH));
    expect(el.getAttribute('aria-valuemin')).toBe(String(DRAWER_MIN_WIDTH));
    expect(el.getAttribute('aria-valuemax')).toBe('864');
  });

  it('ArrowLeft three times narrows by 48 px and updates aria-valuenow', () => {
    for (let i = 0; i < 3; i++) expect(key('ArrowLeft').defaultPrevented).toBeTrue();
    expect(drawer.width()).toBe(DRAWER_DEFAULT_WIDTH - 48);
    expect(el.getAttribute('aria-valuenow')).toBe(String(DRAWER_DEFAULT_WIDTH - 48));
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBe(String(DRAWER_DEFAULT_WIDTH - 48));
  });

  it('ArrowRight widens by 16 px, Shift by 64 px; Home and End go to the bounds', () => {
    key('ArrowRight');
    expect(drawer.width()).toBe(DRAWER_DEFAULT_WIDTH + 16);
    key('ArrowRight', { shiftKey: true });
    expect(drawer.width()).toBe(DRAWER_DEFAULT_WIDTH + 80);
    key('End');
    expect(el.getAttribute('aria-valuenow')).toBe('864');
    key('Home');
    expect(el.getAttribute('aria-valuenow')).toBe(String(DRAWER_MIN_WIDTH));
  });

  it('leaves Escape and modified keys alone', () => {
    expect(key('Escape').defaultPrevented).toBeFalse();
    expect(key('ArrowLeft', { ctrlKey: true }).defaultPrevented).toBeFalse();
    expect(drawer.width()).toBe(DRAWER_DEFAULT_WIDTH);
  });

  it('pointer drag to the left widens live, persists once on release and blocks text selection', () => {
    pointer('pointerdown', 1000);
    fixture.detectChanges();
    expect(el.classList).toContain('dragging');
    expect(document.body.style.userSelect).toBe('none');

    pointer('pointermove', 900);
    expect(drawer.width()).toBe(DRAWER_DEFAULT_WIDTH + 100);
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBeNull();

    pointer('pointermove', 840);
    pointer('pointerup', 840);
    fixture.detectChanges();
    expect(drawer.width()).toBe(DRAWER_DEFAULT_WIDTH + 160);
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBe(String(DRAWER_DEFAULT_WIDTH + 160));
    expect(el.classList).not.toContain('dragging');
    expect(document.body.style.userSelect).toBe('');
  });

  it('drag clamps at the bounds', () => {
    pointer('pointerdown', 1000);
    pointer('pointermove', 2000);
    expect(drawer.width()).toBe(DRAWER_MIN_WIDTH);
    pointer('pointermove', -2000);
    expect(drawer.width()).toBe(864);
    pointer('pointercancel', -2000);
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBe('864');
  });

  it('ignores moves without a drag, other pointers and non-primary buttons', () => {
    pointer('pointermove', 100);
    pointer('pointerdown', 1000, { button: 2 });
    pointer('pointermove', 100);
    expect(drawer.width()).toBe(DRAWER_DEFAULT_WIDTH);
    pointer('pointerdown', 1000);
    pointer('pointermove', 100, { pointerId: 99 });
    pointer('pointerup', 100, { pointerId: 99 });
    expect(drawer.width()).toBe(DRAWER_DEFAULT_WIDTH);
    pointer('pointerup', 1000);
  });

  it('lost pointer capture ends the drag', () => {
    pointer('pointerdown', 1000);
    pointer('pointermove', 980);
    el.dispatchEvent(new PointerEvent('lostpointercapture', { pointerId: 7 }));
    fixture.detectChanges();
    expect(el.classList).not.toContain('dragging');
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBe(String(DRAWER_DEFAULT_WIDTH + 20));
  });

  it('double-click resets to the default width', () => {
    drawer.setWidth(700);
    el.dispatchEvent(new MouseEvent('dblclick', { bubbles: true, cancelable: true }));
    fixture.detectChanges();
    expect(drawer.width()).toBe(DRAWER_DEFAULT_WIDTH);
    expect(el.getAttribute('aria-valuenow')).toBe(String(DRAWER_DEFAULT_WIDTH));
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBeNull();
  });

  it('destroying mid-drag restores the page and keeps the width', () => {
    pointer('pointerdown', 1000);
    pointer('pointermove', 950);
    fixture.destroy();
    expect(document.body.style.userSelect).toBe('');
    expect(localStorage.getItem(DRAWER_WIDTH_KEY)).toBe(String(DRAWER_DEFAULT_WIDTH + 50));
  });
});
