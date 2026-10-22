// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The drawer's section primitive on its own (no drawer): the header renders the
// title, icon, count pill, chevron and trailing slot; the open state is a model;
// a fixed section has no chevron, role or aria-expanded; the card and header take
// the one shared style.
import { ChangeDetectionStrategy, Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { DrawerSectionComponent } from './drawer-section.component';

@Component({
  standalone: true,
  imports: [DrawerSectionComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <app-drawer-section
      sectionId="demo"
      heading="Demo Section"
      [icon]="icon()"
      [count]="count()"
      [countState]="countState()"
      [countTitle]="countTitle()"
      [curated]="curated()"
      [expanded]="expanded()"
      (expandedChange)="changes.push($event); expanded.set($event)"
    >
      @if (action()) {
        <button sbTrailing class="demo-action" (click)="actionClicks = actionClicks + 1">Open</button>
      }
      <p class="demo-body">Body text</p>
    </app-drawer-section>
    <app-drawer-section class="fixed" heading="Fixed Section" [collapsible]="false">
      <p class="fixed-body">Always shown</p>
    </app-drawer-section>
  `,
})
class HostComponent {
  icon = signal('📋');
  count = signal<string | number | null>(3);
  countState = signal<string | null>(null);
  countTitle = signal<string | null>(null);
  curated = signal(false);
  expanded = signal(true);
  action = signal(true);
  changes: boolean[] = [];
  actionClicks = 0;
}

describe('DrawerSectionComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  let host: HostComponent;
  const el = () => fixture.nativeElement as HTMLElement;
  const head = () => el().querySelector<HTMLElement>('#sb-sec-demo')!;
  const text = (e: Element | null) => (e?.textContent ?? '').replace(/\s+/g, ' ').trim();

  beforeEach(() => {
    TestBed.configureTestingModule({ imports: [HostComponent] });
    fixture = TestBed.createComponent(HostComponent);
    host = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('renders the header: chevron, icon, title, count and trailing slot, in that order', () => {
    const h = head();
    expect(h.tagName).toBe('H3');
    expect(h.classList).toContain('sb-head');
    expect(h.classList).toContain('section-title');
    expect(h.classList).toContain('upgrade-section-title');
    expect(h.classList).toContain('collapsible-title');
    const parts = [...h.children].map(c => c.className.split(' ').find(k => k.startsWith('sb-')));
    expect(parts).toEqual(['sb-chevron', 'sb-icon', 'sb-title', 'sb-count', 'sb-trailing']);
    expect(text(h.querySelector('.sb-title'))).toBe('Demo Section');
    expect(text(h.querySelector('.sb-icon'))).toBe('📋');
    const count = h.querySelector('.sb-count')!;
    expect(count.classList).toContain('count-badge');
    expect(count.classList).toContain('upgrade-section-count');
    expect(text(count)).toBe('3');
    expect(h.querySelector('.sb-trailing .demo-action')).not.toBeNull();
  });

  it('is a button with aria-expanded and the open chevron while expanded', () => {
    expect(head().getAttribute('role')).toBe('button');
    expect(head().getAttribute('tabindex')).toBe('0');
    expect(head().getAttribute('aria-expanded')).toBe('true');
    expect(text(head().querySelector('.sb-chevron'))).toBe('▾');
    expect(el().querySelector('.demo-body')).not.toBeNull();
    expect(el().querySelector('app-drawer-section')!.getAttribute('data-section')).toBe('demo');
  });

  it('a click on the header emits the new state; the bound state drives the chevron and the body', () => {
    head().click();
    fixture.detectChanges();
    expect(host.changes).toEqual([false]);
    expect(head().getAttribute('aria-expanded')).toBe('false');
    expect(text(head().querySelector('.sb-chevron'))).toBe('▸');
    expect(el().querySelector('.demo-body')).toBeNull();
    expect(el().querySelector('app-drawer-section')!.classList).toContain('sb-section--collapsed');
    head().click();
    fixture.detectChanges();
    expect(host.changes).toEqual([false, true]);
    expect(el().querySelector('.demo-body')).not.toBeNull();
  });

  it('the state set from outside wins (collapse all, expand relevant)', () => {
    host.expanded.set(false);
    fixture.detectChanges();
    expect(head().getAttribute('aria-expanded')).toBe('false');
    expect(el().querySelector('.demo-body')).toBeNull();
    expect(host.changes).toEqual([]);
  });

  it('Enter and Space on the header toggle it; a key in a trailing control is that control\'s', () => {
    head().dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    fixture.detectChanges();
    expect(host.changes).toEqual([false]);
    head().dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true }));
    fixture.detectChanges();
    expect(host.changes).toEqual([false, true]);
    el().querySelector('.demo-action')!.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    fixture.detectChanges();
    expect(host.changes).toEqual([false, true]);
  });

  it('a count of 0 shows; null or empty hides the pill; countState and countTitle reach the pill', () => {
    host.count.set(0);
    fixture.detectChanges();
    expect(text(head().querySelector('.sb-count'))).toBe('0');
    expect(head().querySelector('.sb-count')!.getAttribute('data-state')).toBeNull();
    host.count.set('not loaded');
    host.countState.set('not-loaded');
    host.countTitle.set('why');
    fixture.detectChanges();
    const pill = head().querySelector('.sb-count')!;
    expect(text(pill)).toBe('not loaded');
    expect(pill.getAttribute('data-state')).toBe('not-loaded');
    expect(pill.getAttribute('title')).toBe('why');
    host.count.set(null);
    fixture.detectChanges();
    expect(head().querySelector('.sb-count')).toBeNull();
    host.count.set('');
    fixture.detectChanges();
    expect(head().querySelector('.sb-count')).toBeNull();
  });

  it('no icon renders no icon slot; curated marks the header', () => {
    host.icon.set('');
    host.curated.set(true);
    fixture.detectChanges();
    expect(head().querySelector('.sb-icon')).toBeNull();
    expect(head().classList).toContain('sb-head--curated');
    expect(getComputedStyle(head().querySelector('.sb-title')!, '::after').content).toContain('curated');
  });

  it('a click on a control in the trailing slot belongs to the control (the section stays as it is); the slot collapses when empty', () => {
    el().querySelector<HTMLButtonElement>('.demo-action')!.click();
    fixture.detectChanges();
    expect(host.actionClicks).toBe(1);
    expect(host.changes).toEqual([]);
    expect(head().getAttribute('aria-expanded')).toBe('true');
    host.action.set(false);
    fixture.detectChanges();
    expect(getComputedStyle(head().querySelector('.sb-trailing')!).display).toBe('none');
  });

  it('a fixed section has no chevron, no role, no aria-expanded and no collapsible-title, and always shows its body', () => {
    const fixed = el().querySelector('app-drawer-section.fixed')!;
    const h = fixed.querySelector('.sb-head')!;
    expect(h.getAttribute('id')).toBeNull();
    expect(h.getAttribute('role')).toBeNull();
    expect(h.getAttribute('aria-expanded')).toBeNull();
    expect(h.classList).not.toContain('collapsible-title');
    expect(h.querySelector('.sb-chevron')).toBeNull();
    (h as HTMLElement).click();
    fixture.detectChanges();
    expect(fixed.querySelector('.fixed-body')).not.toBeNull();
  });

  it('every section card and header computes the same style (one container, one header)', () => {
    const cards = [...el().querySelectorAll<HTMLElement>('app-drawer-section')];
    const heads = cards.map(c => c.querySelector<HTMLElement>('.sb-head')!);
    const card = (e: HTMLElement) => {
      const s = getComputedStyle(e);
      return [s.borderTopWidth, s.borderBottomWidth, s.borderLeftWidth, s.borderRightWidth, s.borderTopStyle, s.borderBottomStyle,
        s.borderTopLeftRadius, s.paddingTop, s.paddingLeft, s.paddingBottom, s.marginBottom].join('|');
    };
    const header = (e: HTMLElement) => {
      const s = getComputedStyle(e);
      return [s.fontSize, s.fontWeight, s.letterSpacing, s.textTransform, s.paddingTop, s.paddingLeft, s.borderBottomWidth, s.marginTop].join('|');
    };
    expect(card(cards[0])).toBe(card(cards[1]));
    expect(header(heads[0])).toBe(header(heads[1]));
    const s = getComputedStyle(cards[0]);
    expect(s.borderBottomWidth).toBe('1px');
    expect(s.borderTopLeftRadius).toBe('12px');
    expect(s.paddingTop).toBe('16px');
    const h = getComputedStyle(heads[0]);
    expect(h.fontSize).toBe('10px');
    expect(h.fontWeight).toBe('700');
    expect(h.textTransform).toBe('uppercase');
  });
});
