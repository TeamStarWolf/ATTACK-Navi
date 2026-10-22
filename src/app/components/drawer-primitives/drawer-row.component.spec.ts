// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The drawer's row primitive on its own: the entity, detail and plain kinds; the
// monospace id chip in every kind; links keep their target and rel; projected
// badges and head items land in the head line; a clickable row leaves its links'
// clicks to the links.
import { ChangeDetectionStrategy, Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideLocationMocks } from '@angular/common/testing';
import { DrawerRowComponent, type DrawerBadge } from './drawer-row.component';

@Component({
  standalone: true,
  imports: [DrawerRowComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="sb-list">
      <app-drawer-row class="r-entity" entityId="AC-2" idHref="https://example.org/ac-2" idClass="nist-id"
                      [badges]="badges" secondary="Account Management, a long secondary line" />
      <app-drawer-row class="r-entity2" entityId="CIS-1" secondary="Inventory">
        <span sbBadge class="sb-badge extra-badge" data-tone="warm">AWS</span>
        <button sbHead class="head-action">Show all</button>
      </app-drawer-row>
      <app-drawer-row kind="detail" class="r-detail" entityId="D3-FIM" name="File Integrity Monitoring" nameHref="https://example.org/fim"
                      rel="noopener noreferrer" nameClass="d3fend-name" description="Detects changes to files.">
        <code class="sb-code body-code">x = 1</code>
      </app-drawer-row>
      <app-drawer-row kind="detail" class="r-html" name="Procedure" [descriptionHtml]="html" />
      <app-drawer-row kind="detail" class="r-route" name="Technique page" [nameLink]="['/technique', 'enterprise', 'T1078']" />
      <app-drawer-row kind="plain" class="r-plain">3 public exploits mapped to this technique.</app-drawer-row>
      <app-drawer-row class="r-click" [clickable]="true" (rowClick)="clicks = clicks + 1" entityId="T1003.001" idHref="https://example.org/t" name="LSASS Memory" />
    </div>
  `,
})
class HostComponent {
  badges: DrawerBadge[] = [{ label: 'AC', tone: 'neutral', title: 'Access Control' }, { label: 'Significant', tone: 'success' }];
  html = 'Uses <strong>bold</strong> text<script>alert(1)</script>';
  clicks = 0;
}

describe('DrawerRowComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  const el = () => fixture.nativeElement as HTMLElement;
  const row = (cls: string) => el().querySelector<HTMLElement>(`app-drawer-row.${cls}`)!;
  const text = (e: Element | null) => (e?.textContent ?? '').replace(/\s+/g, ' ').trim();

  beforeEach(() => {
    TestBed.configureTestingModule({ imports: [HostComponent], providers: [provideRouter([]), provideLocationMocks()] });
    fixture = TestBed.createComponent(HostComponent);
    fixture.detectChanges();
  });

  it('an entity row: id chip (linked, kept class), badges with tones and titles, then the secondary line with its tooltip', () => {
    const r = row('r-entity');
    expect(r.classList).toContain('sb-row');
    expect(r.classList).toContain('sb-row--entity');
    expect(r.getAttribute('data-row-kind')).toBe('entity');
    const id = r.querySelector<HTMLAnchorElement>('a.sb-id')!;
    expect(text(id)).toBe('AC-2');
    expect(id.classList).toContain('nist-id');
    expect(id.getAttribute('href')).toBe('https://example.org/ac-2');
    expect(id.getAttribute('target')).toBe('_blank');
    expect(id.getAttribute('rel')).toBe('noopener');
    const badges = [...r.querySelectorAll('.sb-badge')];
    expect(badges.map(b => text(b))).toEqual(['AC', 'Significant']);
    expect(badges.map(b => b.getAttribute('data-tone'))).toEqual(['neutral', 'success']);
    expect(badges[0].getAttribute('title')).toBe('Access Control');
    const sec = r.querySelector('.sb-secondary')!;
    expect(text(sec)).toBe('Account Management, a long secondary line');
    expect(sec.getAttribute('title')).toBe('Account Management, a long secondary line');
    expect(r.querySelector('.sb-name')).toBeNull();
    expect(r.querySelector('.sb-desc')).toBeNull();
  });

  it('an id without a link is a plain chip; projected badges and head items sit in the head line in order', () => {
    const r = row('r-entity2');
    expect(r.querySelector('span.sb-id')).not.toBeNull();
    expect(r.querySelector('a.sb-id')).toBeNull();
    const head = r.querySelector('.sb-row-head')!;
    const order = [...head.children].map(c => c.classList.contains('sb-id') ? 'id' : c.classList.contains('extra-badge') ? 'badge'
      : c.classList.contains('head-action') ? 'action' : c.classList.contains('sb-secondary') ? 'secondary' : c.tagName);
    expect(order).toEqual(['id', 'badge', 'action', 'secondary']);
  });

  it('a detail row: name link with the given rel, description paragraph, projected body after it', () => {
    const r = row('r-detail');
    expect(r.classList).toContain('sb-row--detail');
    const name = r.querySelector<HTMLAnchorElement>('a.sb-name')!;
    expect(text(name)).toBe('File Integrity Monitoring');
    expect(name.classList).toContain('d3fend-name');
    expect(name.getAttribute('href')).toBe('https://example.org/fim');
    expect(name.getAttribute('target')).toBe('_blank');
    expect(name.getAttribute('rel')).toBe('noopener noreferrer');
    expect(r.querySelector<HTMLAnchorElement>('a.sb-id')).toBeNull();
    expect(text(r.querySelector('span.sb-id'))).toBe('D3-FIM');
    expect(text(r.querySelector('p.sb-desc'))).toBe('Detects changes to files.');
    const desc = r.querySelector('p.sb-desc')!;
    const code = r.querySelector('code.body-code')!;
    expect(desc.compareDocumentPosition(code) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('a description given as HTML is rendered and sanitised', () => {
    const p = row('r-html').querySelector('p.sb-desc')!;
    expect(p.querySelector('strong')).not.toBeNull();
    expect(p.innerHTML).not.toContain('<script');
  });

  it('an in-app name link is a routerLink', () => {
    const a = row('r-route').querySelector<HTMLAnchorElement>('a.sb-name')!;
    expect(a.getAttribute('href')).toBe('/technique/enterprise/T1078');
    expect(a.getAttribute('target')).toBeNull();
  });

  it('a plain row is the projected text only', () => {
    const r = row('r-plain');
    expect(r.classList).toContain('sb-row--plain');
    expect(r.querySelector('.sb-row-head')).toBeNull();
    expect(text(r)).toBe('3 public exploits mapped to this technique.');
  });

  it('a clickable row emits on a click on the row, not on a click on its link', () => {
    const r = row('r-click');
    expect(r.classList).toContain('sb-row--clickable');
    r.querySelector<HTMLElement>('.sb-name')!.click();
    expect(fixture.componentInstance.clicks).toBe(1);
    const link = r.querySelector<HTMLAnchorElement>('a.sb-id')!;
    link.addEventListener('click', e => e.preventDefault());
    link.click();
    expect(fixture.componentInstance.clicks).toBe(1);
  });

  it('the id chip is monospace in every row kind, and rows of a kind compute the same box', () => {
    for (const cls of ['r-entity', 'r-entity2', 'r-detail', 'r-click']) {
      expect(getComputedStyle(row(cls).querySelector('.sb-id')!).fontFamily).withContext(cls).toContain('IBM Plex Mono');
    }
    const box = (e: HTMLElement) => {
      const s = getComputedStyle(e);
      return [s.paddingTop, s.paddingLeft, s.minHeight, s.fontFamily, s.fontSize].join('|');
    };
    expect(box(row('r-entity'))).toBe(box(row('r-entity2')));
    expect(box(row('r-entity'))).toBe(box(row('r-click')));
    expect(box(row('r-detail'))).toBe(box(row('r-html')));
    expect(getComputedStyle(row('r-entity')).paddingTop).toBe('6px');
    expect(getComputedStyle(row('r-entity')).minHeight).toBe('28px');
    expect(getComputedStyle(row('r-plain')).paddingTop).toBe('0px');
    // Rows of a list are divided by a top rule, the first one excepted.
    expect(getComputedStyle(row('r-entity')).borderTopWidth).toBe('0px');
    expect(getComputedStyle(row('r-entity2')).borderTopWidth).toBe('1px');
  });
});
