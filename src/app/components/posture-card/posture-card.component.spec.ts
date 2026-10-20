// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// PostureCardComponent (Phase 2 design §3 P2-07): Known / Covered / partial /
// Proven / stale over every parent technique, from PostureService.rollup;
// Covered and Proven words only when PostureService.ownerWords() is true.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { PostureCardComponent } from './posture-card.component';
import { DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';
import type { PostureBucket, PostureState } from '../../models/posture/posture.types';
import { makeSplitDomain } from '../../testing/report-split-fixture';
import { PostureStub, makePostureStub, postureStubProvider } from '../../testing/posture-stub';

describe('PostureCardComponent (P2-07)', () => {
  let fixture: ComponentFixture<PostureCardComponent>;
  let posture: PostureStub;
  let domain: Domain;

  function render(buckets: Record<string, PostureBucket>, scope?: 'all' | 'threat-relevant', weightless: string[] = []): HTMLElement {
    domain = makeSplitDomain();
    posture = makePostureStub(() => domain, buckets);
    const stateFor = posture.stateFor;
    // A threat weight of 0 for the named techniques, 1 for the rest.
    const weighted = {
      ...posture,
      stateFor: (t: Parameters<PostureStub['stateFor']>[0]): PostureState =>
        ({ ...stateFor(t), threatWeight: weightless.includes(t.attackId) ? 0 : 1 }),
    };
    TestBed.configureTestingModule({
      imports: [PostureCardComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(domain) } },
        postureStubProvider(weighted as PostureStub),
      ],
    });
    fixture = TestBed.createComponent(PostureCardComponent);
    if (scope) fixture.componentRef.setInput('scope', scope);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  const text = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
  const num = (el: HTMLElement, key: string) => Number(text(el.querySelector(`[data-posture="${key}"]`)));

  it("is headed 'Posture' and defaults to scope 'all'", () => {
    const el = render({});
    expect(text(el.querySelector('h3'))).toBe('Posture');
    expect(fixture.componentInstance.scope).toBe('all');
    expect(el.querySelector('[data-testid="posture-card"]')!.getAttribute('data-scope')).toBe('all');
  });

  it('shows Known only on a fresh profile: no Covered or Proven words', () => {
    const el = render({});
    const o = posture.rollup().overall;
    expect([num(el, 'known-mapped'), num(el, 'known-total')]).toEqual([o.mapped, o.total]);
    expect([o.mapped, o.total]).toEqual([3, 5]);
    for (const key of ['covered', 'partial', 'proven', 'stale']) expect(el.querySelector(`[data-posture="${key}"]`)).withContext(key).toBeNull();
    expect(text(el)).not.toMatch(/\bcovered\b|\bproven\b|\bdefended\b/i);
    expect(text(el)).toContain('No data of yours recorded');
  });

  it('shows the rollup tally over parent techniques when the owner has data', () => {
    const el = render({ T1: 'covered', T2: 'partial', T4: 'proven', T5: 'stale', 'T1.001': 'covered' });
    const o = posture.rollup().overall;
    expect([num(el, 'known-mapped'), num(el, 'known-total'), num(el, 'covered'), num(el, 'partial'), num(el, 'proven'), num(el, 'stale')])
      .toEqual([o.mapped, o.total, o.covered, o.partial, o.proven, o.stale]);
    expect([o.covered, o.partial, o.proven, o.stale]).withContext('the sub-technique does not count').toEqual([1, 1, 1, 1]);
    expect(text(el)).toContain('Covered (self-attested)');
    expect(text(el)).toContain('Proven');
    expect(text(el)).not.toContain('No data of yours recorded');
  });

  it('recomputes when the posture states change', () => {
    const el = render({ T1: 'covered' });
    expect(num(el, 'covered')).toBe(1);
    posture.set({ T1: 'covered', T2: 'covered' });
    fixture.detectChanges();
    expect(num(el, 'covered')).toBe(2);
  });

  it("scope 'threat-relevant' tallies only the parents with a threat weight", () => {
    const el = render({ T1: 'covered', T2: 'partial', T4: 'covered' }, 'threat-relevant', ['T4', 'T5']);
    // T1, T2, T3 remain: T1 covered, T2 partial; T1 and T2 mapped.
    expect([num(el, 'known-mapped'), num(el, 'known-total'), num(el, 'covered'), num(el, 'partial'), num(el, 'proven')]).toEqual([2, 3, 1, 1, 0]);
    expect(el.querySelector('[data-testid="posture-card"]')!.getAttribute('data-scope')).toBe('threat-relevant');
  });

  it('a null scope falls back to all', () => {
    render({});
    fixture.componentRef.setInput('scope', null);
    fixture.detectChanges();
    expect(fixture.componentInstance.scope).toBe('all');
  });

  it("scope 'threat-relevant' with no domain loaded shows zeros", () => {
    TestBed.configureTestingModule({
      imports: [PostureCardComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) } },
        postureStubProvider(makePostureStub(() => null)),
      ],
    });
    const f = TestBed.createComponent(PostureCardComponent);
    f.componentRef.setInput('scope', 'threat-relevant');
    f.detectChanges();
    expect(f.componentInstance.tally()).toEqual({ total: 0, mapped: 0, covered: 0, partial: 0, proven: 0, stale: 0 });
  });
});
