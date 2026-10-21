// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// PostureCardComponent (Phase 2 design §3 P2-07): Known / Covered / partial /
// Proven / stale over every parent technique, from PostureService.rollup;
// Covered and Proven words only when PostureService.ownerWords() is true.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Provider, signal } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { PostureCardComponent } from './posture-card.component';
import { DataService } from '../../services/data.service';
import { THREAT_WEIGHT_PROVIDER } from '../../models/posture/threat-weight';
import { Domain } from '../../models/domain';
import type { PostureBucket } from '../../models/posture/posture.types';
import { makeSplitDomain } from '../../testing/report-split-fixture';
import { PostureStub, makePostureStub, postureStubProvider } from '../../testing/posture-stub';

/** A THREAT_WEIGHT_PROVIDER stand-in whose profile holds the given parent STIX ids. */
function threatWeightStub(parentTechniqueIds: readonly string[]): Provider {
  return { provide: THREAT_WEIGHT_PROVIDER, useValue: { weight: () => 0, revision: signal(0), parents: signal(new Set(parentTechniqueIds)) } };
}

describe('PostureCardComponent (P2-07)', () => {
  let fixture: ComponentFixture<PostureCardComponent>;
  let posture: PostureStub;
  let domain: Domain;

  // `threatRelevant` is the parent attackIds in the shared profile; the threat-relevant
  // scope counts exactly those (by STIX id). Default (undefined): every parent technique.
  function render(buckets: Record<string, PostureBucket>, scope?: 'all' | 'threat-relevant', threatRelevant?: string[]): HTMLElement {
    domain = makeSplitDomain();
    posture = makePostureStub(() => domain, buckets);
    const parentIds = (threatRelevant === undefined
      ? domain.techniques.filter(t => !t.isSubtechnique)
      : domain.techniques.filter(t => threatRelevant.includes(t.attackId))
    ).map(t => t.id);
    TestBed.configureTestingModule({
      imports: [PostureCardComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(domain) } },
        postureStubProvider(posture),
        threatWeightStub(parentIds),
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

  it('R16: Covered reads "N of assessable"; an excluded technique lowers assessable and leaves the Known total', () => {
    const el = render({ T1: 'covered', T2: 'partial' });
    expect([num(el, 'covered'), num(el, 'assessable'), num(el, 'known-total')]).toEqual([1, 5, 5]);
    posture.exclude(['T3']);
    fixture.detectChanges();
    const o = posture.rollup().overall;
    expect([o.total, o.assessable]).toEqual([5, 4]);
    expect([num(el, 'covered'), num(el, 'assessable'), num(el, 'known-total')]).toEqual([1, 4, 5]);
    expect(text(el.querySelector('.pc-row--covered dd'))).toBe('1 of 4 assessable');
  });

  it("scope 'threat-relevant' takes assessable from the profile's parent techniques", () => {
    const el = render({ T1: 'covered' }, 'threat-relevant', ['T1', 'T2', 'T3']);
    posture.exclude(['T2']);
    fixture.detectChanges();
    expect([num(el, 'known-total'), num(el, 'assessable')]).toEqual([3, 2]);
  });

  it('recomputes when the posture states change', () => {
    const el = render({ T1: 'covered' });
    expect(num(el, 'covered')).toBe(1);
    posture.set({ T1: 'covered', T2: 'covered' });
    fixture.detectChanges();
    expect(num(el, 'covered')).toBe(2);
  });

  it("scope 'threat-relevant' tallies only the parents in the profile", () => {
    const el = render({ T1: 'covered', T2: 'partial', T4: 'covered' }, 'threat-relevant', ['T1', 'T2', 'T3']);
    // Profile = T1, T2, T3: T1 covered, T2 partial; T1 and T2 mapped. T4 (covered) is out of profile.
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
        threatWeightStub([]),
      ],
    });
    const f = TestBed.createComponent(PostureCardComponent);
    f.componentRef.setInput('scope', 'threat-relevant');
    f.detectChanges();
    expect(f.componentInstance.tally()).toEqual({ total: 0, assessable: 0, mapped: 0, covered: 0, partial: 0, proven: 0, stale: 0 });
  });

  // RP-F item 6: the ctem board read 'threat-relevant techniques: 0' while the domain loaded.
  it("scope 'threat-relevant' says it is loading, not 0, until the domain arrives", () => {
    const d = makeSplitDomain();
    const domain$ = new BehaviorSubject<Domain | null>(null);
    TestBed.configureTestingModule({
      imports: [PostureCardComponent],
      providers: [
        { provide: DataService, useValue: { domain$ } },
        postureStubProvider(makePostureStub(() => domain$.value, {})),
        threatWeightStub(d.techniques.filter(t => !t.isSubtechnique).map(t => t.id)),
      ],
    });
    const f = TestBed.createComponent(PostureCardComponent);
    f.componentRef.setInput('scope', 'threat-relevant');
    f.detectChanges();
    const el = f.nativeElement as HTMLElement;
    const line = el.querySelector('[data-testid="threat-relevant-line"]')!;
    expect(text(line)).toBe('threat-relevant techniques: loading the domain…');
    expect(line.getAttribute('aria-busy')).toBe('true');
    expect(el.querySelector('[data-posture="threat-relevant"]')).toBeNull();

    domain$.next(d);
    f.detectChanges();
    expect(el.querySelector('[data-testid="threat-relevant-loading"]')).toBeNull();
    expect(num(el, 'threat-relevant')).toBe(d.techniques.filter(t => !t.isSubtechnique).length);

    domain$.next(null);   // a domain switch: null, then the new domain
    f.detectChanges();
    expect(el.querySelector('[data-testid="threat-relevant-loading"]')).not.toBeNull();
  });

  it("scope 'threat-relevant' re-renders when the token's parents() signal changes", () => {
    const d = makeSplitDomain();
    const parents = signal<ReadonlySet<string>>(new Set([d.techniques.find(t => t.attackId === 'T1')!.id]));
    const stub = makePostureStub(() => d, {});
    TestBed.configureTestingModule({
      imports: [PostureCardComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(d) } },
        postureStubProvider(stub),
        { provide: THREAT_WEIGHT_PROVIDER, useValue: { weight: () => 0, revision: signal(0), parents } },
      ],
    });
    const f = TestBed.createComponent(PostureCardComponent);
    f.componentRef.setInput('scope', 'threat-relevant');
    f.detectChanges();
    const line = () => Number(((f.nativeElement as HTMLElement).querySelector('[data-posture="threat-relevant"]')?.textContent ?? '').trim());
    expect(line()).toBe(1);

    const allParents = d.techniques.filter(t => !t.isSubtechnique);
    parents.set(new Set(allParents.map(t => t.id)));   // a real signal change
    f.detectChanges();
    expect(line()).toBe(allParents.length);
  });
});
