// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { StatsBarComponent } from './stats-bar.component';
import { TimelineService } from '../../services/timeline.service';
import { FilterService } from '../../services/filter.service';
import { EnrichmentService } from '../../services/enrichment.service';
import { Domain } from '../../models/domain';
import { makeSplitDomain } from '../../testing/report-split-fixture';
import { PostureStub, makePostureStub, postureStubProvider } from '../../testing/posture-stub';
import type { PostureBucket } from '../../models/posture/posture.types';

describe('StatsBarComponent', () => {
  let component: StatsBarComponent;
  let fixture: ComponentFixture<StatsBarComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [StatsBarComponent],
      providers: [
        { provide: TimelineService, useValue: { snapshots$: new BehaviorSubject([]), takeSnapshot: jasmine.createSpy() } },
        { provide: FilterService, useValue: { setActivePanel: jasmine.createSpy() } },
        { provide: EnrichmentService, useValue: { mappedRollup: () => ({ overall: { total: 0, mapped: 0, pct: 0 }, byTactic: [] }) } },
        postureStubProvider(makePostureStub(() => null)),
      ],
    });
    fixture = TestBed.createComponent(StatsBarComponent);
    component = fixture.componentInstance;
    component.domain = {
      techniques: [], tactics: [], groups: [], mitigations: [], tacticColumns: [],
      groupsByTechnique: new Map(), mitigationsByTechnique: new Map(),
      techniquesByGroup: new Map(),
    } as unknown as Domain;
    // Note: skipping detectChanges() — stats-bar template requires deeper Domain shape
    // than this minimal mock provides; exercising the constructor is enough for "is-created" coverage.
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});

// P2-07 (S12): the mislabelled "N mitigations implemented" is now the
// Covered/partial tally of PostureService, parents only, with the subs-on
// Covered count as a second labelled number. The relationship count stays.
describe('StatsBarComponent posture tally (P2-07)', () => {
  let fixture: ComponentFixture<StatsBarComponent>;
  let posture: PostureStub;
  let domain: Domain;

  function render(buckets: Record<string, PostureBucket>): HTMLElement {
    domain = { ...makeSplitDomain(), mitigations: [], campaigns: [], techniquesByMitigation: new Map() } as unknown as Domain;
    posture = makePostureStub(() => domain, buckets);
    TestBed.configureTestingModule({
      imports: [StatsBarComponent],
      providers: [
        { provide: TimelineService, useValue: { snapshots$: new BehaviorSubject([]), getAll: () => [] } },
        { provide: FilterService, useValue: { setActivePanel: jasmine.createSpy() } },
        { provide: EnrichmentService, useValue: { mappedRollup: () => ({ overall: { total: 5, mapped: 3, pct: 60 }, byTactic: [] }) } },
        postureStubProvider(posture),
      ],
    });
    fixture = TestBed.createComponent(StatsBarComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  const text = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
  const num = (el: HTMLElement, key: string) => Number(text(el.querySelector(`[data-posture="${key}"]`)));

  it('shows no Covered or Proven words, and no tally, on a fresh profile', () => {
    const el = render({});
    expect(el.querySelector('[data-testid="stats-posture"]')).toBeNull();
    expect(el.querySelector('.impl-bar')).toBeNull();
    expect(text(el)).not.toMatch(/\bcovered\b|\bproven\b|\bdefended\b/i);
    expect(text(el)).not.toContain('mitigations implemented');
    expect(text(el.querySelector('.coverage-sub'))).toBe('3/5 mapped');
  });

  it('shows the parents-only Covered, partial, Proven and stale tally of the rollup', () => {
    const el = render({ T1: 'covered', T2: 'partial', T4: 'proven', 'T1.001': 'covered' });
    const o = posture.rollup().overall;
    expect([num(el, 'covered'), num(el, 'partial'), num(el, 'proven'), num(el, 'stale')]).toEqual([o.covered, o.partial, o.proven, o.stale]);
    expect([o.covered, o.partial, o.proven, o.stale]).withContext('the sub-technique T1.001 is not counted').toEqual([1, 1, 1, 0]);
    expect(text(el.querySelector('[data-testid="stats-posture"]'))).toBe('Covered (self-attested): 1 of 5 assessable · partial: 1 · Proven: 1 · stale: 0');
    expect(text(el)).not.toContain('mitigations implemented');
    expect(el.querySelector('[data-posture="covered-with-subs"]')).toBeNull();
  });

  it('R16: the impl-bar width, its title and the Covered line divide by assessable; the Known total keeps every parent', () => {
    const el = render({ T1: 'covered', T2: 'covered' });
    posture.exclude(['T3']);
    fixture.detectChanges();
    const o = posture.rollup().overall;
    expect([o.total, o.assessable, o.covered]).toEqual([5, 4, 2]);
    expect([num(el, 'covered'), num(el, 'assessable'), num(el, 'known-total')]).toEqual([2, 4, 5]);
    const bar = el.querySelector('.impl-bar') as HTMLElement;
    expect(bar.getAttribute('title')).toBe('Covered (self-attested): 2 of 4 assessable parent techniques (not-reproducible runs with no proof excluded)');
    expect((bar.querySelector('.impl-fill') as HTMLElement).style.width).toBe('50%');
    expect(fixture.componentInstance.postureTally().coveredPct).toBe(50);
  });

  it('gives a 0-width impl-bar, not NaN, when every parent is excluded', () => {
    const el = render({ T1: 'covered' });
    posture.exclude(['T1', 'T2', 'T3', 'T4', 'T5']);
    fixture.detectChanges();
    expect(fixture.componentInstance.postureTally()).toEqual(jasmine.objectContaining({ assessable: 0, coveredPct: 0 }));
    expect((el.querySelector('.impl-fill') as HTMLElement).style.width).toBe('0%');
  });

  it('adds a labelled sub-technique number when includeSubtechniques is on; the parents tally does not move', () => {
    const el = render({ T1: 'covered', 'T1.001': 'covered' });
    fixture.componentInstance.toggleSubtechniques();
    fixture.detectChanges();
    expect(num(el, 'covered')).toBe(1);
    expect(text(el.querySelector('[data-posture="covered-with-subs"]'))).toBe('incl. sub-techniques: 2');
    expect(fixture.componentInstance.postureTally().coveredWithSubs).toBe(posture.rollup({ includeSubtechniques: true }).overall.covered);
  });

  it('refreshes from the posture states and keeps the relationship count', () => {
    const el = render({ T1: 'covered' });
    expect(num(el, 'covered')).toBe(1);
    posture.set({ T1: 'covered', T2: 'covered', T4: 'covered' });
    fixture.detectChanges();
    expect(num(el, 'covered')).toBe(3);
    // makeSplitDomain maps M1+M2 to T1, M1 to T2 and T1.001, M3 to T4: 5 relationships.
    expect(fixture.componentInstance.totalRelationships).toBe(5);
  });
});
