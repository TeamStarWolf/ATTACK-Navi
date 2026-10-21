// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Behavioural specs for MatrixComponent against its REAL template, on the fixed
// fixture domain (src/app/testing/lens-harness.ts). The per-mode score maps are
// pinned separately by src/app/testing/lens-snapshots.spec.ts; this file pins
// what the matrix renders and how it reacts to the user.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NgZone, signal as ngSignal } from '@angular/core';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import { MatrixComponent } from './matrix.component';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';
import { DataService } from '../../services/data.service';
import { FilterService } from '../../services/filter.service';
import { HEATMAP_MODES, LENS_NA_COLOR, unavailableLenses } from '../../models/heatmap-modes';
import { ValidationService } from '../../services/validation.service';
import { ImplementationService } from '../../services/implementation.service';
import { PostureService } from '../../services/posture.service';
import { SettingsService } from '../../services/settings.service';
import { THREAT_WEIGHT_PROVIDER } from '../../models/posture/threat-weight';
import { isThreatGap } from '../../models/posture/gap';
import { CONTRADICTED_WORDS } from '../../models/posture/posture-vocabulary';
import { ControlsService } from '../../services/controls.service';
import { BehaviorSubject } from 'rxjs';
import SNAPSHOTS from '../../testing/__snapshots__/lens-snapshots.json';
import {
  LENS_RUN_AGES, controlsProvider, lensPostureTodayProvider, lensRunTechniques, parseFixtureDomain, resetBrowserState,
  seedLensRuns, signal, signalStubProviders,
} from '../../testing/lens-harness';

describe('MatrixComponent (rendered, fixture domain)', () => {
  let domain: Domain;
  let fixture: ComponentFixture<MatrixComponent>;
  let filter: FilterService;
  let host: HTMLElement;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [MatrixComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        ...signalStubProviders(),
        controlsProvider(domain),
      ],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    filter = TestBed.inject(FilterService);
    fixture = TestBed.createComponent(MatrixComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => resetBrowserState());

  const column = (tacticName: string): HTMLElement =>
    host.querySelector(`td.tactic-col[data-tactic="${tacticName}"]`) as HTMLElement;
  const cellIds = (el: ParentNode): string[] =>
    [...el.querySelectorAll('[data-tech-id]')].map(e => e.getAttribute('data-tech-id')!);

  it('renders one header per tactic, in matrix order', () => {
    const headers = [...host.querySelectorAll('th.tactic-header .tactic-name-text')].map(e => e.textContent!.trim());
    expect(headers).toEqual(domain.tacticColumns.map(c => c.tactic.name));
    expect(headers.length).toBe(15);
  });

  it('renders every parent technique of a tactic with its sub-techniques expanded', () => {
    for (const col of domain.tacticColumns) {
      const expected: string[] = [];
      for (const t of col.techniques) {
        expected.push(t.id);
        for (const s of t.subtechniques) expected.push(s.id);
      }
      expect(cellIds(column(col.tactic.name))).withContext(col.tactic.name).toEqual(expected);
    }
  });

  it('shows ATT&CK id and name on each cell', () => {
    const t = domain.techniques.find(x => x.attackId === 'T1003') as Technique;
    const cell = host.querySelector(`[data-tech-id="${t.id}"] .cell`) as HTMLElement;
    expect(cell.querySelector('.id')!.textContent!.trim()).toBe('T1003');
    expect(cell.querySelector('.name')!.textContent!.trim()).toBe(t.name);
    expect(cell.getAttribute('aria-label')).toBe(`T1003: ${t.name}`);
  });

  it('collapsing a parent removes its sub-technique cells', () => {
    const parent = domain.techniques.find(x => x.attackId === 'T1003') as Technique;
    const sub = parent.subtechniques[0];
    expect(host.querySelector(`[data-tech-id="${sub.id}"]`)).not.toBeNull();
    const btn = host.querySelector(`[data-tech-id="${parent.id}"]`)!.parentElement!.querySelector('.expand-btn') as HTMLButtonElement;
    btn.click();
    fixture.detectChanges();
    expect(host.querySelector(`[data-tech-id="${sub.id}"]`)).toBeNull();
  });

  it('clicking a cell selects that technique and marks it selected', () => {
    const t = domain.techniques.find(x => x.attackId === 'T1082') as Technique;
    let selected: Technique | null = null;
    filter.selectedTechnique$.subscribe(v => (selected = v));
    (host.querySelector(`[data-tech-id="${t.id}"] .cell`) as HTMLElement).click();
    fixture.detectChanges();
    expect(selected!.attackId).toBe('T1082');
    expect(host.querySelector(`[data-tech-id="${t.id}"] .cell`)!.classList).toContain('selected');
  });

  it('shows the no-results state for a search that matches nothing', () => {
    expect(host.querySelector('.no-results')).toBeNull();
    filter.setTechniqueSearch('zzzz-no-such-technique');
    fixture.detectChanges();
    expect(host.querySelector('.no-results')).not.toBeNull();
  });

  it('repaints cells when the heatmap lens changes', () => {
    // Pick a technique with Sigma rules and one without, from the stub data.
    const parents = domain.techniques.filter(t => !t.isSubtechnique);
    const withRules = parents.find(t => signal('sigma', t.attackId) > 0)!;
    const without = parents.find(t => signal('sigma', t.attackId) === 0)!;
    const bg = (t: Technique) => (host.querySelector(`[data-tech-id="${t.id}"] .cell`) as HTMLElement).style.backgroundColor;

    filter.setHeatmapMode('sigma');
    fixture.detectChanges();
    const sigmaWith = bg(withRules);
    const sigmaWithout = bg(without);
    expect(sigmaWith).not.toBe(sigmaWithout);

    filter.setHeatmapMode('coverage');
    fixture.detectChanges();
    expect([bg(withRules), bg(without)]).not.toEqual([sigmaWith, sigmaWithout]);
  });

  // E1.2 PR 2, no silent zeros: switching to ICS, a lens whose domains[] lacks
  // ics never renders an all-zero map; every cell shows 'n/a in this domain'.
  it('renders every lens that has no ICS data as n/a on every cell, never as its zero colour', () => {
    fixture.componentRef.setInput('attackDomain', 'ics');
    const disabled = unavailableLenses('ics');
    expect(disabled.length).toBe(23);
    const parent = domain.techniques.find(x => !x.isSubtechnique)!;
    for (const def of disabled) {
      filter.setHeatmapMode(def.value);
      fixture.detectChanges();
      expect(fixture.componentInstance.lensUnavailable).withContext(def.value).toBeTrue();
      const cells = Array.from(host.querySelectorAll<HTMLElement>('app-technique-cell .cell'));
      expect(cells.length).withContext(def.value).toBeGreaterThan(0);
      const notNa = cells.filter(c => !c.classList.contains('lens-na'));
      expect(notNa.length).withContext(`${def.value}: cells painted on the ramp`).toBe(0);
      expect(fixture.componentInstance.getMinimapCellColor(parent)).withContext(def.value).toBe(LENS_NA_COLOR);
      // No zero metric badge either (D3FEND would otherwise print a 0 on every cell).
      expect(host.querySelectorAll('.d3fend-badge, .atomic-badge, .cri-hm-badge').length).withContext(def.value).toBe(0);
    }
  });

  it('keeps painting a lens that has ICS data, and every lens on Enterprise except F3 origin', () => {
    fixture.componentRef.setInput('attackDomain', 'ics');
    filter.setHeatmapMode('frequency');
    fixture.detectChanges();
    expect(host.querySelectorAll('.cell.lens-na').length).toBe(0);

    fixture.componentRef.setInput('attackDomain', 'enterprise');
    for (const def of HEATMAP_MODES) {
      filter.setHeatmapMode(def.value);
      fixture.detectChanges();
      const naCells = host.querySelectorAll('.cell.lens-na').length;
      expect(naCells > 0).withContext(def.value).toBe(def.value === 'f3-origin');
    }
  });
});

// §7 Decay, Rendering (P2-13): on the Posture lens a stale cell's aria-label
// and tooltip name its proof age and the window it passed, "stale (N days;
// window W)". The harness pins POSTURE_TODAY and seeds one fresh and one
// stale own run (120 days old on the default 90-day own-run window).
describe('MatrixComponent (rendered, Posture lens, stale cell)', () => {
  let domain: Domain;
  let fixture: ComponentFixture<MatrixComponent>;
  let host: HTMLElement;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [MatrixComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        ...signalStubProviders(),
        controlsProvider(domain),
        lensPostureTodayProvider(),
      ],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    seedLensRuns(TestBed.inject(ValidationService), domain);
    fixture = TestBed.createComponent(MatrixComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    TestBed.inject(FilterService).setHeatmapMode('posture');
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => resetBrowserState());

  const cellOf = (t: Technique) => host.querySelector(`[data-tech-id="${t.id}"] .cell`) as HTMLElement;
  const tooltipOf = (t: Technique): string => {
    const cellHost = host.querySelector(`[data-tech-id="${t.id}"] app-technique-cell`) as HTMLElement;
    cellHost.dispatchEvent(new MouseEvent('mouseenter', { clientX: 10, clientY: 10 }));
    fixture.detectChanges();
    return cellHost.querySelector('.tt-posture')!.textContent!.trim();
  };

  it('names the proof age and the decay window on a stale cell, in the aria-label and the tooltip', () => {
    const { stale } = lensRunTechniques(domain);
    const words = `stale (${LENS_RUN_AGES.stale} days; window 90)`;
    expect(cellOf(stale).getAttribute('aria-label')).toBe(`${stale.attackId}: ${stale.name}, Proven (your run), ${words}`);
    expect(tooltipOf(stale)).toBe(`Proven (your run), ${words}`);
  });

  it('keeps the plain badge on a fresh proof', () => {
    const { fresh } = lensRunTechniques(domain);
    expect(cellOf(fresh).getAttribute('aria-label')).toBe(`${fresh.attackId}: ${fresh.name}, Proven (your run)`);
    expect(tooltipOf(fresh)).toBe('Proven (your run)');
  });
});

// RP-F decision 11: a contradicted cell (an implemented M1015 control and
// mitigation, then a later failed run on T1078) says "contradicted" in its
// aria-label and tooltip on the Posture, Covered and Status lenses, the way a
// stale cell names its age; T1003 (the same M1015 marks, no failed run) does not.
describe('MatrixComponent (rendered, contradicted cell, RP-F decision 11)', () => {
  let domain: Domain;
  let fixture: ComponentFixture<MatrixComponent>;
  let host: HTMLElement;
  const tech = (attackId: string) => domain.techniques.find(t => t.attackId === attackId) as Technique;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    const m1015 = domain.mitigations.find(m => m.attackId === 'M1015')!;
    TestBed.configureTestingModule({
      imports: [MatrixComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        ...signalStubProviders(),
        {
          provide: ControlsService,
          useValue: {
            controls$: new BehaviorSubject([{
              id: 'ctl-M1015', name: 'AD configuration', framework: 'Custom', controlRef: 'M1015', description: '',
              mitigationIds: [m1015.id], status: 'implemented',
            }]),
            computeCoverage: () => new Map(),
          },
        },
        lensPostureTodayProvider(),
      ],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    TestBed.inject(ImplementationService).setStatus(m1015.id, 'implemented');
    TestBed.inject(ValidationService).importJson(JSON.stringify({ runs: [
      { id: 'f-t1078', techniqueId: 'T1078', runDate: '2026-10-20T08:00:00.000Z', status: 'failed', attackResult: 'executed' },
    ] }));
    fixture = TestBed.createComponent(MatrixComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => resetBrowserState());

  const cellOf = (t: Technique) => host.querySelector(`[data-tech-id="${t.id}"] .cell`) as HTMLElement;
  const tooltipOf = (t: Technique): string => {
    const cellHost = host.querySelector(`[data-tech-id="${t.id}"] app-technique-cell`) as HTMLElement;
    cellHost.dispatchEvent(new MouseEvent('mouseenter', { clientX: 10, clientY: 10 }));
    fixture.detectChanges();
    const text = cellHost.querySelector('.tt-posture')!.textContent!.trim();
    cellHost.dispatchEvent(new MouseEvent('mouseleave'));
    fixture.detectChanges();
    return text;
  };

  for (const lens of ['posture', 'covered', 'status'] as const) {
    it(`${lens}: the contradicted T1078 cell says so in its aria-label and tooltip; T1003 does not`, () => {
      expect(TestBed.inject(PostureService).stateFor(tech('T1078')).subStates).toContain('contradicted');
      TestBed.inject(FilterService).setHeatmapMode(lens);
      fixture.detectChanges();
      const t1078 = tech('T1078');
      const aria = cellOf(t1078).getAttribute('aria-label')!;
      expect(aria).toMatch(new RegExp(`^T1078: ${t1078.name}, .+, ${CONTRADICTED_WORDS.replace(/[()]/g, '\\$&')}$`));
      expect(tooltipOf(t1078)).toMatch(new RegExp(`, ${CONTRADICTED_WORDS.replace(/[()]/g, '\\$&')}$`));
      const t1003 = tech('T1003');
      expect(cellOf(t1003).getAttribute('aria-label')).not.toContain('contradicted');
      expect(tooltipOf(t1003)).not.toContain('contradicted');
    });
  }

  it('the Proven and Controls lenses keep their own words (not in decision 11)', () => {
    for (const lens of ['proven', 'controls'] as const) {
      TestBed.inject(FilterService).setHeatmapMode(lens);
      fixture.detectChanges();
      expect(cellOf(tech('T1078')).getAttribute('aria-label')).withContext(lens).not.toContain('contradicted');
    }
  });
});

// P2-17 (E2.2-d): the My marks bar and the Threat gaps outline sit on top of
// every lens and never change its colour. No controls seed here, so the only
// marks are the ones each spec records.
describe('MatrixComponent (rendered, My marks and Threat gaps, P2-17)', () => {
  let domain: Domain;
  let fixture: ComponentFixture<MatrixComponent>;
  let filter: FilterService;
  let host: HTMLElement;
  /** A stand-in for the bound threat profile: the token's three members, all reactive. */
  const revision = ngSignal(0);
  const parents = ngSignal<ReadonlySet<string>>(new Set());
  let weight: (id: string) => number = () => 0;

  /**
   * Console calls carrying NG0101 (ApplicationRef.tick is called recursively). The ErrorHandler
   * reports it as console.error('ERROR', err) and the spec still passes, so every spec in this
   * block asserts the count is zero in afterEach.
   */
  let ng0101: () => unknown[][];

  /**
   * The application tick after a store or profile write, run INSIDE the NgZone. TestBed.tick() is a
   * bare ApplicationRef.tick(); called from the test body it runs outside the zone, and flushing the
   * root effect behind PostureService.states$ (toObservable, created in the zone) then enters and
   * leaves the zone at depth 0. That leave emits onMicrotaskEmpty, the zone scheduler starts a
   * second tick while the first is still running, and Angular logs NG0101. In the app every tick
   * already starts inside the zone, which is what this helper reproduces.
   */
  const appTick = (): void => TestBed.inject(NgZone).run(() => TestBed.tick());

  const build = (seed: () => void = () => undefined): void => {
    seed();
    fixture = TestBed.createComponent(MatrixComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  };

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    // The all-groups weight over every parent: the shape of the default profile.
    weight = (id: string) => domain.groupsByTechnique.get(id)?.length ?? 0;
    parents.set(new Set(domain.techniques.filter(t => !t.isSubtechnique).map(t => t.id)));
    TestBed.configureTestingModule({
      imports: [MatrixComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        ...signalStubProviders(),
        { provide: THREAT_WEIGHT_PROVIDER, useValue: { revision, parents, weight: (id: string) => weight(id) } },
      ],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    filter = TestBed.inject(FilterService);
    const error = spyOn(console, 'error').and.callThrough();
    const warn = spyOn(console, 'warn').and.callThrough();
    ng0101 = () => [...error.calls.allArgs(), ...warn.calls.allArgs()]
      .filter(args => args.some(a => String((a as { message?: unknown })?.message ?? a).includes('NG0101')));
  });

  afterEach(() => {
    expect(ng0101()).withContext('NG0101: ApplicationRef.tick is called recursively').toEqual([]);
    resetBrowserState();
  });

  /** The distinct techniques whose cells hold `selector` (a technique in several tactics has a cell in each). */
  const idsWith = (selector: string): string[] =>
    [...new Set([...host.querySelectorAll(selector)].map(e => e.closest('[data-tech-id]')!.getAttribute('data-tech-id')!))].sort();
  /** How many rendered cells belong to `ids`. */
  const cellCount = (ids: readonly string[]): number =>
    [...host.querySelectorAll('[data-tech-id]')].filter(e => ids.includes(e.getAttribute('data-tech-id')!)).length;
  const markedIds = (bucket?: string): string[] => idsWith(bucket ? `.my-mark[data-bucket="${bucket}"]` : '.my-mark');
  const outlinedIds = (): string[] => idsWith('.threat-gap-outline');
  const m1047 = () => domain.mitigations.find(m => m.attackId === 'M1047')!;
  const implementM1047 = () => TestBed.inject(ImplementationService).setStatus(m1047().id, 'implemented');
  const frequencySnapshot = (SNAPSHOTS as unknown as Record<string, Record<string, [unknown, string]>>)['frequency'];

  it('[AC] My marks visible on the Prevalence lens: exactly the 13 cells of M1047 carry a covered bar, and getCellColor is unchanged', () => {
    build(implementM1047);
    filter.setHeatmapMode('frequency');
    fixture.detectChanges();
    expect(filter.getStateSnapshot().heatmapMode).toBe('frequency');
    const expected = (domain.techniquesByMitigation.get(m1047().id) ?? []).map(t => t.id).sort();
    expect(expected.length).toBe(13);   // §1.17: M1047 maps 13 fixture techniques (8 parents), under the D16 threshold of 15
    expect(markedIds('covered')).toEqual(expected);
    expect(markedIds()).toEqual(expected);
    // Every cell of those 13 techniques (one per tactic column it sits in) has the bar; no other cell does.
    expect(host.querySelectorAll('.my-mark[data-bucket="covered"]').length).toBe(cellCount(expected));
    expect(host.querySelectorAll('.my-mark').length).toBe(cellCount(expected));
    // The minimap colour is the committed Prevalence snapshot, technique for technique.
    const matrix = fixture.componentInstance;
    for (const t of domain.techniques) {
      expect(matrix.getCellColor(t)).withContext(t.attackId).toBe(frequencySnapshot[t.attackId][1]);
    }
    const cellHost = host.querySelector(`[data-tech-id="${expected[0]}"] app-technique-cell`)!;
    expect(cellHost.querySelector('.my-mark')!.getAttribute('aria-hidden')).toBe('true');
  });

  it('follows the store: recording and clearing the mark adds and removes the bars', () => {
    build();
    expect(markedIds()).toEqual([]);
    implementM1047();
    appTick();
    fixture.detectChanges();
    expect(markedIds('covered').length).toBe(13);
    TestBed.inject(ImplementationService).setStatus(m1047().id, null);
    appTick();
    fixture.detectChanges();
    expect(markedIds()).toEqual([]);
  });

  it('draws the bar on every lens, and hides it when the My marks setting is off', () => {
    build(implementM1047);
    for (const mode of ['frequency', 'coverage', 'posture', 'kev', 'unified'] as const) {
      filter.setHeatmapMode(mode);
      fixture.detectChanges();
      expect(markedIds('covered').length).withContext(mode).toBe(13);
    }
    const settings = TestBed.inject(SettingsService);
    settings.update({ cellDisplay: { ...settings.current.cellDisplay, myMarks: false } });
    fixture.detectChanges();
    expect(markedIds()).toEqual([]);
  });

  it('fresh profile: no .my-mark and no threat-gap outline anywhere, on any lens', () => {
    build();
    for (const mode of ['frequency', 'posture', 'coverage', 'unified', 'status'] as const) {
      filter.setHeatmapMode(mode);
      fixture.detectChanges();
      expect(host.querySelectorAll('.my-mark').length).withContext(mode).toBe(0);
      expect(host.querySelectorAll('.threat-gap-outline').length).withContext(mode).toBe(0);
    }
  });

  it('Threat gaps: outlines exactly the predicate set, never a marked M1047 cell, and the lens colour is unchanged', () => {
    build(implementM1047);
    filter.setHeatmapMode('frequency');
    fixture.detectChanges();
    const before = domain.techniques.map(t => fixture.componentInstance.getCellColor(t));
    expect(outlinedIds()).toEqual([]);
    filter.setThreatGapOverlay(true);
    fixture.detectChanges();
    const posture = TestBed.inject(PostureService);
    const q75 = fixture.componentInstance.threatGapQ75();
    const expected = domain.techniques.filter(t => isThreatGap(posture.stateFor(t), q75)).map(t => t.id).sort();
    expect(expected.length).toBeGreaterThan(0);
    expect(outlinedIds()).toEqual(expected);
    expect(host.querySelectorAll('.threat-gap-outline').length).toBe(cellCount(expected));
    const marked = new Set(markedIds());
    expect(outlinedIds().filter(id => marked.has(id))).toEqual([]);
    expect(domain.techniques.map(t => fixture.componentInstance.getCellColor(t))).toEqual(before);
    const gap = host.querySelector(`[data-tech-id="${expected[0]}"] .cell`)!;
    expect(gap.getAttribute('aria-label')).toMatch(/, threat gap$/);
    filter.setThreatGapOverlay(false);
    fixture.detectChanges();
    expect(outlinedIds()).toEqual([]);
  });

  it('Threat gaps: a threat profile change moves q75 and the outlines', () => {
    build();
    filter.setThreatGapOverlay(true);
    fixture.detectChanges();
    const posture = TestBed.inject(PostureService);
    const before = outlinedIds();
    const q75Before = fixture.componentInstance.threatGapQ75();
    // One-technique profile: its weight alone sets q75; every other weight is 0.
    const parentIds = domain.techniques.filter(t => !t.isSubtechnique).map(t => t.id);
    const target = parentIds[parentIds.length - 1];
    weight = (id: string) => (id === target ? 50 : 0);
    parents.set(new Set([target]));
    revision.update(n => n + 1);
    appTick();
    fixture.detectChanges();
    expect(fixture.componentInstance.threatGapQ75()).toBe(50);
    expect(q75Before).not.toBe(50);
    const after = outlinedIds();
    const expected = domain.techniques.filter(t => isThreatGap(posture.stateFor(t), 50)).map(t => t.id).sort();
    expect(after).toEqual(expected);
    expect(after).not.toEqual(before);
  });

  it('no recursive tick: both overlays on with marked cells, then a mark and a profile change, log no NG0101', () => {
    build(implementM1047);
    filter.setHeatmapMode('posture');
    filter.setThreatGapOverlay(true);
    fixture.detectChanges();
    appTick();
    expect(markedIds('covered').length).toBe(13);
    expect(outlinedIds().length).toBeGreaterThan(0);
    // A second mark, then clearing it: each store write is followed by the application tick.
    const m1047Ids = new Set((domain.techniquesByMitigation.get(m1047().id) ?? []).map(t => t.id));
    const second = domain.mitigations.find(m => m.attackId !== 'M1047'
      && (domain.techniquesByMitigation.get(m.id) ?? []).some(t => !m1047Ids.has(t.id)))!;
    TestBed.inject(ImplementationService).setStatus(second.id, 'implemented');
    appTick();
    fixture.detectChanges();
    expect(markedIds().length).toBeGreaterThan(13);
    TestBed.inject(ImplementationService).setStatus(second.id, null);
    appTick();
    fixture.detectChanges();
    expect(markedIds('covered').length).toBe(13);
    // A threat profile change with both overlays still on.
    const parentIds = domain.techniques.filter(t => !t.isSubtechnique).map(t => t.id);
    weight = (id: string) => (id === parentIds[0] ? 50 : 0);
    parents.set(new Set([parentIds[0]]));
    revision.update(n => n + 1);
    appTick();
    fixture.detectChanges();
    expect(fixture.componentInstance.threatGapQ75()).toBe(50);
    expect(markedIds('covered').length).toBe(13);
    expect(ng0101()).withContext('NG0101 during the overlay updates').toEqual([]);
  });

  it('ICS: the exposure term is 0 for every technique (exposure is Enterprise only)', () => {
    build();
    const posture = TestBed.inject(PostureService);
    expect([...posture.states().values()].some(st => st.exposureWeight > 0)).withContext('enterprise').toBeTrue();
    (TestBed.inject(DataService) as unknown as { currentDomain$: { next(d: string): void } }).currentDomain$.next('ics');
    expect([...posture.states().values()].every(st => st.exposureWeight === 0)).withContext('ics').toBeTrue();
  });
});
