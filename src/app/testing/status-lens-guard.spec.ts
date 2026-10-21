// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The breadth guard (D16, Phase 2 design §6) on every P2-14 surface, on the
// lens fixture (lens-harness.ts) with the real PostureService and its stores
// and POSTURE_TODAY pinned (R1, R22). No owner data except what each spec
// records: no implementation cycle, no fixture controls.
//
//   - M1026 (16 techniques, broader than the default threshold 15)
//     implemented: the same 16 refs are partial in PostureService.states(),
//     score 1 on heat=covered, the 'implemented, partial via M1026' stop on
//     heat=status, and match no impl= value (impl=implemented included);
//   - M1047 (13) implemented: the same 13 refs are full in all four;
//   - the posture card's diff equals the Covered lens's diff;
//   - Proven: the harness's own runs score 2 (fresh) and 1 (stale), and one
//     range-scoped v2 run scores 2 with the 'lab' badge;
//   - Covered: full and partial values; controls: the partial stop;
//   - the four P2-14 ramps are ordinal and CVD-safe in both themes.
//
// Precondition (§1.17): the loaded techniquesByMitigation counts are M1026 = 16
// and M1047 = 13; mitigation() fails loudly when they move.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { MatrixComponent } from '../components/matrix/matrix.component';
import { PostureCardComponent } from '../components/posture-card/posture-card.component';
import { TechniqueCellComponent } from '../components/technique-cell/technique-cell.component';
import type { Domain } from '../models/domain';
import type { Mitigation } from '../models/mitigation';
import type { Technique } from '../models/technique';
import { HEATMAP_MODES, heatmapModeDef } from '../models/heatmap-modes';
import { CVD_KINDS, hexContrast, relativeLuminance, simulateCvd } from '../models/cvd';
import { POSTURE_SURFACE, type PostureTheme, postureFill, postureLensCell } from '../models/posture/posture-ramp';
import {
  type LensLegendStop, controlStop, controlsLegendStops, coveredColor, coveredLegendStops, coveredProject,
  provenColor, provenLabBadge, provenLegendStops, provenProject, statusLegendStops, statusStopFill,
} from '../models/posture/lens-ramps';
import { PROVEN } from '../models/posture/posture-vocabulary';
import { type TechniqueRefKey, refForTechnique, techniqueRefKey } from '../models/technique-ref';
import { DataService } from '../services/data.service';
import { FilterService, type HeatmapMode } from '../services/filter.service';
import { ControlsService } from '../services/controls.service';
import { ImplementationService, type ImplStatus } from '../services/implementation.service';
import { PostureService } from '../services/posture.service';
import { SettingsService } from '../services/settings.service';
import { TechniqueMarksService } from '../services/technique-marks.service';
import { type ValidationRunV2, ValidationService } from '../services/validation.service';
import { stubState } from './posture-stub';
import {
  LENS_RUN_AGES, daysBeforeLensToday, lensPostureTodayProvider, lensRunTechniques, parseFixtureDomain,
  resetBrowserState, seedLensRuns, signalStubProviders,
} from './lens-harness';

const LIBRARY_MANIFEST = [{ file: 'lens-fixture-a.json', name: 'Lens fixture A', description: '' }];
const IMPL_VALUES: readonly ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];

describe('Breadth guard on the status, controls and Covered lenses and impl= (P2-14, R1)', () => {
  let domain: Domain;
  let matrix: MatrixComponent;
  let filter: FilterService;
  let posture: PostureService;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [MatrixComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), ...signalStubProviders(), lensPostureTodayProvider()],
    });
    TestBed.overrideTemplate(MatrixComponent, '');
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    filter = TestBed.inject(FilterService);
    posture = TestBed.inject(PostureService);
    const fixture = TestBed.createComponent(MatrixComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    matrix = fixture.componentInstance;
    TestBed.inject(HttpTestingController).expectOne('assets/data/library-layers/index.json').flush(LIBRARY_MANIFEST);
  });

  afterEach(() => resetBrowserState());

  const keyOf = (t: Pick<Technique, 'attackId'>): TechniqueRefKey => techniqueRefKey(refForTechnique(t, 'enterprise', domain.attackVersion));
  const byId = (a: Technique, b: Technique) => a.attackId.localeCompare(b.attackId);

  function mitigation(attackId: string, expected: number): Mitigation {
    const m = domain.mitigations.find(x => x.attackId === attackId);
    const n = m ? domain.techniquesByMitigation.get(m.id)?.length : undefined;
    if (!m || n !== expected) {
      throw new Error(`Lens fixture precondition failed: techniquesByMitigation(${attackId}) is ${n}, expected ${expected} (§1.17).`);
    }
    return m;
  }
  const refsOf = (m: Mitigation): TechniqueRefKey[] => domain.techniquesByMitigation.get(m.id)!.map(keyOf).sort();

  /** The refs whose value under `read` differs from `before`. */
  function moved<T>(before: ReadonlyMap<TechniqueRefKey, T>, read: (t: Technique) => T): TechniqueRefKey[] {
    return domain.techniques.filter(t => JSON.stringify(read(t)) !== JSON.stringify(before.get(keyOf(t)))).map(keyOf).sort();
  }
  const capture = <T>(read: (t: Technique) => T) => new Map(domain.techniques.map(t => [keyOf(t), read(t)] as const));

  type LensRead = { score: number; stop: string | null; colour: string; label: string };
  /** Every technique's cell on a lens, read now (the registry projection the matrix binds). */
  function on(mode: HeatmapMode): (t: Technique) => LensRead {
    filter.setHeatmapMode(mode);
    const read = new Map<string, LensRead>(domain.techniques.map(t => {
      const vm = matrix.postureCell(t)!;
      return [t.id, { score: vm.score ?? 0, stop: vm.implStop ?? null, colour: matrix.getCellColor(t), label: vm.label }];
    }));
    return (t) => read.get(t.id)!;
  }
  /** The impl= values a technique matches. */
  function implMatches(t: Technique): ImplStatus[] {
    const out = IMPL_VALUES.filter(v => { filter.setImplStatusFilter(v); return !matrix.isImplFiltered(t); });
    filter.setImplStatusFilter(null);
    return [...out];
  }

  it('M1026 (16) implemented: the same 16 refs are partial in states(), on heat=covered, on heat=status and in impl=', () => {
    const m1026 = mitigation('M1026', 16);
    const refs = refsOf(m1026);
    const bucketBefore = capture(t => posture.stateFor(t).bucket);
    const coveredNow = on('covered');
    const coveredBefore = capture(t => coveredNow(t).score);
    const statusNow = on('status');
    const statusBefore = capture(t => statusNow(t).stop);
    const implBefore = capture(implMatches);

    TestBed.inject(ImplementationService).setStatus(m1026.id, 'implemented');

    // PostureService.states()
    expect(moved(bucketBefore, t => posture.stateFor(t).bucket)).toEqual(refs);
    for (const k of refs) expect(posture.states().get(k)!.bucket).withContext(k).toBe('partial');
    // heat=covered: score 1, drawn dashed
    const covered = on('covered');
    expect(moved(coveredBefore, t => covered(t).score)).toEqual(refs);
    for (const t of domain.techniques.filter(x => refs.includes(keyOf(x)))) {
      expect(covered(t).score).withContext(t.attackId).toBe(1);
      expect(matrix.postureCell(t)!.bucket).withContext(t.attackId).toBe('partial');
      expect(covered(t).colour).toBe(coveredColor({ score: 1 }, { theme: 'dark', colorblindSafe: false }));
    }
    // heat=status: the partial stop, between in progress and implemented
    const status = on('status');
    expect(moved(statusBefore, t => status(t).stop)).toEqual(refs);
    for (const t of domain.techniques.filter(x => refs.includes(keyOf(x)))) {
      expect(status(t).stop).withContext(t.attackId).toBe('partial');
      expect(status(t).label).toBe('Status: implemented, partial via M1026');
      expect(status(t).colour).toBe(statusStopFill('partial', 'dark'));
      expect(matrix.getTechniqueImplStatus(t)).toBe('implemented');
      expect(matrix.getImplPartialVia(t)).toBe('M1026');
    }
    // impl=: no value matches them, impl=implemented included
    expect(moved(implBefore, implMatches)).toEqual([]);
    for (const t of domain.techniques.filter(x => refs.includes(keyOf(x)))) expect(implMatches(t)).withContext(t.attackId).toEqual([]);
    expect(posture.implPartialOnly()).toEqual({ count: 16, via: ['M1026'] });
  });

  it('M1047 (13) implemented: the same 13 refs are full in states(), on heat=covered, on heat=status and in impl=implemented', () => {
    const m1047 = mitigation('M1047', 13);
    const refs = refsOf(m1047);
    const bucketBefore = capture(t => posture.stateFor(t).bucket);
    const coveredNow = on('covered');
    const coveredBefore = capture(t => coveredNow(t).score);
    const statusNow = on('status');
    const statusBefore = capture(t => statusNow(t).stop);
    const implBefore = capture(implMatches);

    TestBed.inject(ImplementationService).setStatus(m1047.id, 'implemented');

    expect(moved(bucketBefore, t => posture.stateFor(t).bucket)).toEqual(refs);
    for (const k of refs) expect(posture.states().get(k)!.bucket).withContext(k).toBe('covered');
    const covered = on('covered');
    expect(moved(coveredBefore, t => covered(t).score)).toEqual(refs);
    const status = on('status');
    expect(moved(statusBefore, t => status(t).stop)).toEqual(refs);
    expect(moved(implBefore, implMatches)).toEqual(refs);
    for (const t of domain.techniques.filter(x => refs.includes(keyOf(x)))) {
      expect(covered(t).score).withContext(t.attackId).toBe(2);
      expect(status(t).stop).withContext(t.attackId).toBe('implemented');
      expect(status(t).colour).toBe(statusStopFill('implemented', 'dark'));
      expect(implMatches(t)).withContext(t.attackId).toEqual(['implemented']);
    }
    expect(posture.implPartialOnly().count).toBe(0);
  });

  it('a confirmed technique reached only by M1026 turns full on Status, Covered and impl=implemented', () => {
    const m1026 = mitigation('M1026', 16);
    TestBed.inject(ImplementationService).setStatus(m1026.id, 'implemented');
    const t = [...domain.techniquesByMitigation.get(m1026.id)!].sort(byId)[0];
    expect(TestBed.inject(TechniqueMarksService).confirm(keyOf(t))).toBeTrue();
    expect(on('status')(t).stop).toBe('implemented');
    expect(on('covered')(t).score).toBe(2);
    expect(implMatches(t)).toEqual(['implemented']);
    expect(posture.implPartialOnly().count).toBe(15);
  });

  it('threshold 20 (Settings > Posture rules) turns M1026 full on Status and Covered', () => {
    const m1026 = mitigation('M1026', 16);
    TestBed.inject(ImplementationService).setStatus(m1026.id, 'implemented');
    const settings = TestBed.inject(SettingsService);
    settings.update({ posture: { ...settings.current.posture, mitigationBreadthThreshold: 20 } });
    const status = on('status');
    const covered = on('covered');
    for (const t of domain.techniquesByMitigation.get(m1026.id)!) {
      expect(status(t).stop).withContext(t.attackId).toBe('implemented');
      expect(covered(t).score).withContext(t.attackId).toBe(2);
    }
  });

  it('the posture card diff equals the Covered-lens diff', () => {
    const card = TestBed.createComponent(PostureCardComponent).componentInstance;
    const parents = domain.techniques.filter(t => !t.isSubtechnique);
    const coveredScores = () => { const read = on('covered'); return parents.map(t => read(t).score); };
    const count = (scores: number[], s: number) => scores.filter(x => x === s).length;
    const before = { tally: card.tally(), scores: coveredScores() };
    const impl = TestBed.inject(ImplementationService);
    impl.setStatus(mitigation('M1026', 16).id, 'implemented');
    impl.setStatus(mitigation('M1047', 13).id, 'implemented');
    const after = { tally: card.tally(), scores: coveredScores() };
    const dPartial = after.tally.partial - before.tally.partial;
    const dCovered = after.tally.covered - before.tally.covered;
    expect(dPartial + dCovered).toBeGreaterThan(0);
    expect(dPartial).toBe(count(after.scores, 1) - count(before.scores, 1));
    expect(dCovered).toBe(count(after.scores, 2) - count(before.scores, 2));
  });

  it('controls: an implemented control behind M1026 is the partial stop, behind M1047 covered; a planned one planned', () => {
    const m1026 = mitigation('M1026', 16);
    const m1047 = mitigation('M1047', 13);
    const controls = TestBed.inject(ControlsService);
    const ctl = (ref: string, mitId: string) =>
      ({ name: ref, framework: 'Custom' as const, controlRef: ref, description: '', mitigationIds: [mitId], status: 'implemented' as const });
    controls.addControl(ctl('ctl-a', m1026.id));
    controls.addControl(ctl('ctl-b', m1047.id));
    const read = on('controls');
    const only1026 = domain.techniquesByMitigation.get(m1026.id)!.filter(t => !domain.techniquesByMitigation.get(m1047.id)!.includes(t));
    expect(only1026.length).toBeGreaterThan(0);
    for (const t of only1026) {
      expect(read(t).stop).withContext(t.attackId).toBe('partial');
      expect(matrix.getControlStatus(t)).toBe('partial');
      expect(read(t).label).toBe('Controls: Covered (self-attested, partial via M1026)');
    }
    for (const t of domain.techniquesByMitigation.get(m1047.id)!) expect(read(t).stop).withContext(t.attackId).toBe('covered');
    expect(controlStop([{ basis: 'control-implemented', strength: 'planned' }])).toBe('planned');
    expect(controlStop([{ basis: 'mitigation-implemented', strength: 'full' }])).toBe('none');
  });
});

describe('Proven lens (P2-14): scores under the pinned POSTURE_TODAY and the lab badge', () => {
  let domain: Domain;
  let matrix: MatrixComponent;
  let filter: FilterService;

  /** The third parent by ATT&CK id: the one range-scoped v2 run lands here. */
  const rangeTechnique = (d: Domain): Technique =>
    d.techniques.filter(t => !t.isSubtechnique).sort((a, b) => a.attackId.localeCompare(b.attackId))[2];

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [MatrixComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), ...signalStubProviders(), lensPostureTodayProvider()],
    });
    TestBed.overrideTemplate(MatrixComponent, '');
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    filter = TestBed.inject(FilterService);
    const validation = TestBed.inject(ValidationService);
    seedLensRuns(validation, domain);
    const t = rangeTechnique(domain);
    const row = {
      id: 'lens-run-range', techniqueId: t.attackId, techniqueName: t.name, runDate: daysBeforeLensToday(5), operator: '',
      telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '', attackResult: 'executed',
      detectionsExpected: ['wazuh:990003'], detectionsFired: [], responsePlaybook: '', responseActions: [], evidenceLinks: [],
      notes: '', status: 'passed', domain: 'enterprise', attackVersion: domain.attackVersion, source: 'lylat-range:m1',
      createdAt: daysBeforeLensToday(5), updatedAt: daysBeforeLensToday(5), techniqueRef: keyFor(t, domain), proofScope: 'range',
      outcomes: [{ detectionRef: 'wazuh:990003', outcome: 'alerted' }], statusFromSource: true, missionId: 'm1',
    } as unknown as ValidationRunV2;
    expect(validation.importRows([row], 'lylat-range:m1').ok).toBeTrue();
    const fixture = TestBed.createComponent(MatrixComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    matrix = fixture.componentInstance;
    TestBed.inject(HttpTestingController).expectOne('assets/data/library-layers/index.json').flush(LIBRARY_MANIFEST);
  });

  afterEach(() => resetBrowserState());

  function keyFor(t: Technique, d: Domain): TechniqueRefKey {
    return techniqueRefKey(refForTechnique(t, 'enterprise', d.attackVersion));
  }

  it('the fresh own run scores 2, the stale one 1, the range run 2 with the lab badge; everything else 0', () => {
    filter.setHeatmapMode('proven');
    const { fresh, stale } = lensRunTechniques(domain);
    const range = rangeTechnique(domain);
    expect(LENS_RUN_AGES).toEqual({ fresh: 10, stale: 120 });
    const cell = (t: Technique) => postureLensCell(matrix.postureCell(t));
    expect(cell(fresh).score).toBe(2);
    expect(cell(stale).score).toBe(1);
    expect(cell(range).score).toBe(2);
    expect(cell(range).proofScope).toBe('range');
    expect(provenLabBadge(cell(range))).toBeTrue();
    expect(provenLabBadge(cell(fresh))).toBeFalse();
    expect(provenLabBadge(cell(stale))).toBeFalse();
    expect(matrix.postureCell(range)!.label).toBe(`${PROVEN} in range`);
    expect(matrix.postureCell(stale)!.label).toBe(`${PROVEN} (your run) (stale)`);
    for (const t of domain.techniques) {
      if ([fresh, stale, range].includes(t)) continue;
      expect(cell(t).score).withContext(t.attackId).toBe(0);
    }
    expect(matrix.getCellColor(range)).toBe(provenColor({ score: 2 }, { theme: 'dark', colorblindSafe: false }));
    expect(matrix.getCellColor(stale)).toBe(postureFill('stale', 'dark'));
  });

  it('the cell renders the check mark, and the lab badge only where the best proof is from the range', () => {
    filter.setHeatmapMode('proven');
    const render = (t: Technique): HTMLElement => {
      const f = TestBed.createComponent(TechniqueCellComponent);
      f.componentRef.setInput('technique', t);
      f.componentRef.setInput('heatmapMode', 'proven');
      f.componentRef.setInput('posture', matrix.postureCell(t));
      f.detectChanges();
      return f.nativeElement as HTMLElement;
    };
    const range = render(rangeTechnique(domain));
    expect(range.querySelector('.posture-check')).not.toBeNull();
    expect(range.querySelector('.proof-lab-badge')?.textContent?.trim()).toBe('lab');
    const fresh = render(lensRunTechniques(domain).fresh);
    expect(fresh.querySelector('.posture-check')).not.toBeNull();
    expect(fresh.querySelector('.proof-lab-badge')).toBeNull();
  });

  it('scores production 3 and nothing without a qualifying proof (projection)', () => {
    const t = { id: 'attack-pattern--x', attackId: 'T1001' } as Technique;
    const prod = { ...stubState('T1001', 'proven'), proofScope: 'production' as const };
    expect(provenProject({ posture: () => prod }, t).score).toBe(3);
    expect(provenProject({ posture: () => stubState('T1001', 'covered') }, t).score).toBe(0);
    expect(provenProject({ posture: () => stubState('T1001', 'stale') }, t).score).toBe(1);
  });
});

describe('Covered lens projection (P2-14): full and partial values', () => {
  const t = { id: 'attack-pattern--x', attackId: 'T1001' } as Technique;
  const mark = (strength: 'full' | 'partial' | 'planned') =>
    ({ qualifier: 'self-attested' as const, basis: 'mitigation-implemented' as const, strength, via: 'M1038', source: 'manual' as const });
  const with_ = (marks: ReturnType<typeof mark>[], subStates: string[] = []) =>
    ({ posture: () => ({ ...stubState('T1001', 'known'), covered: marks, subStates }) as never });

  it('2 full, 1 partial, 0 planned or none; a contradicted full mark falls back to partial', () => {
    expect(coveredProject(with_([mark('full')]), t).score).toBe(2);
    expect(coveredProject(with_([mark('partial')]), t)).toEqual(jasmine.objectContaining({ score: 1, bucket: 'partial' }));
    expect(coveredProject(with_([mark('partial')]), t).label).toBe('Covered (self-attested or range), partial via M1038');
    expect(coveredProject(with_([mark('planned')]), t).score).toBe(0);
    expect(coveredProject(with_([]), t).score).toBe(0);
    expect(coveredProject(with_([mark('full'), mark('partial')], ['contradicted']), t).score).toBe(1);
  });
});

describe('P2-14 ramps: ordinal and CVD-safe in both themes', () => {
  const LEGENDS: Record<string, (theme: PostureTheme) => readonly LensLegendStop[]> = {
    status: statusLegendStops, controls: controlsLegendStops, covered: coveredLegendStops, proven: provenLegendStops,
  };

  for (const [lens, legend] of Object.entries(LEGENDS)) {
    for (const theme of ['dark', 'light'] as const) {
      it(`${lens} (${theme}): luminance distance from the surface rises, neighbours >= 1.2:1 under every CVD`, () => {
        const fills = legend(theme).map(s => s.fill);
        expect(fills[0]).toBe(POSTURE_SURFACE[theme]);
        for (const kind of [null, ...CVD_KINDS]) {
          const seen = kind ? fills.map(f => simulateCvd(f, kind)) : fills;
          const surface = kind ? simulateCvd(POSTURE_SURFACE[theme], kind) : POSTURE_SURFACE[theme];
          const dist = seen.map(f => hexContrast(f, surface));
          for (let i = 1; i < seen.length; i++) {
            expect(dist[i]).withContext(`${lens} ${theme} ${kind ?? 'normal'} stop ${i}`).toBeGreaterThan(dist[i - 1]);
            expect(hexContrast(seen[i], seen[i - 1])).withContext(`${lens} ${theme} ${kind ?? 'normal'} ${i}`).toBeGreaterThanOrEqual(1.2);
          }
        }
        expect(relativeLuminance(fills[0])).toBeDefined();
      });
    }
  }

  it('the registry ramps are the dark legends, the four lenses are registry-hosted, and the legend owner-words flags are set', () => {
    for (const [lens, legend] of Object.entries(LEGENDS)) {
      const def = heatmapModeDef(lens as HeatmapMode)!;
      expect(def.ramp.stops.map(s => s.color)).withContext(lens).toEqual(legend('dark').map(s => s.fill));
      expect(def.project).withContext(lens).toBeDefined();
      expect(def.color).withContext(lens).toBeDefined();
    }
    expect(HEATMAP_MODES.slice(-2).map(m => m.value)).toEqual(['proven', 'covered']);
    for (const stop of [...provenLegendStops('dark').slice(1), ...coveredLegendStops('dark').slice(1)]) {
      expect(stop.ownerWords).withContext(stop.label).toBeTrue();
    }
    expect(statusLegendStops('dark').every(s => !s.ownerWords)).toBeTrue();
    expect(statusLegendStops('dark').map(s => s.key)).toEqual(['none', 'not-started', 'planned', 'in-progress', 'partial', 'implemented']);
  });
});
