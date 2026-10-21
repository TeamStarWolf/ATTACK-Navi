// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Before/after spec for the risk sort, Dim uncovered and the dashboard's
// threat-gap counters (Phase 2 design §3 P2-09, E2.1-d3; R9, S8). P2-01 pinned
// the LEGACY answers (the "before"); P2-09 makes the three read posture, so this
// spec pins the "after" next to them and shows exactly which numbers moved.
// P2-14 re-derives the status lens and impl= from PostureService: the before
// status pins stay as P2-01 pinned them (recomputed below from the legacy fold,
// which no app code holds any more), and section statusAfter.<profile> pins
// the after values on purpose (the breadth guard and the Covered ordinal ramp).
//
// Profiles, on the lens fixture (lens-harness.ts) with the real PostureService
// and its stores, POSTURE_TODAY pinned to 2026-10-01:
//   - fresh: no owner data of the user's (the fixture controls of
//     controlsProvider reach only mitigated techniques, so they move no number;
//     asserted below);
//   - seeded: P2-07's seed, exactly (posture-seed.ts; the picks of
//     posture-count-equality.spec.ts): M1047 and M1026 implemented, one
//     confirmed technique, one passed own run with a fired detection, one
//     failed run after a mark, one not-reproducible run. Every pick that
//     records Covered or above is a mitigated parent, so no P2-09 number moves:
//     its after values equal the fresh after values;
//   - gapSeeded: a third profile, P2-07's composition with the confirmation
//     and the passed run moved to the two highest-risk unrecorded gaps (used by
//     a group, no defensive reference). It shows the movement the design text
//     asks of the seeded profile ("the covered and proven techniques leave the
//     counters and drop in the risk order"), which P2-07's own seed cannot.
//
// Before: __snapshots__/legacy-baseline.json section riskDim.<profile>, as
// P2-01 pinned it (fresh; seeded = M1047 and M1026 implemented). The legacy
// answers read no owner data at all, so P2-01's seeded pin is also the before of
// both fuller seeds (seeded and gapSeeded); the first spec recomputes the legacy
// answers on each profile and checks them against those pins, unchanged:
//   - riskTop20: Sort by risk, the first 20 parent techniques as [attackId,
//     score], read with the pre-posture bucket ('none', riskScore's default);
//   - dimmed: hasAnySignal false (threat-intel and CVE links kept a cell bright);
//   - dashboard: criticalRiskCount and kevExposedGapCount over
//     hasDefensiveReference alone;
//   - statusStops and implImplemented: the legacy status fold (best status over
//     the mapped mitigations, no breadth guard, the old hexes), recomputed here.
//
// Status after (P2-14): section statusAfter.<profile>: each technique's status
// stop and minimap colour on heat=status (PostureService.implViewFor, Covered
// ordinal ramp) and the techniques impl=implemented keeps. A technique whose
// only implemented mitigations are broader than the threshold (M1026, 16, in the
// seeded profiles) shows 'implemented, partial via M1026' and leaves
// impl=implemented; every other technique keeps its stop.
//
// After: section riskDimAfter.<profile>:
//   - riskTop20: the matrix comparator over riskScore(tech, domain, kev,
//     bucket); an unrecorded gap's exposure is doubled only while its bucket
//     is not covered, proven or stale (isUnrecordedGap);
//   - dimmed: matrix isDimmed with Dim uncovered on, which dims posture bucket
//     'none'; newlyDimmed is dimmed minus the before set;
//   - dashboard: criticalRiskCount and kevExposedGapCount read from
//     DashboardPanelComponent's stats (the KEV-gap count is exposed there,
//     unrendered), cross-checked by an independent recomputation.
// Fresh: risk order and both counters equal the before pins; dim equals the
// before set plus the techniques kept bright only by threat-intel or CVE links.
// Seeded (P2-07's seed): equal to fresh after; nothing moves.
// GapSeeded: the covered and the proven technique leave the counters and drop
// in the risk order; nothing else moves.
//
// The KEV-gap count is 0 on the fixture by construction (every KEV-mapped
// technique has a defensive signal; the DARK_TECHNIQUES have no CVE signal), so
// sensitivity specs below show the pins can move.
//
// To update after an INTENDED change: run this spec, copy each logged
// "[legacy-baseline] <section> <json>" line's json into that section of the
// JSON file, and review the diff. Never hand-edit a value to make it pass. The
// before sections (riskDim) are history: P2-09 leaves them byte-identical.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import BASELINE from './__snapshots__/legacy-baseline.json';
import { MatrixComponent } from '../components/matrix/matrix.component';
import { DashboardPanelComponent } from '../components/dashboard-panel/dashboard-panel.component';
import { Domain } from '../models/domain';
import { type StatusStop, statusLegendStops, statusStop, statusStopLabel } from '../models/posture/lens-ramps';
import { ImplementationService, type ImplStatus } from '../services/implementation.service';
import { Technique } from '../models/technique';
import type { PostureBucket } from '../models/posture/posture.types';
import { refForTechnique, techniqueRefKey } from '../models/technique-ref';
import { AtomicService } from '../services/atomic.service';
import { AttackCveService } from '../services/attack-cve.service';
import { CARService } from '../services/car.service';
import { CisControlsService } from '../services/cis-controls.service';
import { CriProfileService } from '../services/cri-profile.service';
import { CsaCcmService } from '../services/csa-ccm.service';
import { D3fendService } from '../services/d3fend.service';
import { M365ControlsService } from '../services/m365-controls.service';
import { NistMappingService } from '../services/nist-mapping.service';
import { SigmaService } from '../services/sigma.service';
import { DataService } from '../services/data.service';
import { EnrichmentService } from '../services/enrichment.service';
import { FilterService } from '../services/filter.service';
import { PostureService } from '../services/posture.service';
import { SourceRegistryService } from '../services/source-registry.service';
import { TechniqueMarksService } from '../services/technique-marks.service';
import { ValidationService } from '../services/validation.service';
import { hasAnySignal, hasDefensiveReference } from '../models/known-signals';
import { DARK_TECHNIQUES, controlsProvider, parseFixtureDomain, resetBrowserState, signalStubProviders } from './lens-harness';
import { type PostureSeedPicks, daysBeforeSeedToday, postureSeedToday, seedPostureProfile } from './posture-seed';

/** The real LibraryLayerService asks for its manifest when the matrix is built. */
const LIBRARY_MANIFEST = [{ file: 'lens-fixture-a.json', name: 'Lens fixture A', description: '' }];

function pin(path: string, actual: unknown): void {
  const expected = path.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], BASELINE);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) console.log(`[legacy-baseline] ${path} ${JSON.stringify(actual)}`);
  expect(actual).withContext(`legacy baseline "${path}" changed; see the spec header`).toEqual(expected);
}

/** The status lens's categorical stops, by the fold's answer (heatmap-modes.ts, 'status'). */
const STATUS_STOP: Record<ImplStatus | 'none', string> = {
  none: 'none', 'not-started': 'not started', 'in-progress': 'in progress', planned: 'planned', implemented: 'implemented',
};

/** The status lens's colours before P2-14 (heatmap-modes.ts at P2-13), by stop label: history for the before pins. */
const LEGACY_STATUS_HEX: Record<string, string> = {
  none: '#90a4ae', 'not started': '#e53935', 'in progress': '#ff9800', planned: '#2196f3', implemented: '#4caf50',
};
const LEGACY_RANK: Record<ImplStatus, number> = { implemented: 4, 'in-progress': 3, planned: 2, 'not-started': 1 };

interface StatusAfter {
  statusStops: Record<string, [string, string]>;
  implImplemented: string[];
}
const statusAfterPin = (profile: string): StatusAfter | undefined =>
  (BASELINE as unknown as { statusAfter?: Record<string, StatusAfter> }).statusAfter?.[profile];

/** Buckets that record something of the owner's at Covered or above (independent of isUnrecordedGap). */
const RECORDED: ReadonlySet<PostureBucket> = new Set<PostureBucket>(['covered', 'proven', 'stale']);

interface DashboardValues { criticalRiskCount: number; kevExposedGapCount: number }

/** Replace one method of an injected stub for one ATT&CK id; every other id keeps the stub's answer. */
function overrideFor(svc: object, method: string, attackId: string, value: unknown): void {
  const target = svc as Record<string, (id: string) => unknown>;
  const original = target[method].bind(svc);
  target[method] = (id: string) => (id === attackId ? value : original(id));
}

interface BeforeValues {
  riskTop20: [string, number][];
  dimmed: string[];
  dashboard: DashboardValues;
  statusStops: Record<string, [string, string]>;
  implImplemented: string[];
}

interface AfterValues {
  riskTop20: [string, number][];
  dimmed: string[];
  newlyDimmed: string[];
  dashboard: DashboardValues;
}

/** P2-01 pinned fresh and seeded; the legacy answers read no owner data, so gapSeeded's before is seeded's. */
const before = (profile: string): BeforeValues =>
  (BASELINE as unknown as { riskDim: Record<string, BeforeValues> }).riskDim[profile === 'gapSeeded' ? 'seeded' : profile];
const afterPin = (profile: string): AfterValues | undefined =>
  (BASELINE as unknown as { riskDimAfter?: Record<string, AfterValues> }).riskDimAfter?.[profile];

for (const profile of ['fresh', 'seeded', 'gapSeeded'] as const) {
  describe(`Risk sort, dim and threat-gap counters before and after posture, ${profile} profile (P2-09, E2.1-d3)`, () => {
    let domain: Domain;
    let matrix: MatrixComponent;
    let filter: FilterService;
    let posture: PostureService;
    let picks: PostureSeedPicks | null = null;

    beforeEach(() => {
      resetBrowserState();
      domain = parseFixtureDomain();
      TestBed.configureTestingModule({
        imports: [MatrixComponent, DashboardPanelComponent],
        providers: [
          provideHttpClient(withXhr()), provideHttpClientTesting(), ...signalStubProviders(), controlsProvider(domain),
          postureSeedToday(),
        ],
      });
      // Score maps and the sort are computed in the class, not the template.
      TestBed.overrideTemplate(MatrixComponent, '');
      (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
      filter = TestBed.inject(FilterService);
      posture = TestBed.inject(PostureService);
      picks = profile === 'fresh' ? null : seedPostureProfile(domain, profile);
      const fixture = TestBed.createComponent(MatrixComponent);
      fixture.componentRef.setInput('domain', domain);
      fixture.detectChanges();
      matrix = fixture.componentInstance;
      TestBed.inject(HttpTestingController).expectOne('assets/data/library-layers/index.json').flush(LIBRARY_MANIFEST);
    });

    afterEach(() => resetBrowserState());

    const byId = (a: Technique, b: Technique) => a.attackId.localeCompare(b.attackId);
    const sorted = (ids: Iterable<string>) => [...ids].sort((a, b) => a.localeCompare(b));
    const keyOf = (t: Technique) => techniqueRefKey(refForTechnique(t, 'enterprise', domain.attackVersion));
    const parentsById = () => domain.techniques.filter(t => !t.isSubtechnique).sort(byId);

    /**
     * The dashboard's threat-gap counters, read from
     * DashboardPanelComponent's stats (kevExposedGapCount is exposed there,
     * unrendered, for this pin; dashboard-panel.component.ts buildStats).
     */
    function dashboard(): DashboardValues {
      const dash = TestBed.createComponent(DashboardPanelComponent);
      dash.detectChanges();
      const stats = dash.componentInstance.stats!;
      dash.destroy();
      return { criticalRiskCount: stats.criticalRiskCount, kevExposedGapCount: stats.kevExposedGapCount };
    }

    const kev = (t: Technique) => matrix.kevScores.get(t.attackId) ?? 0;
    /** After: the posture-aware score the matrix sorts by. */
    const risk = (t: Technique) => TestBed.inject(EnrichmentService).riskScore(t, domain, kev(t), posture.stateFor(t).bucket);
    /** Before: the pre-posture score (bucket 'none', riskScore's default). */
    const legacyRisk = (t: Technique) => TestBed.inject(EnrichmentService).riskScore(t, domain, kev(t));
    const rankBy = (score: (t: Technique) => number) => [...parentsById()].sort((a, b) => score(b) - score(a) || byId(a, b));
    const top20 = (ranked: Technique[], score: (t: Technique) => number) =>
      ranked.slice(0, 20).map(t => [t.attackId, score(t)] as [string, number]);

    /** The legacy answers, recomputed from the signals alone (they read no owner data). */
    function legacy(): Omit<BeforeValues, 'statusStops' | 'implImplemented'> {
      const enrichment = TestBed.inject(EnrichmentService);
      const cves = TestBed.inject(AttackCveService);
      const parents = parentsById();
      const undefended = (t: Technique) => !hasDefensiveReference(enrichment.signals(t, domain));
      return {
        riskTop20: top20(rankBy(legacyRisk), legacyRisk),
        dimmed: [...domain.techniques].sort(byId).filter(t => !hasAnySignal(enrichment.signals(t, domain))).map(t => t.attackId),
        dashboard: {
          criticalRiskCount: parents.filter(t => (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0 && undefended(t)).length,
          kevExposedGapCount: parents.filter(t => cves.getKevCvesForTechnique(t.attackId).length > 0 && undefended(t)).length,
        },
      };
    }

    /**
     * The legacy status fold, recomputed (P2-14 removed it from the matrix):
     * the best status over the mapped mitigations, no breadth guard, painted
     * with the pre-P2-14 hexes. History for the before pins.
     */
    function legacyStatusFold(): Pick<BeforeValues, 'statusStops' | 'implImplemented'> {
      const all = [...domain.techniques].sort(byId);
      const statusMap = TestBed.inject(ImplementationService).getStatusMap();
      const statusStops: Record<string, [string, string]> = {};
      const implImplemented: string[] = [];
      for (const t of all) {
        let best: ImplStatus | null = null;
        for (const rel of domain.mitigationsByTechnique.get(t.id) ?? []) {
          const s = statusMap.get(rel.mitigation.id);
          if (s && (best === null || LEGACY_RANK[s] > LEGACY_RANK[best])) best = s;
        }
        const stop = STATUS_STOP[best ?? 'none'];
        statusStops[t.attackId] = [stop, LEGACY_STATUS_HEX[stop]];
        if (best === 'implemented') implImplemented.push(t.attackId);
      }
      return { statusStops, implImplemented };
    }

    /** The status lens and impl= after P2-14, read from the matrix (PostureService.implViewFor). */
    function statusAfter(): StatusAfter {
      const all = [...domain.techniques].sort(byId);
      filter.setHeatmapMode('status');
      const fills = new Map(statusLegendStops('dark').map(s => [s.key, s.fill]));
      const statusStops: Record<string, [string, string]> = {};
      for (const t of all) {
        const stop = matrix.postureCell(t)!.implStop as StatusStop;
        expect(stop).withContext(t.attackId).toBe(statusStop(posture.implViewFor(t)));
        const colour = matrix.getCellColor(t);
        expect(colour).withContext(`status colour of ${t.attackId} is its ramp stop`).toBe(fills.get(stop)!);
        statusStops[t.attackId] = [statusStopLabel(stop, matrix.getImplPartialVia(t)), colour];
      }
      // impl=implemented: the techniques the filter keeps; every other one is dimmed.
      filter.setImplStatusFilter('implemented');
      const implImplemented = all.filter(t => !matrix.isImplFiltered(t)).map(t => t.attackId);
      for (const t of all) expect(matrix.isDimmed(t)).withContext(`impl= dims ${t.attackId}`).toBe(!implImplemented.includes(t.attackId));
      filter.setImplStatusFilter(null);
      return { statusStops, implImplemented };
    }

    /** The posture-aware answers, read from the matrix and the dashboard. */
    function after(): AfterValues & { ranked: Technique[] } {
      const enrichment = TestBed.inject(EnrichmentService);
      const all = [...domain.techniques].sort(byId);
      const parents = all.filter(t => !t.isSubtechnique);

      // Sort by risk: the matrix comparator, over every parent technique.
      filter.setSortMode('coverage');
      const ranked = rankBy(risk);
      // The matrix's own columns are ordered by that same comparator.
      const rank = new Map(ranked.map((t, i) => [t.id, i]));
      expect(matrix.sortedColumns.length).toBeGreaterThan(5);
      for (const col of matrix.sortedColumns) {
        const order = col.techniques.map(t => rank.get(t.id)!);
        expect(order).withContext(col.tactic.name).toEqual([...order].sort((a, b) => a - b));
      }
      filter.setSortMode('alpha');

      // Dim uncovered.
      filter.toggleDimUncovered();
      expect(matrix.dimUncovered).toBeTrue();
      const dimmed = all.filter(t => matrix.isDimmed(t)).map(t => t.attackId);
      filter.toggleDimUncovered();
      expect(dimmed).withContext('dim = bucket none').toEqual(all.filter(t => posture.stateFor(t).bucket === 'none').map(t => t.attackId));

      // Dashboard threat-gap counters, read from the component; an independent
      // recomputation cross-checks both.
      const dash = dashboard();
      const cves = TestBed.inject(AttackCveService);
      const gap = (t: Technique) =>
        !hasDefensiveReference(enrichment.signals(t, domain)) && !RECORDED.has(posture.stateFor(t).bucket);
      const critical = parents.filter(t => (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0 && gap(t)).length;
      const kevGaps = parents.filter(t => cves.getKevCvesForTechnique(t.attackId).length > 0 && gap(t)).length;
      expect(dash.criticalRiskCount).withContext('criticalRiskCount predicate').toBe(critical);
      expect(dash.kevExposedGapCount).withContext('kevExposedGapCount predicate').toBe(kevGaps);

      const was = new Set(before(profile).dimmed);
      return {
        riskTop20: top20(ranked, risk),
        dimmed,
        newlyDimmed: dimmed.filter(id => !was.has(id)),
        dashboard: dash,
        ranked,
      };
    }

    const pinnable = (v: AfterValues): AfterValues =>
      ({ riskTop20: v.riskTop20, dimmed: v.dimmed, newlyDimmed: v.newlyDimmed, dashboard: v.dashboard });

    it('before: the legacy answers still equal the P2-01 pins (they read no owner data)', () => {
      const pinned = before(profile);
      expect(pinned).withContext('both before profiles are pinned').toBeDefined();
      const l = legacy();
      expect(l.riskTop20).toEqual(pinned.riskTop20);
      expect(l.dimmed).toEqual(pinned.dimmed);
      expect(l.dashboard).toEqual(pinned.dashboard);
      // The legacy status fold, recomputed: exactly as P2-01 pinned it.
      const fold = legacyStatusFold();
      expect(fold.statusStops).toEqual(pinned.statusStops);
      expect(fold.implImplemented).toEqual(pinned.implImplemented);
      if (profile !== 'fresh') {
        expect(new Set(Object.values(fold.statusStops).map(s => s[0]))).toEqual(new Set(['none', 'implemented']));
      } else {
        expect(new Set(Object.values(fold.statusStops).map(s => s[0]))).toEqual(new Set(['none']));
      }
    });

    it('status after (P2-14): pins the guarded status stops, the Covered ramp colours and impl=implemented', () => {
      const legacy = legacyStatusFold();
      const v = statusAfter();
      pin(`statusAfter.${profile}`, v);
      expect(statusAfterPin(profile)).withContext('statusAfter is pinned').toBeDefined();
      const partial = Object.entries(v.statusStops).filter(([, [stop]]) => stop.startsWith('implemented, partial via ')).map(([id]) => id);
      // A technique-level statement (a confirmation) counts on the guarded view; the legacy fold read mitigations only.
      const confirmed = domain.techniques
        .filter(t => posture.stateFor(t).covered.some(m => m.basis === 'technique-confirmed' && m.strength === 'full'))
        .map(t => t.attackId);
      // Only the partial techniques (which leave impl=implemented) and the confirmed ones (implemented) change stop.
      for (const [id, [stop]] of Object.entries(v.statusStops)) {
        if (partial.includes(id)) expect(legacy.statusStops[id][0]).withContext(id).toBe('implemented');
        else if (confirmed.includes(id)) expect(stop).withContext(id).toBe('implemented');
        else expect(stop).withContext(id).toBe(legacy.statusStops[id][0]);
      }
      expect(v.implImplemented).toEqual(sorted(new Set([...legacy.implImplemented.filter(id => !partial.includes(id)), ...confirmed])));
      if (profile === 'fresh') {
        expect(partial).toEqual([]);
      } else {
        expect(partial.length).toBeGreaterThan(0);
        for (const id of partial) expect(v.statusStops[id][0]).toBe('implemented, partial via M1026');
      }
    });

    it('after: pins the posture-aware values', () => {
      const v = after();
      expect(v.riskTop20.length).toBe(20);
      expect(v.dashboard.criticalRiskCount).toBeGreaterThan(0);
      pin(`riskDimAfter.${profile}`, pinnable(v));
    });

    if (profile === 'fresh') {
      it('fresh: risk order and both counters equal the before pins; dim adds exactly the threat-only techniques', () => {
        const enrichment = TestBed.inject(EnrichmentService);
        // The fixture controls give owner marks only where a mitigation is mapped,
        // so no owner mark reaches a technique without a defensive reference.
        for (const t of domain.techniques) {
          if (posture.stateFor(t).bucket === 'none' || posture.stateFor(t).bucket === 'known') continue;
          expect(hasDefensiveReference(enrichment.signals(t, domain))).withContext(`${t.attackId} has a mark and a reference`).toBeTrue();
        }
        const v = after();
        const pinned = before('fresh');
        expect(v.riskTop20).withContext('risk order byte-identical').toEqual(pinned.riskTop20);
        expect(v.ranked.map(t => t.attackId)).withContext('every parent, not only the top 20')
          .toEqual(rankBy(legacyRisk).map(t => t.attackId));
        expect(v.dashboard).withContext('both counters unchanged').toEqual(pinned.dashboard);

        // Kept bright before only by threat-intel or CVE links: some signal, but
        // none of the five Known reference inputs (Atomic tests count there).
        const threatOnly = [...domain.techniques].sort(byId)
          .filter(t => hasAnySignal(enrichment.signals(t, domain)) && enrichment.referenceSignalCount(t, domain) === 0)
          .map(t => t.attackId);
        expect(threatOnly.length).withContext('the change is visible on the fixture').toBeGreaterThan(0);
        expect(v.dimmed).toEqual(sorted(new Set([...pinned.dimmed, ...threatOnly])));
        expect(v.newlyDimmed).toEqual(threatOnly);
        // On this fixture they are exactly the techniques with no ATT&CK mitigation.
        expect(threatOnly).toEqual(sorted(DARK_TECHNIQUES));
      });
    } else if (profile === 'seeded') {
      it("seeded (P2-07's seed, exactly): owner data on mitigated parents moves no P2-09 number; after equals fresh after", () => {
        const s = picks!;
        // P2-07's picks (posture-count-equality.spec.ts picks()): proof only1047[0],
        // failed only1047[1], confirmed only1026[0], notReproducible untouched[0].
        expect([s.confirmed, s.proof, s.failed, s.notReproducible].map(t => t.attackId))
          .withContext("P2-07's picks: confirmed, proof, failed, not reproducible").toEqual(['T1003', 'T1021', 'T1578', 'T1001']);
        expect(posture.stateFor(s.confirmed).bucket).toBe('covered');
        expect(posture.stateFor(s.proof).bucket).toBe('proven');
        expect(posture.stateFor(s.failed).subStates).toContain('contradicted');
        expect(posture.stateFor(s.notReproducible).excluded).toBeTrue();
        const enrichment = TestBed.inject(EnrichmentService);
        for (const t of [s.confirmed, s.proof]) {
          expect(hasDefensiveReference(enrichment.signals(t, domain))).withContext(`${t.attackId} is a mapped parent`).toBeTrue();
        }
        const freshAfter = afterPin('fresh');
        expect(freshAfter).withContext('the fresh after values are pinned').toBeDefined();
        expect(pinnable(after())).toEqual(freshAfter!);
        expect(afterPin('seeded')).withContext('the seeded pin equals the fresh pin').toEqual(freshAfter!);
      });
    } else {
      it('gapSeeded: the covered and the proven technique leave the counters and drop in the risk order; nothing else moves', () => {
        const s = picks!;
        const v = after();
        const pinned = before(profile);
        const freshAfter = afterPin('fresh');
        expect(freshAfter).withContext('the fresh after values are pinned').toBeDefined();
        // Confirmed and proof: the two highest-risk unrecorded gaps; failed and
        // not reproducible: P2-07's picks.
        expect([s.confirmed, s.proof, s.failed, s.notReproducible].map(t => t.attackId))
          .withContext('the gapSeeded picks: confirmed, proof, failed, not reproducible').toEqual(['T1007', 'T1082', 'T1578', 'T1001']);
        expect(posture.stateFor(s.confirmed).bucket).toBe('covered');
        expect(posture.stateFor(s.proof).bucket).toBe('proven');
        expect(posture.stateFor(s.failed).subStates).toContain('contradicted');
        expect(posture.stateFor(s.notReproducible).excluded).toBeTrue();

        // Counters: both picks were critical-risk before (used by a group, no
        // defensive reference) and leave; neither is KEV-mapped on the fixture.
        expect(v.dashboard.criticalRiskCount).toBe(pinned.dashboard.criticalRiskCount - 2);
        expect(v.dashboard.kevExposedGapCount).toBe(pinned.dashboard.kevExposedGapCount);

        // Risk: each pick's score halves and it drops; the other parents keep their order.
        const legacyOrder = rankBy(legacyRisk).map(t => t.attackId);
        const afterOrder = v.ranked.map(t => t.attackId);
        for (const t of [s.confirmed, s.proof]) {
          expect(risk(t) * 2).withContext(t.attackId).toBe(legacyRisk(t));
          expect(afterOrder.indexOf(t.attackId)).withContext(`${t.attackId} drops`).toBeGreaterThan(legacyOrder.indexOf(t.attackId));
        }
        const moved = new Set([s.confirmed.attackId, s.proof.attackId]);
        expect(afterOrder.filter(id => !moved.has(id))).toEqual(legacyOrder.filter(id => !moved.has(id)));
        for (const t of parentsById()) if (!moved.has(t.attackId)) expect(risk(t)).withContext(t.attackId).toBe(legacyRisk(t));
        expect(legacyOrder.slice(0, 20)).toEqual(pinned.riskTop20.map(([id]) => id));

        // Dim: the fresh after set, minus the two picks the owner recorded.
        expect(v.dimmed).toEqual(freshAfter!.dimmed.filter(id => !moved.has(id)));
      });
    }

    // ── Sensitivity: each pin can see a change ─────────────────────────────
    /** A dark parent used by a group that the seed did not touch. */
    function darkProbe(): Technique {
      const taken = new Set(picks ? [picks.confirmed, picks.proof, picks.failed, picks.notReproducible].map(t => t.id) : []);
      const t = parentsById().find(x => DARK_TECHNIQUES.has(x.attackId) && !taken.has(x.id)
        && (domain.groupsByTechnique.get(x.id)?.length ?? 0) > 0)!;
      expect(t).withContext('the fixture has an untouched dark parent').toBeDefined();
      expect(posture.stateFor(t).bucket).toBe('none');
      return t;
    }

    it('the dim pin can see a change: owner data or an Atomic test lifts a dimmed technique', () => {
      const probe = darkProbe();
      const dimmedNow = () => {
        filter.toggleDimUncovered();
        const d = matrix.isDimmed(probe);
        filter.toggleDimUncovered();
        return d;
      };
      expect(dimmedNow()).withContext(`${probe.attackId} dims (bucket none)`).toBeTrue();

      // An Atomic test is a Known reference input: bucket 'known', not dimmed.
      // A store write is not involved, so nudge PostureService's Known revision.
      overrideFor(TestBed.inject(AtomicService), 'getTestCount', probe.attackId, 2);
      const registry = TestBed.inject(SourceRegistryService);
      registry.succeed(registry.all()[0].id);
      expect(posture.stateFor(probe).bucket).toBe('known');
      expect(dimmedNow()).toBeFalse();
      overrideFor(TestBed.inject(AtomicService), 'getTestCount', probe.attackId, 0);
      registry.succeed(registry.all()[0].id);
      expect(dimmedNow()).toBeTrue();

      // A technique confirmation: bucket 'covered', not dimmed.
      expect(TestBed.inject(TechniqueMarksService).confirm(keyOf(probe))).toBeTrue();
      expect(posture.stateFor(probe).bucket).toBe('covered');
      expect(dimmedNow()).toBeFalse();
    });

    it('the OnPush matrix re-checks on a posture change under Dim uncovered alone, and re-sorts only under Sort by risk', () => {
      const cdr = (matrix as unknown as { cdr: { markForCheck(): void } }).cdr;
      const mark = spyOn(cdr, 'markForCheck').and.callThrough();
      const resort = spyOn(matrix as unknown as { rebuildSortedColumns(): void }, 'rebuildSortedColumns').and.callThrough();
      const probe = darkProbe();
      const settle = () => { TestBed.tick(); mark.calls.reset(); resort.calls.reset(); };
      let n = 0;
      const postureChange = () => {
        expect(TestBed.inject(ValidationService).importJson(JSON.stringify({ runs: [
          { id: `p209-cd-${++n}`, techniqueId: probe.attackId, runDate: daysBeforeSeedToday(n), status: 'not-reproducible',
            attackResult: 'executed' },
        ] })).ok).toBeTrue();
        TestBed.tick();
      };
      filter.setSortMode('alpha');
      settle();

      // Neither on: a posture change asks for nothing.
      expect(matrix.dimUncovered).toBeFalse();
      postureChange();
      expect(mark).not.toHaveBeenCalled();
      expect(resort).not.toHaveBeenCalled();

      // Dim uncovered alone (sort alpha): re-check, no re-sort.
      filter.toggleDimUncovered();
      settle();
      postureChange();
      expect(mark).toHaveBeenCalled();
      expect(resort).not.toHaveBeenCalled();
      filter.toggleDimUncovered();

      // Sort by risk: re-sort and re-check.
      filter.setSortMode('coverage');
      settle();
      postureChange();
      expect(resort).toHaveBeenCalled();
      expect(mark).toHaveBeenCalled();
      filter.setSortMode('alpha');
    });

    it('the counters and the risk sort can see a stale proof: it leaves the counters and loses its doubling', () => {
      const probe = darkProbe();
      const start = dashboard();
      const doubled = risk(probe);
      expect(TestBed.inject(ValidationService).importJson(JSON.stringify({ runs: [
        { id: 'p209-stale', techniqueId: probe.attackId, runDate: daysBeforeSeedToday(200), status: 'passed', attackResult: 'executed',
          detectionsFired: ['sigma:p2-09-stale'] },
      ] })).ok).toBeTrue();
      expect(posture.stateFor(probe).bucket).toBe('stale');
      expect(dashboard().criticalRiskCount).toBe(start.criticalRiskCount - 1);
      expect(risk(probe) * 2).toBe(doubled);
    });

    it('the KEV-gap pin can see a change: an undefended (dark) technique given a KEV CVE is a KEV-exposed gap until the owner covers it', () => {
      const start = dashboard();
      expect(start).withContext('the component reproduces the pinned counters').toEqual(afterPin(profile)!.dashboard);

      const cves = TestBed.inject(AttackCveService);
      const enrichment = TestBed.inject(EnrichmentService);
      const probe = darkProbe();
      expect(hasDefensiveReference(enrichment.signals(probe, domain))).toBeFalse();
      expect(cves.getKevCvesForTechnique(probe.attackId)).toEqual([]);

      overrideFor(cves, 'getKevCvesForTechnique', probe.attackId, [{ cveId: `CVE-2024-${probe.attackId.slice(1)}0` }]);
      const one = dashboard();
      expect(one.kevExposedGapCount).toBe(start.kevExposedGapCount + 1);
      expect(one.kevExposedGapCount).toBe(1);
      expect(one.criticalRiskCount).withContext('KEV is not a criticalRisk input').toBe(start.criticalRiskCount);

      // Every untouched dark parent at once cannot hide.
      const recorded = (t: Technique) => RECORDED.has(posture.stateFor(t).bucket);
      const darkParents = parentsById().filter(t => DARK_TECHNIQUES.has(t.attackId) && !recorded(t));
      expect(darkParents.length).toBeGreaterThanOrEqual(3);
      for (const t of darkParents) {
        if (t !== probe) overrideFor(cves, 'getKevCvesForTechnique', t.attackId, [{ cveId: `CVE-2024-${t.attackId.slice(1)}0` }]);
      }
      expect(dashboard().kevExposedGapCount).toBe(darkParents.length);

      // Covered (a technique confirmation) takes it out of both counters.
      expect(TestBed.inject(TechniqueMarksService).confirm(keyOf(probe))).toBeTrue();
      const covered = dashboard();
      expect(covered.kevExposedGapCount).toBe(darkParents.length - 1);
      expect(covered.criticalRiskCount).toBe(start.criticalRiskCount - 1);
    });

    it('the KEV-gap pin can see a change: a KEV-mapped parent stripped of every defensive link is a KEV-exposed gap', () => {
      const start = dashboard();
      const cves = TestBed.inject(AttackCveService);
      const enrichment = TestBed.inject(EnrichmentService);
      const target = parentsById()
        .find(t => cves.getKevCvesForTechnique(t.attackId).length > 0 && !RECORDED.has(posture.stateFor(t).bucket))!;
      expect(target).withContext('the fixture has a KEV-mapped parent with nothing of the owner recorded').toBeDefined();
      expect(hasDefensiveReference(enrichment.signals(target, domain))).withContext(`${target.attackId} is mapped today`).toBeTrue();

      // Strip its mitigation, detection, control and D3FEND links.
      const id = target.attackId;
      (target as { mitigationCount?: number }).mitigationCount = 0;
      domain.mitigationsByTechnique.delete(target.id);
      overrideFor(TestBed.inject(SigmaService), 'getRuleCount', id, 0);
      overrideFor(TestBed.inject(CARService), 'getLiveCount', id, 0);
      for (const svc of [NistMappingService, CriProfileService, CisControlsService, CsaCcmService, M365ControlsService]) {
        overrideFor(TestBed.inject(svc as unknown as typeof NistMappingService), 'getControlCount', id, 0);
      }
      overrideFor(TestBed.inject(D3fendService), 'getCountermeasures', id, []);
      expect(hasDefensiveReference(enrichment.signals(target, domain))).withContext(`${id} stripped`).toBeFalse();

      const stripped = dashboard();
      expect(stripped.kevExposedGapCount).toBe(start.kevExposedGapCount + 1);
      expect(stripped.kevExposedGapCount).toBe(1);
    });
  });
}
