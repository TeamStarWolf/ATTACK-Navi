// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Characterization baseline (Phase 2 design P2-01, R18): the LEGACY risk, dim
// and threat-gap answers and the legacy status fold, pinned as they are today,
// on a fresh profile and on the seeded profile (M1047 and M1026 'implemented').
// P2-09 makes risk, dim and the threat-gap counters read posture, and P2-14
// re-derives the status lens and impl= from PostureService; each updates this
// baseline in the same PR, so the diff shows exactly which numbers moved.
//
// Pinned in __snapshots__/legacy-baseline.json, section riskDim.<profile>:
//   - riskTop20: Sort by risk (matrix sortMode 'coverage', comparator over
//     EnrichmentService.riskScore with the matrix's KEV scores), the first 20
//     parent techniques as [attackId, score];
//   - dimmed: the techniques "Dim uncovered" dims (matrix isDimmed with
//     dimUncovered on, which reads hasAnySignal over EnrichmentService.signals,
//     the retired isEnriched's logic, P2-08); empty on the fixture today, with a
//     sensitivity spec that shows the pin can move;
//   - dashboard: criticalRiskCount and kevExposedGapCount, read from
//     DashboardPanelComponent's stats (the KEV-gap count is exposed there,
//     unrendered, for this pin; an independent recomputation of both predicates
//     cross-checks them). The KEV-gap count is 0 on the fixture by construction
//     (every KEV-mapped technique has a defensive reference input; the
//     DARK_TECHNIQUES have no CVE signal), so two sensitivity specs below show
//     the pin can move: a dark technique given a KEV CVE, and a KEV-mapped
//     parent stripped of every defensive link, each become a KEV-exposed gap.
//     The baseline also holds the legacy postureScore, which P2-08 deleted from
//     the dashboard (hidden since E1.5); the pin compares every other value of
//     the section byte for byte and skips only that deleted key, so the JSON
//     is unchanged and P2-09 rewrites the section with its after values;
//   - statusStops: the status-lens stop and cell colour per technique (the
//     best-status fold over every mapped mitigation);
//   - implImplemented: the techniques impl=implemented keeps (not filtered).
//
// To update after an INTENDED change: run this spec, copy each logged
// "[legacy-baseline] <section> <json>" line's json into that section of the
// JSON file, and review the diff. Never hand-edit a value to make it pass.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import BASELINE from './__snapshots__/legacy-baseline.json';
import { MatrixComponent } from '../components/matrix/matrix.component';
import { DashboardPanelComponent } from '../components/dashboard-panel/dashboard-panel.component';
import { Domain } from '../models/domain';
import { HEATMAP_MODES } from '../models/heatmap-modes';
import { Technique } from '../models/technique';
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
import { ImplementationService, ImplStatus } from '../services/implementation.service';
import { hasDefensiveReference } from '../models/known-signals';
import { DARK_TECHNIQUES, controlsProvider, parseFixtureDomain, resetBrowserState, signalStubProviders } from './lens-harness';

const SEEDED = ['M1026', 'M1047'] as const;

/** The real LibraryLayerService asks for its manifest when the matrix is built. */
const LIBRARY_MANIFEST = [{ file: 'lens-fixture-a.json', name: 'Lens fixture A', description: '' }];

/**
 * A riskDim section of the baseline without the dashboard's deleted legacy
 * postureScore (P2-08); every other value is compared as pinned.
 */
function withoutDeleted(section: unknown): unknown {
  const s = section as { dashboard?: Record<string, unknown> } | undefined;
  if (!s?.dashboard) return section;
  const { postureScore: _deleted, ...dashboard } = s.dashboard;
  return { ...s, dashboard };
}

function pin(path: string, actual: unknown): void {
  const pinned = path.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], BASELINE);
  const expected = path.startsWith('riskDim.') ? withoutDeleted(pinned) : pinned;
  if (JSON.stringify(actual) !== JSON.stringify(expected)) console.log(`[legacy-baseline] ${path} ${JSON.stringify(actual)}`);
  expect(actual).withContext(`legacy baseline "${path}" changed; see the spec header`).toEqual(expected);
}

/** The status lens's categorical stops, by the fold's answer (heatmap-modes.ts, 'status'). */
const STATUS_STOP: Record<ImplStatus | 'none', string> = {
  none: 'none', 'not-started': 'not started', 'in-progress': 'in progress', planned: 'planned', implemented: 'implemented',
};

interface DashboardValues { criticalRiskCount: number; kevExposedGapCount: number }

/** No mitigation, detection, control or D3FEND: the pure test that replaced hasDefensiveSignal (P2-08). */
const undefended = (enrichment: EnrichmentService, t: Technique, d: Domain) => !hasDefensiveReference(enrichment.signals(t, d));

/** Replace one method of an injected stub for one ATT&CK id; every other id keeps the stub's answer. */
function overrideFor(svc: object, method: string, attackId: string, value: unknown): void {
  const target = svc as Record<string, (id: string) => unknown>;
  const original = target[method].bind(svc);
  target[method] = (id: string) => (id === attackId ? value : original(id));
}

interface RiskDimValues {
  riskTop20: [string, number][];
  dimmed: string[];
  dashboard: DashboardValues;
  statusStops: Record<string, [string, string]>;
  implImplemented: string[];
}

for (const profile of ['fresh', 'seeded'] as const) {
  describe(`Legacy risk sort, dim, threat-gap counters and status fold, ${profile} profile (characterization, P2-01)`, () => {
    let domain: Domain;
    let matrix: MatrixComponent;
    let filter: FilterService;

    beforeEach(() => {
      resetBrowserState();
      domain = parseFixtureDomain();
      TestBed.configureTestingModule({
        imports: [MatrixComponent, DashboardPanelComponent],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), ...signalStubProviders(), controlsProvider(domain)],
      });
      // Score maps and the sort are computed in the class, not the template.
      TestBed.overrideTemplate(MatrixComponent, '');
      (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
      filter = TestBed.inject(FilterService);
      if (profile === 'seeded') {
        const impl = TestBed.inject(ImplementationService);
        for (const id of SEEDED) impl.setStatus(domain.mitigations.find(m => m.attackId === id)!.id, 'implemented');
      }
      const fixture = TestBed.createComponent(MatrixComponent);
      fixture.componentRef.setInput('domain', domain);
      fixture.detectChanges();
      matrix = fixture.componentInstance;
      TestBed.inject(HttpTestingController).expectOne('assets/data/library-layers/index.json').flush(LIBRARY_MANIFEST);
    });

    afterEach(() => resetBrowserState());

    const byId = (a: Technique, b: Technique) => a.attackId.localeCompare(b.attackId);

    /**
     * The dashboard's threat-gap counters, read from DashboardPanelComponent's
     * stats (kevExposedGapCount is exposed there, unrendered, for this pin;
     * dashboard-panel.component.ts buildStats).
     */
    function dashboard(): DashboardValues {
      const dash = TestBed.createComponent(DashboardPanelComponent);
      dash.detectChanges();
      const stats = dash.componentInstance.stats!;
      dash.destroy();
      return { criticalRiskCount: stats.criticalRiskCount, kevExposedGapCount: stats.kevExposedGapCount };
    }

    function values(): RiskDimValues {
      const enrichment = TestBed.inject(EnrichmentService);
      const all = [...domain.techniques].sort(byId);
      const parents = all.filter(t => !t.isSubtechnique);

      // Sort by risk: the matrix comparator, over every parent technique.
      filter.setSortMode('coverage');
      const risk = (t: Technique) => enrichment.riskScore(t, domain, matrix.kevScores.get(t.attackId) ?? 0);
      const ranked = [...parents].sort((a, b) => risk(b) - risk(a) || byId(a, b));
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

      // Dashboard threat-gap counters (dashboard-panel.component.ts), read from
      // the component; an independent recomputation cross-checks both.
      const dash = dashboard();
      const cves = TestBed.inject(AttackCveService);
      const kevGaps = parents.filter(t =>
        cves.getKevCvesForTechnique(t.attackId).length > 0 && undefended(enrichment, t, domain)).length;
      const critical = parents.filter(t =>
        (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0 && undefended(enrichment, t, domain)).length;
      expect(dash.criticalRiskCount).withContext('criticalRiskCount predicate').toBe(critical);
      expect(dash.kevExposedGapCount).withContext('kevExposedGapCount predicate').toBe(kevGaps);

      // Status lens: the best-status fold, its ramp stop and the cell colour.
      filter.setHeatmapMode('status');
      const statusDef = HEATMAP_MODES.find(m => m.value === 'status')!;
      const stopColours = new Map(statusDef.ramp.stops.map(s => [s.label, s.color]));
      const statusStops: Record<string, [string, string]> = {};
      for (const t of all) {
        const stop = STATUS_STOP[matrix.getTechniqueImplStatus(t) ?? 'none'];
        const colour = matrix.getCellColor(t);
        expect(colour).withContext(`status colour of ${t.attackId} is its ramp stop`).toBe(stopColours.get(stop)!);
        statusStops[t.attackId] = [stop, colour];
      }

      // impl=implemented: the techniques the filter keeps; every other one is dimmed.
      filter.setImplStatusFilter('implemented');
      const implImplemented = all.filter(t => !matrix.isImplFiltered(t)).map(t => t.attackId);
      for (const t of all) expect(matrix.isDimmed(t)).withContext(`impl= dims ${t.attackId}`).toBe(!implImplemented.includes(t.attackId));
      filter.setImplStatusFilter(null);

      return {
        riskTop20: ranked.slice(0, 20).map(t => [t.attackId, risk(t)] as [string, number]),
        dimmed,
        dashboard: dash,
        statusStops,
        implImplemented,
      };
    }

    it('pins the legacy values', () => {
      const v = values();
      // Non-degenerate: the pins can see a change.
      expect(v.riskTop20.length).toBe(20);
      // Today every fixture technique has some enrichment link (the undefended
      // ones are still used by a group), so Dim uncovered dims nothing; the
      // sensitivity spec below shows the pin can see a technique that loses them.
      expect(v.dimmed).toEqual([]);
      expect(v.dashboard.criticalRiskCount).toBeGreaterThan(0);
      if (profile === 'seeded') {
        expect(v.implImplemented.length).toBeGreaterThan(0);
        expect(new Set(Object.values(v.statusStops).map(s => s[0]))).toEqual(new Set(['none', 'implemented']));
      } else {
        expect(v.implImplemented).toEqual([]);
        expect(new Set(Object.values(v.statusStops).map(s => s[0]))).toEqual(new Set(['none']));
      }
      pin(`riskDim.${profile}`, v);
    });

    it('the dim pin can see a change: an undefended technique stripped of its threat links is dimmed', () => {
      const t = domain.techniques.find(x => x.attackId === 'T1007')!;
      expect(DARK_TECHNIQUES.has(t.attackId)).withContext('T1007 has no defensive or CVE signal').toBeTrue();
      domain.groupsByTechnique.delete(t.id);
      domain.softwareByTechnique.delete(t.id);
      domain.campaignsByTechnique.delete(t.id);
      expect(values().dimmed).toEqual(['T1007']);
    });

    it('the KEV-gap pin can see a change: an undefended (dark) technique given a KEV CVE is a KEV-exposed gap', () => {
      const pinned = (withoutDeleted((BASELINE as unknown as { riskDim: Record<string, RiskDimValues> }).riskDim[profile]) as RiskDimValues).dashboard;
      const before = dashboard();
      expect(before).withContext('the component reproduces the pinned counters').toEqual(pinned);

      const cves = TestBed.inject(AttackCveService);
      const enrichment = TestBed.inject(EnrichmentService);
      const t1007 = domain.techniques.find(x => x.attackId === 'T1007')!;
      expect(DARK_TECHNIQUES.has('T1007')).withContext('T1007 has no defensive or CVE signal').toBeTrue();
      expect(undefended(enrichment, t1007, domain)).toBeTrue();
      expect(cves.getKevCvesForTechnique('T1007')).toEqual([]);

      overrideFor(cves, 'getKevCvesForTechnique', 'T1007', [{ cveId: 'CVE-2024-10070' }]);
      const one = dashboard();
      expect(one.kevExposedGapCount).toBe(before.kevExposedGapCount + 1);
      expect(one.kevExposedGapCount).toBe(1);
      expect(one.criticalRiskCount).withContext('KEV is not a criticalRisk input').toBe(before.criticalRiskCount);

      // One technique moves the 0.15 KEV term by 100 * 0.15 / 45 = 0.33 points,
      // which rounding can hide; every dark parent at once cannot hide.
      const darkParents = domain.techniques.filter(t => !t.isSubtechnique && DARK_TECHNIQUES.has(t.attackId));
      expect(darkParents.length).toBeGreaterThan(3);
      for (const t of darkParents) {
        if (t.attackId !== 'T1007') overrideFor(cves, 'getKevCvesForTechnique', t.attackId, [{ cveId: `CVE-2024-${t.attackId.slice(1)}0` }]);
      }
      const all = dashboard();
      expect(all.kevExposedGapCount).toBe(darkParents.length);
      expect(all.criticalRiskCount).toBe(before.criticalRiskCount);
    });

    it('the KEV-gap pin can see a change: a KEV-mapped parent stripped of every defensive link is a KEV-exposed gap', () => {
      const before = dashboard();
      const cves = TestBed.inject(AttackCveService);
      const enrichment = TestBed.inject(EnrichmentService);
      const target = domain.techniques.filter(t => !t.isSubtechnique).sort(byId)
        .find(t => cves.getKevCvesForTechnique(t.attackId).length > 0)!;
      expect(target).withContext('the fixture has a KEV-mapped parent').toBeDefined();
      expect(undefended(enrichment, target, domain)).withContext(`${target.attackId} has a defensive reference today`).toBeFalse();

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
      expect(undefended(enrichment, target, domain)).withContext(`${id} stripped`).toBeTrue();

      const after = dashboard();
      expect(after.kevExposedGapCount).toBe(before.kevExposedGapCount + 1);
      expect(after.kevExposedGapCount).toBe(1);
    });

    it('today, risk, dim and the threat-gap counters ignore implemented mitigations (P2-09 changes this)', () => {
      const v = values();
      const other = (BASELINE as unknown as { riskDim: Record<string, RiskDimValues | undefined> }).riskDim[profile === 'fresh' ? 'seeded' : 'fresh'];
      expect(other).withContext('both profiles are pinned').toBeDefined();
      expect(v.riskTop20).toEqual(other!.riskTop20);
      expect(v.dimmed).toEqual(other!.dimmed);
      expect(v.dashboard).toEqual((withoutDeleted(other) as RiskDimValues).dashboard);
    });
  });
}
