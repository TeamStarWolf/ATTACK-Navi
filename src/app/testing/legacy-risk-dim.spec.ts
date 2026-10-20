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
//     dimUncovered on, which reads EnrichmentService.isEnriched); empty on the
//     fixture today, with a sensitivity spec that shows the pin can move;
//   - dashboard: criticalRiskCount and kevExposedGapCount (dashboard-panel's
//     own predicates; the gap count is not rendered, so it is recomputed with
//     the component's predicate and cross-checked through postureScore);
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
import { DataService } from '../services/data.service';
import { EnrichmentService } from '../services/enrichment.service';
import { FilterService } from '../services/filter.service';
import { ImplementationService, ImplStatus } from '../services/implementation.service';
import { DARK_TECHNIQUES, controlsProvider, parseFixtureDomain, resetBrowserState, signalStubProviders } from './lens-harness';

const SEEDED = ['M1026', 'M1047'] as const;

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

interface RiskDimValues {
  riskTop20: [string, number][];
  dimmed: string[];
  dashboard: { criticalRiskCount: number; kevExposedGapCount: number; postureScore: number };
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

      // Dashboard threat-gap counters (dashboard-panel.component.ts).
      const dash = TestBed.createComponent(DashboardPanelComponent);
      dash.detectChanges();
      const stats = dash.componentInstance.stats!;
      const cves = TestBed.inject(AttackCveService);
      const kevExposedGapCount = parents.filter(t =>
        cves.getKevCvesForTechnique(t.attackId).length > 0 && !enrichment.hasDefensiveSignal(t, domain)).length;
      const critical = parents.filter(t =>
        (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0 && !enrichment.hasDefensiveSignal(t, domain)).length;
      expect(stats.criticalRiskCount).withContext('criticalRiskCount predicate').toBe(critical);
      dash.destroy();

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
        dashboard: { criticalRiskCount: stats.criticalRiskCount, kevExposedGapCount, postureScore: stats.postureScore },
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

    it('today, risk, dim and the threat-gap counters ignore implemented mitigations (P2-09 changes this)', () => {
      const v = values();
      const other = (BASELINE as unknown as { riskDim: Record<string, RiskDimValues | undefined> }).riskDim[profile === 'fresh' ? 'seeded' : 'fresh'];
      expect(other).withContext('both profiles are pinned').toBeDefined();
      expect(v.riskTop20).toEqual(other!.riskTop20);
      expect(v.dimmed).toEqual(other!.dimmed);
      expect(v.dashboard).toEqual(other!.dashboard);
    });
  });
}
