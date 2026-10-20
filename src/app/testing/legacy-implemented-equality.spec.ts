// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Characterization baseline (Phase 2 design P2-01, R18; plan:702
// "characterization tests always precede a rewrite of a surface"): the LEGACY
// "implemented technique" answer, pinned as it is today, before P2-07 moves
// these surfaces to PostureService.rollup.
//
// On the lens fixture (lens-harness.ts) with M1047 (13 techniques, narrow) and
// M1026 (16, broad) set 'implemented', three surfaces answer "which parent
// techniques are implemented?" with their own code:
//   - stats-bar (stats-bar.component.ts recompute: parents reached by an
//     implemented mitigation; it exposes only the count);
//   - the report split (report-split.ts isTechniqueImplemented / computeReportSplit);
//   - actor-profile (actor-profile-panel.component.ts getTechCoverage, which
//     also reaches sub-techniques; restricted to parents here).
// They must agree, and the set and its size are pinned in
// __snapshots__/legacy-baseline.json (section implementedEquality).
//
// The numbers are pinned on purpose: P2-07 changes them (the D16 breadth guard
// makes M1026's marks partial) and updates this baseline in the same PR. To
// update after an INTENDED change: run this spec, copy each logged
// "[legacy-baseline] <section> <json>" line's json into that section of the
// JSON file, and review the diff. Never hand-edit a value to make it pass.
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import BASELINE from './__snapshots__/legacy-baseline.json';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { computeReportSplit, isTechniqueImplemented } from '../models/report-split';
import { DataService } from '../services/data.service';
import { ImplementationService } from '../services/implementation.service';
import { StatsBarComponent } from '../components/stats-bar/stats-bar.component';
import { ActorProfilePanelComponent } from '../components/actor-profile-panel/actor-profile-panel.component';
import { controlsProvider, parseFixtureDomain, resetBrowserState, signalStubProviders } from './lens-harness';

/** The seeded profile: one narrow and one broad mitigation set 'implemented' (design §1.17). */
const SEEDED = ['M1026', 'M1047'] as const;

/** Compare one baseline section; log a machine-readable line when it differs. */
function pin(path: string, actual: unknown): void {
  const expected = path.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], BASELINE);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) console.log(`[legacy-baseline] ${path} ${JSON.stringify(actual)}`);
  expect(actual).withContext(`legacy baseline "${path}" changed; see the spec header`).toEqual(expected);
}

for (const profile of ['fresh', 'seeded'] as const) {
  describe(`Legacy implemented-technique set, ${profile} profile (characterization, P2-01)`, () => {
    let domain: Domain;
    let parents: Technique[];

    beforeEach(() => {
      resetBrowserState();
      domain = parseFixtureDomain();
      parents = domain.techniques.filter(t => !t.isSubtechnique);
      TestBed.configureTestingModule({
        providers: [
          provideRouter([]),
          provideHttpClient(withXhr()),
          provideHttpClientTesting(),
          ...signalStubProviders(),
          controlsProvider(domain),
        ],
      });
      (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
      if (profile === 'seeded') {
        const impl = TestBed.inject(ImplementationService);
        for (const id of SEEDED) impl.setStatus(domain.mitigations.find(m => m.attackId === id)!.id, 'implemented');
      }
    });

    afterEach(() => resetBrowserState());

    const mitigation = (attackId: string) => domain.mitigations.find(m => m.attackId === attackId)!;
    const ids = (ts: readonly Technique[]) => ts.map(t => t.attackId).sort();

    function statsBarCount(): number {
      const f = TestBed.createComponent(StatsBarComponent);
      f.componentRef.setInput('domain', domain);
      f.detectChanges();
      const n = f.componentInstance.implementedCount;
      f.destroy();
      return n;
    }

    function actorProfileSet(): string[] {
      const f = TestBed.createComponent(ActorProfilePanelComponent);
      f.detectChanges();
      const set = ids(parents.filter(t => f.componentInstance.getTechCoverage(t.id)));
      f.destroy();
      return set;
    }

    it('precondition: the loaded fixture maps M1047 to 13 techniques and M1026 to 16 (§1.17)', () => {
      expect(domain.techniquesByMitigation.get(mitigation('M1047').id)?.length).toBe(13);
      expect(domain.techniquesByMitigation.get(mitigation('M1026').id)?.length).toBe(16);
      expect(parents.length).toBe(45);
    });

    it('stats-bar, the report split and actor-profile give the same implemented parent set, pinned', () => {
      const statusMap = TestBed.inject(ImplementationService).getStatusMap();
      const report = ids(parents.filter(t => isTechniqueImplemented(domain, t, statusMap)));
      const split = computeReportSplit(domain, statusMap);
      const actor = actorProfileSet();
      const stats = statsBarCount();

      expect(actor).withContext('actor-profile vs report split').toEqual(report);
      expect(split.implemented).withContext('report split count').toBe(report.length);
      expect(stats).withContext('stats-bar count').toBe(report.length);

      // Independent oracle (reviewer walk 3): the union of the seeded
      // mitigations' parent targets, de-duplicated (at most 8 + 11 = 19).
      const oracle = profile === 'seeded'
        ? [...new Set(SEEDED.flatMap(id => (domain.techniquesByMitigation.get(mitigation(id).id) ?? [])
          .filter(t => !t.isSubtechnique).map(t => t.attackId)))].sort()
        : [];
      expect(report).withContext('oracle').toEqual(oracle);

      pin(`implementedEquality.${profile}`, {
        seeded: profile === 'seeded' ? [...SEEDED] : [],
        size: report.length,
        statsBar: stats,
        reportSplit: split.implemented,
        actorProfile: actor.length,
        allMappedImplemented: split.allMappedImplemented,
        implementedPct: split.implementedPct,
        ids: report,
      });
    });
  });
}
