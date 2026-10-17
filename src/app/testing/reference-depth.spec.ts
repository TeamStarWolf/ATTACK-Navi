// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// E1.1 acceptance spec (plan P1 row E1.1): "a technique's Reference depth does
// not change when the number of groups using it changes".
//
// Reference depth is the heat=unified lens. It is a Known-rung composite built
// from defensive reference inputs only (mitigations, detection content, CTID
// controls, D3FEND, Atomic); threat-intel and KEV are Threat-lens inputs. The
// spec checks the pure scoring function and then the real MatrixComponent on
// the E0.2 lens fixture, adding groups (and software, campaigns and KEV CVEs)
// to every technique and asserting that no Reference depth score moves while
// the Threat lenses that read those inputs do move.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject } from 'rxjs';

import { MatrixComponent } from '../components/matrix/matrix.component';
import { Domain } from '../models/domain';
import { HEATMAP_MODES } from '../models/heatmap-modes';
import { REFERENCE_DEPTH_TERMS, ReferenceDepthInputs, referenceDepthScore } from '../models/reference-depth';
import { CveService } from '../services/cve.service';
import { DataService } from '../services/data.service';
import { FilterService } from '../services/filter.service';
import { DARK_TECHNIQUES, controlsProvider, parseFixtureDomain, resetBrowserState, signalStubProviders } from './lens-harness';

describe('Reference depth (heat=unified) is a defensive-reference composite', () => {
  describe('referenceDepthScore()', () => {
    const none: ReferenceDepthInputs = { mitigations: 0, detectionContent: 0, controls: 0, d3fend: 0, atomic: 0 };

    it('is 0 with no defensive reference and 100 with every source saturated', () => {
      expect(referenceDepthScore(none)).toBe(0);
      const saturated = Object.fromEntries(
        Object.entries(REFERENCE_DEPTH_TERMS).map(([k, t]) => [k, t.saturatesAt]),
      ) as unknown as ReferenceDepthInputs;
      expect(referenceDepthScore(saturated)).toBe(100);
      expect(referenceDepthScore({ ...saturated, mitigations: 99, atomic: 99 })).toBe(100);
    });

    it('takes exactly the five defensive reference inputs, no threat or KEV term', () => {
      expect(Object.keys(REFERENCE_DEPTH_TERMS).sort())
        .toEqual(['atomic', 'controls', 'd3fend', 'detectionContent', 'mitigations']);
    });

    it('keeps the old relative weights of the defensive terms (15 / 20 / 15 / 10 / 10)', () => {
      const w = Object.fromEntries(Object.entries(REFERENCE_DEPTH_TERMS).map(([k, t]) => [k, t.weight]));
      expect(w).toEqual({ mitigations: 15, detectionContent: 20, controls: 15, d3fend: 10, atomic: 10 });
      // Detection content alone, saturated: 20 of 70 -> 29 of 100.
      expect(referenceDepthScore({ ...none, detectionContent: 5 })).toBe(29);
    });

    it('rises monotonically with each input and treats bad counts as 0', () => {
      for (const key of Object.keys(REFERENCE_DEPTH_TERMS) as Array<keyof ReferenceDepthInputs>) {
        expect(referenceDepthScore({ ...none, [key]: 1 })).withContext(key).toBeGreaterThan(0);
        expect(referenceDepthScore({ ...none, [key]: -3 })).withContext(key).toBe(0);
        expect(referenceDepthScore({ ...none, [key]: Number.NaN })).withContext(key).toBe(0);
      }
    });
  });

  describe('on the matrix (E0.2 lens fixture)', () => {
    let domain: Domain;
    let matrix: MatrixComponent;
    let filter: FilterService;
    let kev$: BehaviorSubject<Map<string, number>>;

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
      TestBed.overrideTemplate(MatrixComponent, '');
      (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
      filter = TestBed.inject(FilterService);
      kev$ = (TestBed.inject(CveService) as unknown as { kevTechScores$: BehaviorSubject<Map<string, number>> }).kevTechScores$;

      const fixture = TestBed.createComponent(MatrixComponent);
      fixture.componentRef.setInput('domain', domain);
      fixture.detectChanges();
      matrix = fixture.componentInstance;
      TestBed.inject(HttpTestingController).match(() => true);
    });

    afterEach(() => resetBrowserState());

    const sorted = () => [...domain.techniques].sort((a, b) => a.attackId.localeCompare(b.attackId));

    function depthMap(): Record<string, number> {
      filter.setHeatmapMode('unified');
      return Object.fromEntries(sorted().map(t => [t.attackId, matrix.getUnifiedScore(t)]));
    }

    function frequencyMap(): Record<string, number> {
      filter.setHeatmapMode('frequency');
      return Object.fromEntries(sorted().map(t => [t.attackId, matrix.getFrequencyScore(t)]));
    }

    it('the lens keeps its heat= id and is labelled Reference depth', () => {
      const def = HEATMAP_MODES.find(m => m.value === 'unified');
      expect(def?.label).toContain('Reference depth');
      expect(def?.short).toBe('Reference depth');
    });

    it('a technique\'s Reference depth does not change when the number of groups using it changes', () => {
      const before = depthMap();
      const freqBefore = frequencyMap();
      expect(new Set(Object.values(before)).size).toBeGreaterThan(1);

      // Every technique is now used by every group (and every software entry and
      // campaign), and carries 9 KEV CVEs.
      const allGroups = [...domain.groups];
      for (const t of domain.techniques) {
        domain.groupsByTechnique.set(t.id, allGroups);
        domain.softwareByTechnique.set(t.id, [...domain.software]);
        domain.campaignsByTechnique.set(t.id, [...domain.campaigns]);
      }
      kev$.next(new Map(domain.techniques.map(t => [t.attackId, 9] as [string, number])));

      // The threat inputs really changed (the Frequency lens reads them) ...
      const freqAfter = frequencyMap();
      expect(freqAfter).not.toEqual(freqBefore);
      expect(Object.values(freqAfter).every(n => n === allGroups.length)).toBeTrue();
      // ... and no technique's Reference depth moved.
      expect(depthMap()).toEqual(before);
    });

    it('removing every group from a technique leaves its Reference depth unchanged too', () => {
      const before = depthMap();
      for (const t of domain.techniques) domain.groupsByTechnique.set(t.id, []);
      kev$.next(new Map());
      expect(depthMap()).toEqual(before);
    });

    it('gives a technique with no defensive reference a depth of 0, whatever its threat signals', () => {
      // The fixture's 'dark' techniques have no mitigation and the stubs give them
      // no other defensive signal. Make them heavily threat-relevant first.
      const dark = sorted().filter(t => DARK_TECHNIQUES.has(t.attackId));
      expect(dark.length).toBeGreaterThan(0);
      for (const t of dark) domain.groupsByTechnique.set(t.id, [...domain.groups]);
      kev$.next(new Map(dark.map(t => [t.attackId, 9] as [string, number])));
      depthMap();
      for (const t of dark) expect(matrix.getUnifiedScore(t)).withContext(t.attackId).toBe(0);
    });
  });
});
