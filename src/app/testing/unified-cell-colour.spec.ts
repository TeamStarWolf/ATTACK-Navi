// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Characterization baseline (Phase 2 design P2-01, R4): the colour
// TechniqueCellComponent paints for heat=unified (Reference depth) on every
// fixture technique, with colorblindSafe off and on. The lens snapshots
// (lens-snapshots.json) hold only the matrix/minimap copy (getCellColor), which
// has no colour-blind branch; the cell's computeUnifiedColor switched to
// viridis under colorblindSafe. P2-15 moved unified into the LensRegistry (the
// cell now paints through the unified def's `color`, the score is its
// `project`) and keeps both columns byte-identical.
//
// Pinned in __snapshots__/legacy-baseline.json, section unifiedCellColour, as
// { attackId: [score, colour off, colour on] }, on the fresh profile; the seeded
// profile (M1047 and M1026 'implemented') must paint the same colours, since
// Reference depth is a Known-rung number that no owner data moves.
//
// To update after an INTENDED change: run this spec, copy the logged
// "[legacy-baseline] <section> <json>" line's json into that section of the
// JSON file, and review the diff. Never hand-edit a value to make it pass.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import BASELINE from './__snapshots__/legacy-baseline.json';
import { MatrixComponent } from '../components/matrix/matrix.component';
import { heatmapModeDef } from '../models/heatmap-modes';
import { registryCell } from '../models/lens-registry';
import { TechniqueCellComponent } from '../components/technique-cell/technique-cell.component';
import { Domain } from '../models/domain';
import { DataService } from '../services/data.service';
import { FilterService } from '../services/filter.service';
import { ImplementationService } from '../services/implementation.service';
import { SettingsService } from '../services/settings.service';
import { controlsProvider, parseFixtureDomain, resetBrowserState, signalStubProviders } from './lens-harness';

const SEEDED = ['M1026', 'M1047'] as const;
const LIBRARY_MANIFEST = [{ file: 'lens-fixture-a.json', name: 'Lens fixture A', description: '' }];

function pin(path: string, actual: unknown): void {
  const expected = path.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], BASELINE);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) console.log(`[legacy-baseline] ${path} ${JSON.stringify(actual)}`);
  expect(actual).withContext(`legacy baseline "${path}" changed; see the spec header`).toEqual(expected);
}

type Colours = Record<string, [number, string, string]>;

for (const profile of ['fresh', 'seeded'] as const) {
  describe(`Unified (Reference depth) cell colour, colorblindSafe off and on, ${profile} profile (characterization, P2-01)`, () => {
    let domain: Domain;
    let matrix: MatrixComponent;

    beforeEach(() => {
      resetBrowserState();
      domain = parseFixtureDomain();
      TestBed.configureTestingModule({
        imports: [MatrixComponent, TechniqueCellComponent],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), ...signalStubProviders(), controlsProvider(domain)],
      });
      TestBed.overrideTemplate(MatrixComponent, '');
      (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
      if (profile === 'seeded') {
        const impl = TestBed.inject(ImplementationService);
        for (const id of SEEDED) impl.setStatus(domain.mitigations.find(m => m.attackId === id)!.id, 'implemented');
      }
      const fixture = TestBed.createComponent(MatrixComponent);
      fixture.componentRef.setInput('domain', domain);
      fixture.detectChanges();
      matrix = fixture.componentInstance;
      TestBed.inject(HttpTestingController).expectOne('assets/data/library-layers/index.json').flush(LIBRARY_MANIFEST);
      TestBed.inject(FilterService).setHeatmapMode('unified');
    });

    afterEach(() => resetBrowserState());

    function colours(): Colours {
      const settings = TestBed.inject(SettingsService);
      expect(settings.current.colorblindSafe).withContext('default is off').toBeFalse();
      const out: Colours = {};
      const techs = [...domain.techniques].sort((a, b) => a.attackId.localeCompare(b.attackId));
      for (const t of techs) {
        const score = registryCell(heatmapModeDef('unified')!, matrix.lensContext(), t).score;
        const cell = TestBed.createComponent(TechniqueCellComponent);
        cell.componentRef.setInput('technique', t);
        cell.componentRef.setInput('heatmapMode', 'unified');
        cell.componentRef.setInput('unifiedScore', score);
        cell.detectChanges();
        const off = cell.componentInstance.bgColor;
        settings.update({ colorblindSafe: true });
        cell.detectChanges();
        const on = cell.componentInstance.bgColor;
        settings.update({ colorblindSafe: false });
        cell.destroy();
        out[t.attackId] = [Math.round(score * 1e6) / 1e6, off, on];
      }
      return out;
    }

    it('pins the cell colour for every fixture technique', () => {
      const c = colours();
      expect(Object.keys(c).length).toBe(domain.techniques.length);
      // Non-degenerate: several stops in each column, and the two columns differ.
      expect(new Set(Object.values(c).map(v => v[1])).size).toBeGreaterThan(1);
      expect(new Set(Object.values(c).map(v => v[2])).size).toBeGreaterThan(1);
      expect(Object.values(c).every(v => v[1] !== v[2])).withContext('colorblindSafe switches every cell').toBeTrue();
      // The fresh profile owns the pin; the seeded profile must paint the same.
      pin('unifiedCellColour', c);
    });
  });
}
