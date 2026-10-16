// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Characterization ("golden master") specs for the 33 heatmap lenses.
//
// For every mode in HEATMAP_MODES this spec builds a fresh MatrixComponent on
// the fixed fixture domain (see lens-harness.ts), switches to that mode, and
// compares the per-technique score map — [score, cell colour] for each of the
// fixture's techniques, keyed and sorted by ATT&CK id — with the committed
// snapshot in __snapshots__/lens-snapshots.json. ANY change to a score map, a
// colour ramp or the set of modes fails here.
//
// When a change is intended, regenerate and review the diff:
//   node scripts/update-lens-snapshots.mjs
// (it runs this spec, collects the "[lens-snapshot]" lines a mismatching spec
// logs, and rewrites the JSON). Never hand-edit the snapshot to make it pass.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import SNAPSHOTS from './__snapshots__/lens-snapshots.json';
import { MatrixComponent } from '../components/matrix/matrix.component';
import { HEATMAP_MODES } from '../models/heatmap-modes';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { DataService } from '../services/data.service';
import { FilterService, HeatmapMode } from '../services/filter.service';
import { ImplementationService } from '../services/implementation.service';
import { SigmaService } from '../services/sigma.service';
import {
  IMPL_CYCLE, LENS_FIXTURE, controlsProvider, parseFixtureDomain, resetBrowserState,
  signal, signalStubProviders, sortedMitigations,
} from './lens-harness';

type Score = number | string | null;
type SnapshotEntry = [Score, string];
type ModeSnapshot = Record<string, SnapshotEntry>;

const COMMITTED = SNAPSHOTS as unknown as Record<string, ModeSnapshot>;

/**
 * How to read a technique's score in each mode. Typed as a Record over the
 * HeatmapMode union, so adding a mode without teaching this table about it is
 * a compile error, not a silently missing snapshot.
 */
const SCORE: Record<HeatmapMode, (m: MatrixComponent, t: Technique) => Score> = {
  coverage: (_m, t) => t.mitigationCount,
  status: (m, t) => m.getTechniqueImplStatus(t),
  controls: (m, t) => m.getControlStatus(t),
  unified: (m, t) => m.getUnifiedScore(t),
  library: (m, t) => m.getLibraryScore(t),
  frequency: (m, t) => m.getFrequencyScore(t),
  risk: (m, t) => m.getRiskScore(t),
  exposure: (m, t) => m.getExposureScore(t),
  software: (m, t) => m.getSoftwareScore(t),
  campaign: (m, t) => m.getCampaignScore(t),
  intelligence: (m, t) => m.getIntelScore(t),
  'my-exposure': (m, t) => m.getMyExposureScore(t),
  kev: (m, t) => m.getKevScore(t),
  cve: (m, t) => m.getCveScore(t),
  epss: (m, t) => m.getEpssScore(t),
  'kill-chain': (m, t) => m.getKillChainScore(t),
  'poc-exploits': (m, t) => m.getPocScore(t),
  detection: (m, t) => m.getDetectionScore(t),
  sigma: (m, t) => m.getSigmaScore(t),
  elastic: (m, t) => m.getElasticScore(t),
  splunk: (m, t) => m.getSplunkScore(t),
  wazuh: (m, t) => m.getWazuhScore(t),
  m365: (m, t) => m.getM365Score(t),
  car: (m, t) => m.getCarScore(t),
  atomic: (m, t) => m.getAtomicScore(t),
  d3fend: (m, t) => m.getD3fendScore(t),
  engage: (m, t) => m.getEngageScore(t),
  nist: (m, t) => m.getNistScore(t),
  veris: (m, t) => m.getVerisScore(t),
  cri: (m, t) => m.getCriScore(t),
  'csa-ccm': (m, t) => m.getCsaCcmScore(t),
  'm365-controls': (m, t) => m.getM365ControlsScore(t),
  // F3 origin is a categorical lens: shared-with-ATT&CK (T-id) vs fraud-native.
  'f3-origin': (_m, t) => (t.attackId.startsWith('T') ? 'shared' : 'native'),
};

/** Lenses whose fixture snapshot is legitimately single-valued (see the spec below). */
const SINGLE_VALUED = new Set<HeatmapMode>(['f3-origin']);

/** Curated library layers served to the real LibraryLayerService. */
const LIBRARY_MANIFEST = [
  { file: 'lens-fixture-a.json', name: 'Lens fixture A', description: 'first manifest entry (auto-selected)' },
  { file: 'lens-fixture-b.json', name: 'Lens fixture B', description: 'never selected by the matrix' },
];
function libraryLayerA(): { name: string; description: string; techniques: Array<{ techniqueID: string; score?: number }> } {
  const ids = LENS_FIXTURE.x_lens_fixture.techniques;
  const techniques: Array<{ techniqueID: string; score?: number }> = ids
    .filter(id => signal('library', id) > 0)
    .map(id => ({ techniqueID: id, score: signal('library', id) * 15 }));
  // One entry without a score: the service defaults it to 100.
  techniques.push({ techniqueID: ids[ids.length - 1] });
  return { name: 'Lens fixture A', description: '', techniques };
}

const round = (v: Score): Score => (typeof v === 'number' ? Math.round(v * 1e6) / 1e6 : v);

describe('Heatmap lens characterization (33 modes, fixed fixture)', () => {
  let domain: Domain;
  let matrix: MatrixComponent;
  let filter: FilterService;
  let http: HttpTestingController;

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
    // Score maps are computed in the class, not the template: render nothing.
    TestBed.overrideTemplate(MatrixComponent, '');

    // Real FilterService / DataService, with the fixture domain published.
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    filter = TestBed.inject(FilterService);
    http = TestBed.inject(HttpTestingController);

    // User state the status / exposure lenses read.
    const impl = TestBed.inject(ImplementationService);
    sortedMitigations(domain).forEach((m, i) => impl.setStatus(m.id, IMPL_CYCLE[i % IMPL_CYCLE.length]));
    const groups = [...domain.groups].sort((a, b) => a.attackId.localeCompare(b.attackId));
    for (const g of groups.slice(0, 3)) filter.toggleThreatGroup(g.id);

    const fixture = TestBed.createComponent(MatrixComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    matrix = fixture.componentInstance;

    // The real LibraryLayerService asks for its manifest at construction.
    http.expectOne('assets/data/library-layers/index.json').flush(LIBRARY_MANIFEST);
  });

  afterEach(() => {
    resetBrowserState();
  });

  function snapshotOf(mode: HeatmapMode): ModeSnapshot {
    filter.setHeatmapMode(mode);
    if (mode === 'library') {
      // Library mode with no user layer auto-selects manifest[0] and fetches it.
      http.expectOne(`assets/data/library-layers/${LIBRARY_MANIFEST[0].file}`).flush(libraryLayerA());
    }
    const out: ModeSnapshot = {};
    const techs = [...domain.techniques].sort((a, b) => a.attackId.localeCompare(b.attackId));
    for (const t of techs) out[t.attackId] = [round(SCORE[mode](matrix, t)), matrix.getCellColor(t)];
    return out;
  }

  it('covers exactly the 33 modes in HEATMAP_MODES, with no stale snapshot', () => {
    const modes = HEATMAP_MODES.map(m => m.value);
    expect(modes.length).toBe(33);
    expect(new Set(modes).size).toBe(33);
    expect(Object.keys(SCORE).sort()).toEqual([...modes].sort());
    expect(Object.keys(COMMITTED).sort()).toEqual([...modes].sort());
  });

  it('snapshots every fixture technique in every mode', () => {
    const ids = [...domain.techniques].map(t => t.attackId).sort();
    expect(ids).toEqual([...LENS_FIXTURE.x_lens_fixture.techniques].sort());
    for (const m of HEATMAP_MODES) {
      expect(Object.keys(COMMITTED[m.value] ?? {}).sort()).withContext(m.value).toEqual(ids);
    }
  });

  it('has a non-degenerate snapshot for every lens except the categorical F3 origin', () => {
    // A lens whose snapshot holds a single value cannot detect a change in its
    // inputs. F3 origin only distinguishes T-ids from F-ids, and the Enterprise
    // fixture has no F-ids, so it is the one documented exception.
    for (const m of HEATMAP_MODES) {
      const values = new Set(Object.values(COMMITTED[m.value] ?? {}).map(e => JSON.stringify(e[0])));
      if (SINGLE_VALUED.has(m.value)) {
        expect(values.size).withContext(m.value).toBe(1);
      } else {
        expect(values.size).withContext(m.value).toBeGreaterThan(1);
      }
    }
  });

  for (const def of HEATMAP_MODES) {
    it(`${def.value}: score map matches the committed snapshot`, () => {
      const actual = snapshotOf(def.value);
      const expected = COMMITTED[def.value];
      const same = JSON.stringify(actual) === JSON.stringify(expected);
      if (!same) {
        // Machine-readable line for scripts/update-lens-snapshots.mjs.
        console.log(`[lens-snapshot] ${def.value} ${JSON.stringify(actual)}`);
      }
      expect(actual).withContext(`lens "${def.value}" changed; see the spec header to update`).toEqual(expected);
    });
  }

  it('is sensitive: perturbing one input changes the affected lens', () => {
    // Guards against a snapshot that would pass no matter what (e.g. a lens
    // reading a map that is never filled).
    const sigma = TestBed.inject(SigmaService) as unknown as { getRuleCount(id: string): number };
    const target = Object.entries(COMMITTED['sigma']).find(([, e]) => e[0] === 0)![0];
    const original = sigma.getRuleCount;
    sigma.getRuleCount = (id: string) => (id === target ? 99 : original(id));
    const after = snapshotOf('sigma');
    expect(after[target][0]).toBe(99);
    expect(after).not.toEqual(COMMITTED['sigma']);
  });

  it('does not issue any unexpected HTTP request', () => {
    for (const def of HEATMAP_MODES) snapshotOf(def.value);
    expect(() => http.verify()).not.toThrow();
  });
});
