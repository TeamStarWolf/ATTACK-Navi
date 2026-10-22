// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The CVE2CAPEC chains and the trickest PoC index load on demand (never at boot:
// the two CVE2CAPEC years are about 56 MiB of gzip that inflate to about 1.7 GB,
// which a phone's browser does not survive). Picking the CVE Kill Chain or PoC
// Exploits lens asks for its source, the cells stay unscored while it loads, and
// the lens re-renders on the source's loaded$ to the same scores the lens
// snapshot (lens-snapshots.spec.ts) holds for loaded data.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject } from 'rxjs';

import SNAPSHOTS from './__snapshots__/lens-snapshots.json';
import { MatrixComponent } from '../components/matrix/matrix.component';
import { Domain } from '../models/domain';
import { DataService } from '../services/data.service';
import { FilterService, HeatmapMode } from '../services/filter.service';
import { Cve2CapecService } from '../services/cve2capec.service';
import { PocExploitService } from '../services/poc-exploit.service';
import {
  controlsProvider, lensPostureTodayProvider, parseFixtureDomain, resetBrowserState, signal, signalStubProviders,
} from './lens-harness';

const COMMITTED = SNAPSHOTS as unknown as Record<string, Record<string, [number | string | null, string]>>;

/** A stand-in for an on-demand source: counts the asks, scores nothing until it "loads". */
function onDemandSource(source: string) {
  const state = { asks: 0, ready: false, loaded$: new BehaviorSubject<boolean>(false) };
  const count = (id: string) => (state.ready ? signal(source, id) : 0);
  return {
    state,
    stub: { loaded$: state.loaded$, loadOnDemand: () => { state.asks++; }, getChainCount: count, getPocCount: count },
    load() { state.ready = true; state.loaded$.next(true); },
  };
}

describe('On-demand lens sources (CVE Kill Chain, PoC Exploits)', () => {
  let domain: Domain;
  let matrix: MatrixComponent;
  let filter: FilterService;
  let chains: ReturnType<typeof onDemandSource>;
  let poc: ReturnType<typeof onDemandSource>;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    chains = onDemandSource('kill-chain');
    poc = onDemandSource('poc');
    TestBed.configureTestingModule({
      imports: [MatrixComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        ...signalStubProviders(),
        { provide: Cve2CapecService, useValue: chains.stub },
        { provide: PocExploitService, useValue: poc.stub },
        controlsProvider(domain),
        lensPostureTodayProvider(),
      ],
    });
    TestBed.overrideTemplate(MatrixComponent, '');
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    filter = TestBed.inject(FilterService);
    const fixture = TestBed.createComponent(MatrixComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    matrix = fixture.componentInstance;
    TestBed.inject(HttpTestingController).match(() => true);
  });

  afterEach(() => resetBrowserState());

  const scores = (mode: HeatmapMode): Record<string, number | string | null> => {
    const read = mode === 'kill-chain' ? (id: string) => matrix.getKillChainScore(byId(id)) : (id: string) => matrix.getPocScore(byId(id));
    return Object.fromEntries([...domain.techniques].map(t => t.attackId).sort().map(id => [id, read(id)]));
  };
  const byId = (id: string) => domain.techniques.find(t => t.attackId === id)!;
  const committed = (mode: HeatmapMode) =>
    Object.fromEntries(Object.entries(COMMITTED[mode]).map(([id, [score]]) => [id, score]));

  it('creating the matrix on the default lens asks for neither source', () => {
    filter.setHeatmapMode('frequency');
    expect(chains.state.asks).toBe(0);
    expect(poc.state.asks).toBe(0);
  });

  it('picking the CVE Kill Chain lens asks for the chains, then re-renders on loaded$ to the snapshot scores', () => {
    filter.setHeatmapMode('kill-chain');
    expect(chains.state.asks).toBeGreaterThan(0);
    expect(poc.state.asks).toBe(0);
    // Not loaded yet: no technique is scored, the legend says the chains are loading.
    expect(Object.values(scores('kill-chain')).every(s => s === 0)).toBeTrue();
    chains.load();
    expect(scores('kill-chain')).toEqual(committed('kill-chain'));
    expect(Object.values(scores('kill-chain')).some(s => (s as number) > 0)).toBeTrue();
  });

  it('picking the PoC Exploits lens asks for the PoC index, then re-renders on loaded$ to the snapshot scores', () => {
    filter.setHeatmapMode('poc-exploits');
    expect(poc.state.asks).toBeGreaterThan(0);
    expect(chains.state.asks).toBe(0);
    expect(Object.values(scores('poc-exploits')).every(s => s === 0)).toBeTrue();
    poc.load();
    expect(scores('poc-exploits')).toEqual(committed('poc-exploits'));
  });
});
