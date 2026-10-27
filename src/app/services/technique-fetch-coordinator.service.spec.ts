// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// TechniqueFetchCoordinator (technique page design 4.4, PR 1): the one place
// both hosts start a technique's per-technique live fetches. One D3FEND live call
// and one Atomic YAML request per technique, whichever host asks first and however
// often; each failure reaches the SourceRegistry as failed, never as "no data".
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATOMIC_LIVE_LIMIT, TechniqueFetchCoordinator } from './technique-fetch-coordinator.service';
import { D3fendService, d3fendTechniqueApiUrl } from './d3fend.service';
import { SourceRegistryService } from './source-registry.service';
import type { AtomicLiveTest } from './atomic.service';

const ATOMIC_YAML = (id: string) => `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/${id}/${id}.yaml`;

/** A minimal Atomic Red Team YAML with `n` tests. */
function atomicYaml(id: string, n: number): string {
  const tests = Array.from({ length: n }, (_, i) => [
    `- name: Test ${i + 1}`,
    `  auto_generated_guid: 00000000-0000-0000-0000-00000000000${i}`,
    '  description: A test.',
    '  supported_platforms:',
    '  - windows',
    '  executor:',
    '    name: powershell',
    '    command: Write-Host hi',
  ].join('\n'));
  return [`attack_technique: ${id}`, 'display_name: Something', 'atomic_tests:', ...tests].join('\n');
}

/** One D3FEND API binding for `attackId`. */
function d3fendAnswer(defs: readonly string[]) {
  return {
    off_to_def: {
      results: {
        bindings: defs.map((d, i) => ({
          def_tech_id: { value: `D3-X${i}` },
          def_tech_label: { value: d },
          def_tactic_label: { value: 'Detect' },
          def_tech: { value: `http://d3fend.mitre.org/ontologies/d3fend.owl#${d.replace(/\s+/g, '')}` },
        })),
      },
    },
  };
}

describe('TechniqueFetchCoordinator', () => {
  let coordinator: TechniqueFetchCoordinator;
  let http: HttpTestingController;
  let sources: SourceRegistryService;
  let d3fend: D3fendService;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
    coordinator = TestBed.inject(TechniqueFetchCoordinator);
    http = TestBed.inject(HttpTestingController);
    sources = TestBed.inject(SourceRegistryService);
    d3fend = TestBed.inject(D3fendService);
  });

  const d3fendRequests = (id: string) => http.match(r => r.url === d3fendTechniqueApiUrl(id));
  const atomicRequests = (id: string) => http.match(r => r.url === ATOMIC_YAML(id));

  it('makes no request when it is created (no boot load moves)', () => {
    expect(d3fendRequests('T1037').length).toBe(0);
    expect(atomicRequests('T1037').length).toBe(0);
  });

  it('prime starts one D3FEND live call and one Atomic YAML request per technique, however often it is called', () => {
    coordinator.prime({ attackId: 'T1037' });
    coordinator.prime({ attackId: 'T1037' });
    coordinator.atomicTests({ attackId: 'T1037' }).subscribe();
    const d3 = d3fendRequests('T1037');
    const art = atomicRequests('T1037');
    expect(d3.length).withContext('one D3FEND live call').toBe(1);
    expect(art.length).withContext('one Atomic YAML request').toBe(1);
    expect(d3fend.liveState('T1037')).toBe('loading');
    expect(coordinator.atomicState('T1037')).toBe('loading');
    d3[0].flush(d3fendAnswer(['Process Analysis', 'File Analysis']));
    art[0].flush(atomicYaml('T1037', 2));
    expect(d3fend.liveState('T1037')).toBe('loaded');
    expect(coordinator.atomicState('T1037')).toBe('loaded');
    // Primed again after both answered: nothing new is asked.
    coordinator.prime({ attackId: 'T1037' });
    expect(d3fendRequests('T1037').length).toBe(0);
    expect(atomicRequests('T1037').length).toBe(0);
  });

  it('the live D3FEND answer is what every host counts once it arrives', () => {
    coordinator.prime({ attackId: 'T1037' });
    d3fendRequests('T1037')[0].flush(d3fendAnswer(['Process Analysis', 'File Analysis', 'Script Execution Analysis']));
    expect(d3fend.getCountermeasures('T1037').map(d => d.name))
      .toEqual(['Process Analysis', 'File Analysis', 'Script Execution Analysis']);
  });

  it('a sub-technique also asks for its parent, as the drawer did, and loads once both answered', () => {
    expect(d3fend.liveState('T1037.001')).withContext('nothing asked yet').toBeNull();
    coordinator.prime({ attackId: 'T1037.001' });
    const sub = d3fendRequests('T1037.001');
    const parent = d3fendRequests('T1037');
    expect(sub.length).toBe(1);
    expect(parent.length).toBe(1);
    sub[0].flush(d3fendAnswer([]));
    expect(d3fend.liveState('T1037.001')).withContext('the parent is still on its way').toBe('loading');
    parent[0].flush(d3fendAnswer(['Process Analysis']));
    expect(d3fend.liveState('T1037.001')).toBe('loaded');
  });

  it('the live count is merged before the source reads loaded, so a view re-reading on the record sees it', () => {
    const seen: number[] = [];
    sources.records$.subscribe(() => {
      if (sources.get('d3fend-technique-api').status === 'loaded') seen.push(d3fend.getCountermeasures('T1037').length);
    });
    coordinator.prime({ attackId: 'T1037' });
    d3fendRequests('T1037')[0].flush(d3fendAnswer(['Process Analysis', 'File Analysis']));
    expect(seen).toEqual([2]);
  });

  it('every subscriber for one technique shares the one Atomic answer, replayed to a late subscriber', () => {
    const first: AtomicLiveTest[][] = [];
    const late: AtomicLiveTest[][] = [];
    coordinator.atomicTests({ attackId: 'T1059.001' }).subscribe(t => first.push(t));
    atomicRequests('T1059.001')[0].flush(atomicYaml('T1059.001', ATOMIC_LIVE_LIMIT + 2));
    coordinator.atomicTests({ attackId: 'T1059.001' }).subscribe(t => late.push(t));
    expect(first.length).toBe(1);
    expect(first[0].length).withContext('the drawer lists the first five').toBe(ATOMIC_LIVE_LIMIT);
    expect(late).toEqual(first);
    expect(atomicRequests('T1059.001').length).toBe(0);
  });

  it('no Atomic tests (a 404) is an answer, not a failure', () => {
    let got: AtomicLiveTest[] | null = null;
    coordinator.atomicTests({ attackId: 'T1001' }).subscribe(t => (got = t));
    atomicRequests('T1001')[0].flush('Not Found', { status: 404, statusText: 'Not Found' });
    expect(got as AtomicLiveTest[] | null).toEqual([]);
    expect(coordinator.atomicState('T1001')).toBe('loaded');
    expect(sources.get('atomic-tests').status).not.toBe('failed');
    coordinator.prime({ attackId: 'T1001' });
    expect(atomicRequests('T1001').length).withContext('a 404 is kept: not asked again').toBe(0);
  });

  it('a failed Atomic request is reported as failed and asked again by the next prime', () => {
    let inCallback: string | null = null;
    coordinator.atomicTests({ attackId: 'T1003' }).subscribe(() => (inCallback = coordinator.atomicState('T1003')));
    atomicRequests('T1003')[0].flush('boom', { status: 503, statusText: 'Service Unavailable' });
    expect(inCallback as string | null).withContext('settled before the answer reaches a subscriber (the drawer reads it there)').toBe('failed');
    expect(coordinator.atomicState('T1003')).toBe('failed');
    expect(sources.get('atomic-tests').status).toBe('failed');
    coordinator.prime({ attackId: 'T1003' });
    expect(atomicRequests('T1003').length).withContext('the next prime asks again').toBe(1);
  });

  it('a failed D3FEND live call is reported as failed, not as "no countermeasures", and is not refetched by a prime', () => {
    coordinator.prime({ attackId: 'T1037' });
    d3fendRequests('T1037')[0].flush('rate limited', { status: 429, statusText: 'Too Many Requests' });
    expect(sources.get('d3fend-technique-api').status).toBe('failed');
    expect(d3fend.liveState('T1037')).toBe('failed');
    coordinator.prime({ attackId: 'T1037' });
    expect(d3fendRequests('T1037').length).withContext('the data-health Retry refetches it, not a prime').toBe(0);
    d3fend.retryTechniqueApi('T1037');
    expect(d3fend.liveState('T1037')).toBe('loading');
    d3fendRequests('T1037')[0].flush(d3fendAnswer(['Process Analysis']));
    expect(d3fend.liveState('T1037')).toBe('loaded');
  });
});
