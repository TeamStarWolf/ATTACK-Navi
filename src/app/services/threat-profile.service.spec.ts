// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { BehaviorSubject, of } from 'rxjs';
import { ThreatProfileService } from './threat-profile.service';
import { DataService, AttackDomain } from './data.service';
import { LibraryLayerService } from './library-layer.service';
import { Domain } from '../models/domain';
import { ThreatProfile } from '../models/threat-profile';

const KEY = 'navi.v2.threat-profile';

/** A one-group, one-technique domain, enough to prove resolution and weight. */
function tinyDomain(): Domain {
  const t = { id: 't1', attackId: 'T1', name: 'T1', isSubtechnique: false, parentId: null } as unknown as Domain['techniques'][number];
  const g = { id: 'g1', attackId: 'G0001', name: 'G1', aliases: [] } as unknown as Domain['groups'][number];
  return {
    name: 'Enterprise ATT&CK', techniques: [t], groups: [g],
    groupsByTechnique: new Map([['t1', [g]]]), techniquesByGroup: new Map([['g1', [t]]]),
    campaigns: [], campaignsByGroup: new Map(), techniquesByCampaign: new Map(), attackVersion: '19.2',
  } as unknown as Domain;
}

function makeService(domainSubject = new BehaviorSubject<Domain | null>(null), layerIds: readonly string[] = []): ThreatProfileService {
  const data = {
    domain$: domainSubject.asObservable(),
    getCurrentDomain: () => domainSubject.value,
    getCurrentAttackDomain: () => 'enterprise' as AttackDomain,
  };
  const library = { layerTechniqueIds: (_file: string) => of(layerIds), manifest: [] as unknown[] };
  return new ThreatProfileService(data as unknown as DataService, library as unknown as LibraryLayerService);
}

describe('ThreatProfileService', () => {
  beforeEach(() => localStorage.removeItem(KEY));
  afterEach(() => localStorage.removeItem(KEY));

  it('defaults to Top 20 groups by prevalence', () => {
    const svc = makeService();
    expect(svc.current.source).toEqual({ kind: 'top-groups', n: 20 });
    expect(svc.current.label).toBe('Top 20 groups by prevalence');
  });

  it('profile$ emits synchronously on subscribe', () => {
    const svc = makeService();
    let emitted: ThreatProfile | undefined;
    svc.profile$.subscribe((p) => (emitted = p));
    expect(emitted).toBeDefined();
    expect(emitted!.source.kind).toBe('top-groups');
  });

  it('persists a chosen source and restores it in a new instance', () => {
    makeService().setSource({ kind: 'all' });
    expect(makeService().current.source.kind).toBe('all');
  });

  it('falls back to the default when storage is corrupt', () => {
    localStorage.setItem(KEY, 'not-json{');
    expect(makeService().current.source).toEqual({ kind: 'top-groups', n: 20 });
  });

  it('rejects a malformed record (ids not an array) and falls back to the default', () => {
    // A poisoned bundle import: passes a naive kind/source/createdAt check but would
    // throw in `new Set(ids)`. The strict guard must drop it, not crash on load.
    localStorage.setItem(KEY, JSON.stringify({
      schema: 2, tombstones: [], records: [
        { kind: 'groups', ids: {}, source: 'manual', domain: 'enterprise', attackVersion: '19.2', createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z' },
      ],
    }));
    expect(makeService().current.source).toEqual({ kind: 'top-groups', n: 20 });
  });

  it('restores a valid groups source with string ids', () => {
    localStorage.setItem(KEY, JSON.stringify({
      schema: 2, tombstones: [], records: [
        { kind: 'groups', ids: ['intrusion-set--x'], source: 'manual', domain: 'enterprise', attackVersion: '19.2', createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z' },
      ],
    }));
    expect(makeService().current.source).toEqual({ kind: 'groups', ids: ['intrusion-set--x'] });
  });

  it('resolves against a loaded domain and weight() delegates to the current profile', () => {
    const domain$ = new BehaviorSubject<Domain | null>(null);
    const svc = makeService(domain$);
    domain$.next(tinyDomain());
    svc.setSource({ kind: 'all' });
    expect(svc.current.parentTechniqueIds.has('t1')).toBeTrue();
    expect(svc.weight('t1')).toBe(svc.current.weight('t1'));
    expect(svc.weight('t1')).toBe(1);
  });

  it('resolves a library-layer source to the layer\'s techniques (not an empty profile)', () => {
    const domain$ = new BehaviorSubject<Domain | null>(null);
    const svc = makeService(domain$, ['T1']);   // the layer lists T1
    domain$.next(tinyDomain());
    svc.setSource({ kind: 'library-layer', file: 'x.json' });
    expect(svc.current.source.kind).toBe('library-layer');
    expect(svc.current.parentTechniqueIds.has('t1')).toBeTrue();
  });

  it('round-trips sources that carry n, ids and file', () => {
    makeService().setSource({ kind: 'top-groups', n: 7 });
    expect(makeService().current.source).toEqual({ kind: 'top-groups', n: 7 });
    makeService().setSource({ kind: 'groups', ids: ['intrusion-set--a', 'intrusion-set--b'] });
    expect(makeService().current.source).toEqual({ kind: 'groups', ids: ['intrusion-set--a', 'intrusion-set--b'] });
    makeService().setSource({ kind: 'library-layer', file: 'ransomware.json' });
    expect(makeService().current.source).toEqual({ kind: 'library-layer', file: 'ransomware.json' });
  });
});
