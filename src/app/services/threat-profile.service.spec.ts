// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { BehaviorSubject, Subject, of } from 'rxjs';
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

// Mutable so a test can switch the named domain BEFORE domain$ emits null, which is what
// proves build(null) reads the new domain rather than keeping the stale profile's (item 9).
let currentAttackDomain: AttackDomain = 'enterprise';

function makeService(domainSubject = new BehaviorSubject<Domain | null>(null), layerIds: readonly string[] = []): ThreatProfileService {
  const data = {
    domain$: domainSubject.asObservable(),
    getCurrentDomain: () => domainSubject.value,
    getCurrentAttackDomain: () => currentAttackDomain,
  };
  const library = { layerTechniqueIds: (_file: string) => of(layerIds), manifest: [] as unknown[] };
  return new ThreatProfileService(data as unknown as DataService, library as unknown as LibraryLayerService);
}

describe('ThreatProfileService', () => {
  beforeEach(() => { localStorage.removeItem(KEY); currentAttackDomain = 'enterprise'; });
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

  it('empties the profile but names the new domain when domain$ emits null (item 9)', () => {
    const domain$ = new BehaviorSubject<Domain | null>(null);
    const svc = makeService(domain$);
    domain$.next(tinyDomain());
    svc.setSource({ kind: 'all' });
    expect(svc.current.parentTechniqueIds.has('t1')).toBeTrue();
    currentAttackDomain = 'mobile';   // the switch has already named the new domain
    domain$.next(null);               // a domain switch emits null before the new domain arrives
    expect(svc.current.parentTechniqueIds.size).toBe(0);   // no stale cross-domain denominator
    expect(svc.current.domain).toBe('mobile');             // build(null) reads the NEW domain, not the stale profile's
  });

  it('resolves a library-layer source to the layer\'s techniques (not an empty profile)', () => {
    const domain$ = new BehaviorSubject<Domain | null>(null);
    const svc = makeService(domain$, ['T1']);   // the layer lists T1
    domain$.next(tinyDomain());
    svc.setSource({ kind: 'library-layer', file: 'x.json' });
    expect(svc.current.source.kind).toBe('library-layer');
    expect(svc.current.parentTechniqueIds.has('t1')).toBeTrue();
  });

  // RP-F round 1: the Threat gaps legend keyed its "No threat profile is set" note on
  // an empty parents(); emptyReason says WHY it is empty, from the stored source.
  describe('emptyReason (RP-F round 1)', () => {
    it('is null while the profile holds techniques', () => {
      const domain$ = new BehaviorSubject<Domain | null>(tinyDomain());
      const svc = makeService(domain$);
      svc.setSource({ kind: 'groups', ids: ['g1'] });
      expect(svc.parents().size).toBe(1);
      expect(svc.emptyReason()).toBeNull();
    });

    it('names-nothing for a groups or campaigns source with no ids, loaded domain or not', () => {
      const domain$ = new BehaviorSubject<Domain | null>(null);
      const svc = makeService(domain$);
      svc.setSource({ kind: 'groups', ids: [] });
      expect(svc.emptyReason()).toBe('names-nothing');
      domain$.next(tinyDomain());
      expect(svc.emptyReason()).toBe('names-nothing');
      svc.setSource({ kind: 'campaigns', ids: [] });
      expect(svc.emptyReason()).toBe('names-nothing');
    });

    it('none-in-domain for a set profile whose groups use no technique in the loaded domain (APT29 on ICS)', () => {
      const domain$ = new BehaviorSubject<Domain | null>(tinyDomain());
      const svc = makeService(domain$);
      svc.setSource({ kind: 'groups', ids: ['intrusion-set--not-here'] });
      expect(svc.parents().size).toBe(0);
      expect(svc.emptyReason()).toBe('none-in-domain');
    });

    it('resolving while a domain switch emits null, then the loaded answer', () => {
      const domain$ = new BehaviorSubject<Domain | null>(tinyDomain());
      const svc = makeService(domain$);
      svc.setSource({ kind: 'groups', ids: ['g1'] });
      domain$.next(null);
      expect(svc.emptyReason()).toBe('resolving');
      domain$.next(tinyDomain());
      expect(svc.emptyReason()).toBeNull();
    });

    it('resolving while a library layer has not loaded, not "names nothing"', () => {
      const domain$ = new BehaviorSubject<Domain | null>(tinyDomain());
      const layer$ = new Subject<readonly string[]>();
      const data = { domain$: domain$.asObservable(), getCurrentDomain: () => domain$.value, getCurrentAttackDomain: () => currentAttackDomain };
      const library = { layerTechniqueIds: (_file: string) => layer$.asObservable(), manifest: [] as unknown[] };
      const svc = new ThreatProfileService(data as unknown as DataService, library as unknown as LibraryLayerService);
      svc.setSource({ kind: 'library-layer', file: 'x.json' });
      expect(svc.emptyReason()).toBe('resolving');
      layer$.next(['T1']);
      expect(svc.emptyReason()).toBeNull();
      layer$.next(['T9999']);   // a layer with no technique in this domain
      expect(svc.emptyReason()).toBe('none-in-domain');
    });
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
