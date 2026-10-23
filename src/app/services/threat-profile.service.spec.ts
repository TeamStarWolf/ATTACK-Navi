// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { BehaviorSubject, Subject, of } from 'rxjs';
import { ThreatProfileService } from './threat-profile.service';
import { DataService, AttackDomain } from './data.service';
import { LibraryLayerService } from './library-layer.service';
import { Domain } from '../models/domain';
import { ThreatProfile, type GroupIndexEntry } from '../models/threat-profile';

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

/**
 * The service under test. `index` stands in for the all-domain group index (RP-F
 * decision 25); these specs use their own fixture ids, so it defaults to none, and
 * src/app/testing/profile-ids-cross-domain.spec.ts runs the bundled one.
 */
function makeService(
  domainSubject = new BehaviorSubject<Domain | null>(null), layerIds: readonly string[] = [], index: readonly GroupIndexEntry[] = [],
): ThreatProfileService {
  const data = {
    domain$: domainSubject.asObservable(),
    getCurrentDomain: () => domainSubject.value,
    getCurrentAttackDomain: () => currentAttackDomain,
  };
  const library = { layerTechniqueIds: (_file: string) => of(layerIds), manifest: [] as unknown[] };
  return new ThreatProfileService(data as unknown as DataService, library as unknown as LibraryLayerService, index);
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

  describe('cross-domain groups (RP-F decision 6)', () => {
    const APT29 = 'intrusion-set--apt29';
    const FIN7 = 'intrusion-set--fin7';
    /** A domain carrying the named groups, each using one technique. */
    function domainOf(name: string, groups: readonly [string, string][]): Domain {
      const t = { id: 't1', attackId: 'T1', name: 'T1', isSubtechnique: false, parentId: null } as unknown as Domain['techniques'][number];
      const gs = groups.map(([id, n]) => ({ id, attackId: n, name: n, aliases: [] }) as unknown as Domain['groups'][number]);
      return {
        name, techniques: [t], groups: gs,
        groupsByTechnique: new Map([['t1', gs]]), techniquesByGroup: new Map(gs.map((g) => [g.id, [t]])),
        campaigns: [], campaignsByGroup: new Map(), techniquesByCampaign: new Map(), attackVersion: '19.2',
      } as unknown as Domain;
    }
    const enterprise = () => domainOf('Enterprise ATT&CK', [[APT29, 'APT29'], [FIN7, 'FIN7']]);
    const ics = () => domainOf('ICS ATT&CK', [[FIN7, 'FIN7']]);
    const names = (refs: readonly { name: string }[]) => refs.map((r) => r.name);
    /** An all-domain group index carrying the fixture's two groups (RP-F decision 25). */
    const INDEX: readonly GroupIndexEntry[] = [
      { attackId: 'G0016', stixId: APT29, name: 'APT29', aliases: [], revoked: false, deprecated: false, domains: ['enterprise'] },
      { attackId: 'G0046', stixId: FIN7, name: 'FIN7', aliases: [], revoked: false, deprecated: false, domains: ['enterprise', 'ics'] },
    ];

    it('a domain switch never mutates the stored profile: {APT29, FIN7} on ICS is FIN7 present, APT29 absent', () => {
      const domain$ = new BehaviorSubject<Domain | null>(enterprise());
      const svc = makeService(domain$);
      svc.setSource({ kind: 'groups', ids: [APT29, FIN7] });
      const stored = localStorage.getItem(KEY);
      expect(svc.domainNotice()).toBeNull();

      currentAttackDomain = 'ics';
      domain$.next(null);                       // data.service emits null first on a switch
      expect(svc.domainNotice()).toBeNull();    // nothing to say while the domain loads
      domain$.next(ics());
      expect(localStorage.getItem(KEY)).toBe(stored);
      expect(svc.current.source).toEqual({ kind: 'groups', ids: [APT29, FIN7] });
      expect(names(svc.presentGroups(ics()))).toEqual(['FIN7']);
      expect(svc.absentGroups(ics())).toEqual([{ id: APT29, name: 'APT29' }]);
      expect(svc.domainGroups()?.domain).toBe('ics');
      expect(svc.domainNotice()).toBe('1 of 2 groups present in ICS: FIN7; APT29 has no ICS use');
      expect(svc.current.groupIds).toEqual([FIN7]);   // the counted profile uses the same rule

      currentAttackDomain = 'enterprise';
      domain$.next(enterprise());
      expect(localStorage.getItem(KEY)).toBe(stored);
      expect(names(svc.presentGroups(enterprise()))).toEqual(['APT29', 'FIN7']);
      expect(svc.absentGroups(enterprise())).toEqual([]);
      expect(svc.domainNotice()).toBeNull();
      expect(svc.current.label).toBe('2 groups');
    });

    it("the 'all' profile and an empty groups profile are unaffected", () => {
      const domain$ = new BehaviorSubject<Domain | null>(ics());
      const svc = makeService(domain$);
      svc.setSource({ kind: 'all' });
      expect(svc.presentGroups(ics())).toEqual([]);
      expect(svc.absentGroups(ics())).toEqual([]);
      expect(svc.domainNotice()).toBeNull();
      svc.setSource({ kind: 'groups', ids: [] });
      expect(svc.absentGroups(ics())).toEqual([]);
      expect(svc.domainNotice()).toBeNull();
      expect(svc.emptyReason()).toBe('names-nothing');
    });

    it('names an absent group after a reload straight into a domain that lacks it, from the group index (RP-F decision 25)', () => {
      makeService(new BehaviorSubject<Domain | null>(enterprise())).setSource({ kind: 'groups', ids: [APT29, FIN7] });
      const raw = JSON.parse(localStorage.getItem(KEY)!);
      expect(raw.records[0].groupNames).toEqual({ [APT29]: 'APT29', [FIN7]: 'FIN7' });
      expect(makeService(new BehaviorSubject<Domain | null>(ics()), [], INDEX).domainNotice())
        .toBe('1 of 2 groups present in ICS: FIN7; APT29 has no ICS use');
      // The stored hint alone is never a resolution: with no index entry the id is unresolved.
      expect(makeService(new BehaviorSubject<Domain | null>(ics())).domainNotice())
        .toBe(`1 of 2 groups present in ICS: FIN7; ${APT29}: unknown or withdrawn group id`);
    });

    it('a malformed name hint is ignored without dropping the stored source', () => {
      makeService(new BehaviorSubject<Domain | null>(enterprise())).setSource({ kind: 'groups', ids: [APT29, FIN7] });
      const raw = JSON.parse(localStorage.getItem(KEY)!);
      raw.records[0].groupNames = { [APT29]: 42, [FIN7]: '' };
      localStorage.setItem(KEY, JSON.stringify(raw));
      const svc = makeService(new BehaviorSubject<Domain | null>(ics()));
      expect(svc.current.source).toEqual({ kind: 'groups', ids: [APT29, FIN7] });
      // No name known and no domain seen that carries it: unknown or withdrawn, never absent (RP-F decision 18).
      expect(svc.absentGroups(ics())).toEqual([]);
      expect(svc.unresolvedGroups(ics())).toEqual([{ id: APT29, name: APT29, unresolved: true }]);
      raw.records[0].groupNames = ['APT29'];
      localStorage.setItem(KEY, JSON.stringify(raw));
      expect(makeService(new BehaviorSubject<Domain | null>(ics())).unresolvedGroups(ics())).toEqual([{ id: APT29, name: APT29, unresolved: true }]);
    });

    // RP-F decision 13: a profile stored with ATT&CK ids (G0016) resolved only by STIX id,
    // so every stored group read as absent: "APT29 has no Enterprise use" on Enterprise.
    describe('a profile stored with ATT&CK ids (RP-F decision 13)', () => {
      const withAttackIds = (name: string, groups: readonly [string, string, string][]): Domain => {
        const d = domainOf(name, []);
        const gs = groups.map(([id, attackId, n]) => ({ id, attackId, name: n, aliases: [] }) as unknown as Domain['groups'][number]);
        const t = d.techniques[0];
        return { ...d, groups: gs, groupsByTechnique: new Map([['t1', gs]]), techniquesByGroup: new Map(gs.map((g) => [g.id, [t]])) } as Domain;
      };
      const ent = () => withAttackIds('Enterprise ATT&CK', [[APT29, 'G0016', 'APT29'], [FIN7, 'G0046', 'FIN7']]);
      const icsOnly = () => withAttackIds('ICS ATT&CK', [[FIN7, 'G0046', 'FIN7']]);

      it('reads every stored group present on Enterprise, after a reload, with no absent notice', () => {
        makeService(new BehaviorSubject<Domain | null>(ent())).setSource({ kind: 'groups', ids: ['G0016', 'g0046'] });
        // RP-F decision 18: one shape in storage; the ATT&CK ids are written back as STIX ids.
        expect(JSON.parse(localStorage.getItem(KEY)!).records[0].ids).toEqual([APT29, FIN7]);
        const svc = makeService(new BehaviorSubject<Domain | null>(ent()));
        expect(names(svc.presentGroups(ent()))).toEqual(['APT29', 'FIN7']);
        expect(svc.absentGroups(ent())).toEqual([]);
        expect(svc.domainNotice()).toBeNull();
        expect(svc.current.groupIds).toEqual([APT29, FIN7]);   // the counted profile resolves them too
        expect(svc.current.label).toBe('2 groups');
      });

      it('on ICS names the absent group by its name, not "G0016"', () => {
        const domain$ = new BehaviorSubject<Domain | null>(ent());
        const svc = makeService(domain$);
        svc.setSource({ kind: 'groups', ids: ['G0016', 'G0046'] });
        currentAttackDomain = 'ics';
        domain$.next(icsOnly());
        expect(names(svc.presentGroups(icsOnly()))).toEqual(['FIN7']);
        expect(svc.absentGroups(icsOnly())).toEqual([{ id: APT29, name: 'APT29' }]);   // normalised on the Enterprise load
        expect(svc.domainNotice()).toBe('1 of 2 groups present in ICS: FIN7; APT29 has no ICS use');
        currentAttackDomain = 'enterprise';
      });

      it('a group stored under both ids and absent from ICS is named once; the notice counts it once', () => {
        const domain$ = new BehaviorSubject<Domain | null>(ent());
        const svc = makeService(domain$);
        svc.setSource({ kind: 'groups', ids: [APT29, 'G0016', 'G0046'] });
        currentAttackDomain = 'ics';
        domain$.next(icsOnly());
        expect(svc.absentGroups(icsOnly())).toEqual([{ id: APT29, name: 'APT29' }]);
        expect(svc.domainNotice()).toBe('1 of 2 groups present in ICS: FIN7; APT29 has no ICS use');
        currentAttackDomain = 'enterprise';
      });

      it('after a reload straight onto ICS, the group index names it once', () => {
        makeService(new BehaviorSubject<Domain | null>(ent())).setSource({ kind: 'groups', ids: [APT29, 'G0016', 'G0046'] });
        currentAttackDomain = 'ics';
        const svc = makeService(new BehaviorSubject<Domain | null>(icsOnly()), [], INDEX);
        expect(svc.absentGroups(icsOnly())).toEqual([{ id: APT29, name: 'APT29' }]);
        expect(svc.domainNotice()).toBe('1 of 2 groups present in ICS: FIN7; APT29 has no ICS use');
        currentAttackDomain = 'enterprise';
      });

      it('a group stored under both ids counts once', () => {
        const svc = makeService(new BehaviorSubject<Domain | null>(ent()));
        svc.setSource({ kind: 'groups', ids: [APT29, 'G0016'] });
        expect(names(svc.presentGroups(ent()))).toEqual(['APT29']);
        expect(svc.absentGroups(ent())).toEqual([]);
        expect(svc.current.groupIds).toEqual([APT29]);
      });

      // RP-F decision 18: one shape in storage. A profile stored with ATT&CK ids is
      // normalised to STIX ids on load (and on workspace import), with its name hint.
      describe('normalised to STIX ids on load (RP-F decision 18)', () => {
        const ZERO = 'intrusion-set--00000000-0000-0000-0000-000000000000';
        const storeRaw = (ids: string[], groupNames?: Record<string, string>) => localStorage.setItem(KEY, JSON.stringify({
          schema: 2, tombstones: [], records: [{
            kind: 'groups', ids, ...(groupNames ? { groupNames } : {}),
            domain: 'enterprise', attackVersion: '19.2', source: 'manual', createdAt: '2026-10-21T00:00:00.000Z', updatedAt: '2026-10-21T00:00:00.000Z',
          }],
        }));
        const storedIds = () => JSON.parse(localStorage.getItem(KEY)!).records[0].ids;

        it("a profile stored as ['G0016','G0046'] loads on Enterprise as STIX ids, and storage holds STIX ids after load", () => {
          storeRaw(['G0016', 'G0046']);
          const svc = makeService(new BehaviorSubject<Domain | null>(ent()));
          expect(svc.current.source).toEqual({ kind: 'groups', ids: [APT29, FIN7] });
          expect(storedIds()).toEqual([APT29, FIN7]);
          expect(JSON.parse(localStorage.getItem(KEY)!).records[0].groupNames).toEqual({ [APT29]: 'APT29', [FIN7]: 'FIN7' });
          expect(svc.domainNotice()).toBeNull();
          expect(svc.current.groupIds).toEqual([APT29, FIN7]);
        });

        it('lower-case and mixed shapes collapse to one STIX id per group', () => {
          storeRaw(['g0016', APT29, 'G0046']);
          makeService(new BehaviorSubject<Domain | null>(ent()));
          expect(storedIds()).toEqual([APT29, FIN7]);
        });

        it('on a cold ICS boot only the ids ICS names are normalised; Enterprise finishes the job when it loads', () => {
          storeRaw(['G0016', 'G0046']);
          currentAttackDomain = 'ics';
          const domain$ = new BehaviorSubject<Domain | null>(icsOnly());
          const svc = makeService(domain$);
          expect(storedIds()).toEqual(['G0016', FIN7]);
          // G0016 resolves to no group this session yet: announced as such, never "has no ICS use".
          expect(svc.domainNotice()).toBe('1 of 2 groups present in ICS: FIN7; G0016: unknown or withdrawn group id');
          expect(svc.absentGroups(icsOnly())).toEqual([]);
          expect(svc.unresolvedGroups(icsOnly())).toEqual([{ id: 'G0016', name: 'G0016', unresolved: true }]);
          currentAttackDomain = 'enterprise';
          domain$.next(ent());
          expect(storedIds()).toEqual([APT29, FIN7]);
          currentAttackDomain = 'ics';
          domain$.next(icsOnly());
          expect(svc.domainNotice()).toBe('1 of 2 groups present in ICS: FIN7; APT29 has no ICS use');
          currentAttackDomain = 'enterprise';
        });

        const UNRESOLVED = ['Fancy Bear', 'G0074', 'G0042', 'G9999', ZERO];
        it('aliases, revoked G0074 and G0042, unknown G9999 and an all-zero STIX id are unknown or withdrawn on Enterprise', () => {
          storeRaw([APT29, ...UNRESOLVED]);
          const svc = makeService(new BehaviorSubject<Domain | null>(ent()));
          expect(storedIds()).toEqual([APT29, ...UNRESOLVED]);    // kept, never dropped
          expect(svc.absentGroups(ent())).toEqual([]);
          expect(svc.unresolvedGroups(ent()).map((r) => r.id)).toEqual(UNRESOLVED);
          const notice = svc.domainNotice()!;
          expect(notice).toBe('1 of 6 groups present in Enterprise: APT29; '
            + UNRESOLVED.map((id) => `${id}: unknown or withdrawn group id`).join('; '));
          expect(notice).not.toContain('has no');
        });

        it('the same ids on ICS: the indexed group is absent by name, the rest unknown or withdrawn', () => {
          storeRaw([APT29, ...UNRESOLVED], { [APT29]: 'APT29' });
          currentAttackDomain = 'ics';
          const svc = makeService(new BehaviorSubject<Domain | null>(icsOnly()), [], INDEX);
          expect(svc.absentGroups(icsOnly())).toEqual([{ id: APT29, name: 'APT29' }]);
          expect(svc.domainNotice()).toBe('0 of 6 groups present in ICS; APT29 has no ICS use; '
            + UNRESOLVED.map((id) => `${id}: unknown or withdrawn group id`).join('; '));
          currentAttackDomain = 'enterprise';
        });

        it('a name hint never names a group that did not resolve: an alias hint is ignored, a hint renaming a real group is refused', () => {
          storeRaw(['Fancy Bear', ZERO], { 'Fancy Bear': 'APT28', [ZERO]: 'APT29' });
          const svc = makeService(new BehaviorSubject<Domain | null>(ent()));
          const notice = svc.domainNotice()!;
          expect(notice).toBe('0 of 2 groups present in Enterprise; Fancy Bear: unknown or withdrawn group id; '
            + `${ZERO}: unknown or withdrawn group id`);
          expect(notice).not.toContain('APT28');
          expect(notice).not.toContain('APT29 has no');
        });

        it('a workspace-bundle value is normalised to STIX ids with its name hint; one that does not parse is left as it is', () => {
          const svc = makeService(new BehaviorSubject<Domain | null>(ent()));
          const value = JSON.stringify({ schema: 2, tombstones: [], records: [{
            kind: 'groups', ids: ['G0016', 'g0046', 'G9999'], source: 'manual', createdAt: 'x', updatedAt: 'x', domain: 'enterprise', attackVersion: '19.2',
          }] });
          const out = JSON.parse(svc.normaliseImportedValue(value));
          expect(out.records[0].ids).toEqual([APT29, FIN7, 'G9999']);
          expect(out.records[0].groupNames).toEqual({ [APT29]: 'APT29', [FIN7]: 'FIN7' });
          expect(out.records[0].source).toBe('manual');
          expect(svc.normaliseImportedValue('not json')).toBe('not json');
          const topN = JSON.stringify({ schema: 2, tombstones: [], records: [{ kind: 'top-groups', n: 5 }] });
          expect(JSON.parse(svc.normaliseImportedValue(topN))).toEqual(JSON.parse(topN));
        });
      });
    });

    it('presentGroups/absentGroups are empty while no domain is loaded', () => {
      const svc = makeService();
      svc.setSource({ kind: 'groups', ids: [APT29] });
      expect(svc.presentGroups(null)).toEqual([]);
      expect(svc.absentGroups(null)).toEqual([]);
      expect(svc.domainNotice()).toBeNull();
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
