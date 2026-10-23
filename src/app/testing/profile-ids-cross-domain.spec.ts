// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F decision 25: stored threat-profile group ids resolve against the bundled
// all-domain group index (src/assets/data/group-index.json), so a real group the
// loaded domain lacks reads "<name> has no <domain> use" on a FRESH BOOT into
// Enterprise, ICS or Mobile and after a reload, and only an id the index does not
// hold as a current group reads "<id>: unknown or withdrawn group id". Round 4 found
// a fresh boot into ICS or Mobile calling APT29 "G0016: unknown or withdrawn group
// id", a hint-less store reading differently across F5, a hint on a fabricated id
// naming APT29 as absent, an empty id rendering ": unknown or withdrawn group id"
// and " G0016 " left untrimmed. Fourteen stored shapes x three domains, each on a
// fresh boot and again after a reload.
import { BehaviorSubject, of } from 'rxjs';
import { BUNDLED_GROUP_INDEX, ThreatProfileService } from '../services/threat-profile.service';
import type { AttackDomain, DataService } from '../services/data.service';
import type { LibraryLayerService } from '../services/library-layer.service';
import type { Domain } from '../models/domain';
import { ATTACK_DOMAIN_SHORT_LABEL, UNRESOLVED_GROUP_WORDS, currentIndexedGroups } from '../models/threat-profile';

const KEY = 'navi.v2.threat-profile';
const APT29 = 'intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542';   // G0016, Enterprise only
const FIN7 = 'intrusion-set--3753cc21-2dae-4dfb-8481-d004e74502cc';    // G0046, Enterprise and ICS
const ALLANITE = 'intrusion-set--190242d7-73fc-4738-af68-20162f7a5aae'; // G1000, ICS only
const BOUNCING_GOLF = 'intrusion-set--049cef3b-22d5-4be6-b50c-9839c7a34fdd'; // G0097, Mobile only
const FABRICATED = 'intrusion-set--11111111-1111-1111-1111-111111111111';
const ZERO = 'intrusion-set--00000000-0000-0000-0000-000000000000';

const DOMAIN_NAMES: Readonly<Record<'enterprise' | 'ics' | 'mobile', string>> = {
  enterprise: 'Enterprise ATT&CK', ics: 'ICS ATT&CK', mobile: 'Mobile ATT&CK',
};

/** A domain carrying exactly the index's current groups of `d`, each using one technique (as its bundle does). */
function domainFor(d: 'enterprise' | 'ics' | 'mobile'): Domain {
  const t = { id: 't1', attackId: 'T1', name: 'T1', isSubtechnique: false, parentId: null } as unknown as Domain['techniques'][number];
  const current = new Set(currentIndexedGroups(BUNDLED_GROUP_INDEX).map((g) => g.id));
  const groups = BUNDLED_GROUP_INDEX.filter((e) => current.has(e.stixId) && e.domains.includes(d))
    .map((e) => ({ id: e.stixId, attackId: e.attackId, name: e.name, aliases: [...e.aliases] }) as unknown as Domain['groups'][number]);
  return {
    name: DOMAIN_NAMES[d], techniques: [t], groups,
    groupsByTechnique: new Map([['t1', groups]]), techniquesByGroup: new Map(groups.map((g) => [g.id, [t]])),
    campaigns: [], campaignsByGroup: new Map(), techniquesByCampaign: new Map(), attackVersion: '19.2',
  } as unknown as Domain;
}

function boot(d: AttackDomain, domain: Domain | null): { svc: ThreatProfileService; domain$: BehaviorSubject<Domain | null> } {
  const domain$ = new BehaviorSubject<Domain | null>(domain);
  const data = { domain$: domain$.asObservable(), getCurrentDomain: () => domain$.value, getCurrentAttackDomain: () => d };
  const library = { layerTechniqueIds: () => of([]), manifest: [] as unknown[] };
  return { svc: new ThreatProfileService(data as unknown as DataService, library as unknown as LibraryLayerService), domain$ };
}

function store(ids: string[], groupNames?: Record<string, string>): void {
  localStorage.setItem(KEY, JSON.stringify({
    schema: 2, tombstones: [], records: [{
      kind: 'groups', ids, ...(groupNames ? { groupNames } : {}),
      domain: 'enterprise', attackVersion: '19.2', source: 'manual', createdAt: '2026-10-21T00:00:00.000Z', updatedAt: '2026-10-21T00:00:00.000Z',
    }],
  }));
}

/**
 * The notice the profile must show: present names, absent names, unresolved ids
 * (profileDomainNotice's sentence). Unresolved ids are counted as ids, never as groups
 * (RP-F decision 30c): "1 of 2 ids resolved; 1 of 1 group present in ...".
 */
function expectedNotice(d: 'enterprise' | 'ics' | 'mobile', present: string[], absent: string[], unresolved: string[]): string | null {
  if (absent.length === 0 && unresolved.length === 0) return null;
  const where = ATTACK_DOMAIN_SHORT_LABEL[d];
  const groups = present.length + absent.length;
  const ids = groups + unresolved.length;
  const parts: string[] = [];
  if (unresolved.length) parts.push(`${groups} of ${ids} ${ids === 1 ? 'id' : 'ids'} resolved`);
  if (groups) parts.push(`${present.length} of ${groups} ${groups === 1 ? 'group' : 'groups'} present in ${where}${present.length ? ': ' + present.join(', ') : ''}`);
  if (absent.length) parts.push(`${absent.join(', ')} ${absent.length === 1 ? 'has' : 'have'} no ${where} use`);
  for (const id of unresolved) parts.push(`${id}: ${UNRESOLVED_GROUP_WORDS}`);
  return parts.join('; ');
}

interface Shape {
  readonly name: string;
  readonly ids: string[];
  readonly hint?: Record<string, string>;
  /** The ids storage holds after the first boot (trimmed, empties dropped, ATT&CK ids of real groups as STIX ids). */
  readonly stored: string[];
  /** The groups the ids name, by display name, or the unresolved id as stored. */
  readonly real: string[];
  readonly unresolved: string[];
}

/** Which domains carry each real group (from the bundled index). */
const CARRIED_BY: Readonly<Record<string, readonly string[]>> = {
  APT29: ['enterprise'], FIN7: ['enterprise', 'ics'], ALLANITE: ['ics'], 'Bouncing Golf': ['mobile'],
};

const SHAPES: readonly Shape[] = [
  { name: 'ATT&CK ids', ids: ['G0016', 'G0046'], stored: [APT29, FIN7], real: ['APT29', 'FIN7'], unresolved: [] },
  { name: 'STIX ids with a name hint', ids: [APT29, FIN7], hint: { [APT29]: 'APT29', [FIN7]: 'FIN7' }, stored: [APT29, FIN7], real: ['APT29', 'FIN7'], unresolved: [] },
  { name: 'hint-less STIX ids', ids: [APT29, FIN7], stored: [APT29, FIN7], real: ['APT29', 'FIN7'], unresolved: [] },
  { name: 'lower-case ATT&CK ids', ids: ['g0016', 'g0046'], stored: [APT29, FIN7], real: ['APT29', 'FIN7'], unresolved: [] },
  { name: 'padded ids', ids: [' G0016 ', 'G0046 '], stored: [APT29, FIN7], real: ['APT29', 'FIN7'], unresolved: [] },
  { name: 'empty ids', ids: ['', 'G0046', '   '], stored: [FIN7], real: ['FIN7'], unresolved: [] },
  { name: 'an alias', ids: ['Fancy Bear', 'G0046'], stored: ['Fancy Bear', FIN7], real: ['FIN7'], unresolved: ['Fancy Bear'] },
  { name: 'revoked G0057', ids: ['G0057', 'G0046'], stored: ['G0057', FIN7], real: ['FIN7'], unresolved: ['G0057'] },
  { name: 'deprecated G0014', ids: ['G0014', 'G0046'], stored: ['G0014', FIN7], real: ['FIN7'], unresolved: ['G0014'] },
  { name: 'unknown G9999', ids: ['G9999', 'G0016'], stored: ['G9999', APT29], real: ['APT29'], unresolved: ['G9999'] },
  { name: 'malformed and all-zero STIX ids', ids: ['intrusion-set--not-a-uuid', ZERO], stored: ['intrusion-set--not-a-uuid', ZERO], real: [], unresolved: ['intrusion-set--not-a-uuid', ZERO] },
  { name: 'a hint on a fabricated STIX id', ids: [FABRICATED, 'G0046'], hint: { [FABRICATED]: 'APT29' }, stored: [FABRICATED, FIN7], real: ['FIN7'], unresolved: [FABRICATED] },
  { name: 'ICS-only G1000', ids: ['G1000', 'G0046'], stored: [ALLANITE, FIN7], real: ['ALLANITE', 'FIN7'], unresolved: [] },
  { name: 'Mobile-only G0097', ids: ['G0097', 'G0016'], stored: [BOUNCING_GOLF, APT29], real: ['Bouncing Golf', 'APT29'], unresolved: [] },
];

describe('stored profile ids resolve against the all-domain group index (RP-F decision 25)', () => {
  beforeEach(() => localStorage.removeItem(KEY));
  afterEach(() => localStorage.removeItem(KEY));

  it('fourteen shapes', () => expect(SHAPES.length).toBe(14));

  for (const d of ['enterprise', 'ics', 'mobile'] as const) {
    for (const shape of SHAPES) {
      it(`${shape.name} on a fresh boot into ${d}, and after a reload`, () => {
        const domain = domainFor(d);
        // The order a domain lists its groups in: present names follow it.
        const order = domain.groups.map((g) => g.name);
        const present = shape.real.filter((n) => CARRIED_BY[n].includes(d)).sort((a, b) => order.indexOf(a) - order.indexOf(b));
        const absent = shape.real.filter((n) => !CARRIED_BY[n].includes(d));
        const want = expectedNotice(d, present, absent, shape.unresolved);
        store(shape.ids, shape.hint);

        // Fresh boot: the domain loads after the service starts, as in the app.
        const first = boot(d, null);
        expect(first.svc.domainNotice()).toBeNull();
        first.domain$.next(domain);
        expect(first.svc.domainNotice()).withContext('fresh boot').toBe(want);
        expect(first.svc.presentGroups(domain).map((g) => g.name)).toEqual(present);
        expect(first.svc.absentGroups(domain).map((g) => g.name)).toEqual(absent);
        expect(first.svc.unresolvedGroups(domain).map((g) => g.id)).toEqual(shape.unresolved);
        const record = JSON.parse(localStorage.getItem(KEY)!).records[0];
        expect(record.ids).withContext('stored ids').toEqual(shape.stored);
        // A name hint for every resolved id, and only for those (a hint is never a resolution).
        const resolved = shape.stored.filter((id) => !shape.unresolved.includes(id));
        expect(Object.keys(record.groupNames ?? {}).sort()).toEqual([...resolved].sort());
        const notice = want ?? '';
        expect(notice).not.toMatch(/(^|; ): /);
        for (const id of shape.unresolved) expect(notice).not.toContain(`${id} has no`);

        // Reload straight into the same domain: the same words.
        const second = boot(d, domain);
        expect(second.svc.domainNotice()).withContext('after a reload').toBe(want);
        expect(JSON.parse(localStorage.getItem(KEY)!).records[0].ids).toEqual(shape.stored);
      });
    }
  }

  it('an in-session switch and the reload after it read the same (hint-less STIX ids, Enterprise to ICS)', () => {
    store([APT29, FIN7]);
    const run = boot('enterprise', domainFor('enterprise'));
    expect(run.svc.domainNotice()).toBeNull();
    run.domain$.next(null);
    run.domain$.next(domainFor('ics'));
    const inSession = run.svc.domainNotice();
    expect(inSession).toBe('1 of 2 groups present in ICS: FIN7; APT29 has no ICS use');
    expect(boot('ics', domainFor('ics')).svc.domainNotice()).toBe(inSession);
  });
});
