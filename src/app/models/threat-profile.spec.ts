// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { Domain } from './domain';
import { Technique } from './technique';
import { ThreatGroup } from './group';
import { Campaign } from './campaign';
import { DataService } from '../services/data.service';
import { profileDomainNotice, rankGroupsByPrevalence, resolveProfile, splitStoredGroups } from './threat-profile';

function tech(id: string, attackId: string, parentId: string | null = null): Technique {
  return {
    id, attackId, name: attackId, description: '', url: '', tacticShortnames: [],
    isSubtechnique: parentId !== null, parentId, subtechniques: [], mitigationCount: 0, platforms: [],
    dataSources: [], detectionText: '', defenseBypassed: [], permissionsRequired: [], effectivePermissions: [],
    systemRequirements: [], impactType: [], remoteSupport: false, capecIds: [],
  };
}
function group(id: string, attackId: string): ThreatGroup {
  return { id, attackId, name: `grp-${attackId}`, description: '', url: '', aliases: [] };
}
function emptyDomain(over: Partial<Domain>): Domain {
  return {
    name: 'Enterprise ATT&CK', attackVersion: '19.2', attackModified: '', tactics: [], techniques: [],
    mitigations: [], tacticColumns: [], mitigationsByTechnique: new Map(), techniquesByMitigation: new Map(),
    maxMitigationCount: 0, groups: [], groupsByTechnique: new Map(), techniquesByGroup: new Map(), software: [],
    softwareByTechnique: new Map(), techniquesBySoftware: new Map(), proceduresByTechnique: new Map(), dataSources: [],
    dataComponents: [], techniquesByDataComponent: new Map(), dataComponentsByTechnique: new Map(), campaigns: [],
    campaignsByTechnique: new Map(), techniquesByCampaign: new Map(), softwareByGroup: new Map(), groupsBySoftware: new Map(),
    softwareByCampaign: new Map(), campaignsByGroup: new Map(), detectionNotesByTechnique: new Map(), supersededBy: new Map(),
    retiredNames: new Map(), ...over,
  };
}

/**
 * Consistent fixture: groupsByTechnique and techniquesByGroup are exact inverses.
 * Usage: t1 {ga,gb,gc}, t2 {ga,gb}, t3 {ga}, t1a(sub of t1) {gb,gd}.
 * Prevalence (Σ groupsByTechnique over the group's techniques): gb 7, ga 6, gc 3, gd 2.
 */
function fixtureDomain(): Domain {
  const t1 = tech('t1', 'T1'), t2 = tech('t2', 'T2'), t3 = tech('t3', 'T3'), t1a = tech('t1a', 'T1.001', 't1');
  const ga = group('ga', 'G0001'), gb = group('gb', 'G0002'), gc = group('gc', 'G0003'), gd = group('gd', 'G0004');
  return emptyDomain({
    techniques: [t1, t2, t3, t1a],
    groups: [ga, gb, gc, gd],
    groupsByTechnique: new Map([['t1', [ga, gb, gc]], ['t2', [ga, gb]], ['t3', [ga]], ['t1a', [gb, gd]]]),
    techniquesByGroup: new Map([['ga', [t1, t2, t3]], ['gb', [t1, t2, t1a]], ['gc', [t1]], ['gd', [t1a]]]),
    campaignsByGroup: new Map([['ga', [{ id: 'c1', attackId: 'C0001', name: 'camp', description: '', url: '', aliases: [], firstSeen: '', lastSeen: '', attributedGroupIds: [] }]]]),
  });
}

/** Two groups that tie on prevalence AND campaign count; only attackId breaks the tie. */
function tieDomain(groupOrder: ThreatGroup[]): Domain {
  const tz = tech('tz', 'T9');
  return emptyDomain({
    techniques: [tz],
    groups: groupOrder,
    groupsByTechnique: new Map([['tz', [...groupOrder]]]),
    techniquesByGroup: new Map(groupOrder.map((g) => [g.id, [tz]])),
  });
}

describe('threat-profile model', () => {
  it('ranks groups by prevalence (gb 7 > ga 6 > gc 3 > gd 2)', () => {
    expect(rankGroupsByPrevalence(fixtureDomain()).map((g) => g.id)).toEqual(['gb', 'ga', 'gc', 'gd']);
  });

  it('breaks a full prevalence+campaign tie by attackId, independent of input order', () => {
    const gx = group('gx', 'G0002'), gy = group('gy', 'G0001');
    expect(rankGroupsByPrevalence(tieDomain([gx, gy])).map((g) => g.id)).toEqual(['gy', 'gx']);
    expect(rankGroupsByPrevalence(tieDomain([gy, gx])).map((g) => g.id)).toEqual(['gy', 'gx']);
  });

  it('rolls sub-only usage up to the parent in parentTechniqueIds', () => {
    const profile = resolveProfile({ kind: 'groups', ids: ['gd'] }, fixtureDomain());
    expect([...profile.techniqueIds]).toEqual(['t1a']);        // the raw STIX technique used
    expect([...profile.parentTechniqueIds]).toEqual(['t1']);   // rolled up: THE denominator
    expect(profile.weight('t1a')).toBe(1);
    expect(profile.weight('t1')).toBe(1);
  });

  it('top-groups counts distinct profile actors per parent (sub usage rolls up)', () => {
    const profile = resolveProfile({ kind: 'top-groups', n: 2 }, fixtureDomain());
    expect(profile.groupIds).toEqual(['gb', 'ga']);             // prevalence order
    expect([...profile.parentTechniqueIds].sort()).toEqual(['t1', 't2', 't3']);
    expect(profile.weight('t1')).toBe(2);
    expect(profile.weight('t1a')).toBe(2);                      // rolls to t1
    expect(profile.weight('t3')).toBe(1);
    expect(profile.usedBy('t2')).toEqual(['grp-G0001', 'grp-G0002']);
    expect(profile.label).toBe('Top 2 groups by prevalence');
  });

  it('clamps top-groups n to [1, number of groups]', () => {
    const d = fixtureDomain();
    expect(resolveProfile({ kind: 'top-groups', n: 0 }, d).groupIds.length).toBe(1);
    expect(resolveProfile({ kind: 'top-groups', n: 999 }, d).groupIds.length).toBe(4);
    expect(resolveProfile({ kind: 'top-groups', n: 999 }, d).label).toBe('Top 4 groups by prevalence');
  });

  it('library layer resolves T#### attackIds to STIX ids; unknown ids drop', () => {
    const profile = resolveProfile(
      { kind: 'library-layer', file: 'x.json' }, fixtureDomain(),
      { meta: { file: 'x.json', name: 'Layer X', description: '' }, techniques: [{ techniqueID: 'T1' }, { techniqueID: 'T1.001' }, { techniqueID: 'T9999' }] },
    );
    expect([...profile.techniqueIds].sort()).toEqual(['t1', 't1a']);
    expect([...profile.parentTechniqueIds]).toEqual(['t1']);
    expect(profile.label).toBe('Layer X');
  });

  it("'all' equals every parent technique and lists every group", () => {
    const profile = resolveProfile({ kind: 'all' }, fixtureDomain());
    expect([...profile.parentTechniqueIds].sort()).toEqual(['t1', 't2', 't3']);
    expect(profile.techniqueIds.size).toBe(4);   // parents + the sub
    expect([...profile.groupIds].sort()).toEqual(['ga', 'gb', 'gc', 'gd']);
    expect(profile.label).toBe('All techniques');
  });

  it('campaigns groupIds are the attributed intrusion-sets', () => {
    const d = emptyDomain({
      campaigns: [{ id: 'camp1', attackId: 'C0001', name: 'C1', description: '', url: '', aliases: [], firstSeen: '', lastSeen: '', attributedGroupIds: ['ga', 'gb'] }],
      techniquesByCampaign: new Map([['camp1', []]]),
    });
    expect([...resolveProfile({ kind: 'campaigns', ids: ['camp1'] }, d).groupIds].sort()).toEqual(['ga', 'gb']);
  });

  // The Top-20 and all-groups parent counts over the real bundled Enterprise 19.2,
  // through parseBundle (the same code path the app runs; bundled-data.spec pattern).
  describe('cross-domain groups (RP-F decision 6)', () => {
    it('splitStoredGroups: present in the domain order, absent in the stored order without duplicates', () => {
      const d = emptyDomain({ groups: [group('g-b', 'G0002'), group('g-a', 'G0001')] });
      const split = splitStoredGroups(['g-x', 'g-a', 'g-b', 'g-x', 'g-y'], d);
      expect(split.present.map((g) => g.id)).toEqual(['g-b', 'g-a']);
      expect(split.absentIds).toEqual(['g-x', 'g-y']);
    });

    it('resolveProfile counts only the present groups (the same rule) and keeps the source as stored', () => {
      const d = emptyDomain({ groups: [group('g-a', 'G0001')] });
      const p = resolveProfile({ kind: 'groups', ids: ['g-a', 'g-gone'] }, d);
      expect(p.groupIds).toEqual(['g-a']);
      expect(p.source).toEqual({ kind: 'groups', ids: ['g-a', 'g-gone'] });
    });

    it('profileDomainNotice names the present and absent groups and the domain, or is null', () => {
      const fin7 = { id: 'g-fin7', name: 'FIN7' };
      const apt29 = { id: 'g-apt29', name: 'APT29' };
      const apt28 = { id: 'g-apt28', name: 'APT28' };
      expect(profileDomainNotice(null)).toBeNull();
      expect(profileDomainNotice({ domain: 'enterprise', present: [fin7, apt29], absent: [] })).toBeNull();
      expect(profileDomainNotice({ domain: 'ics', present: [fin7], absent: [apt29] }))
        .toBe('1 of 2 groups present in ICS: FIN7; APT29 has no ICS use');
      expect(profileDomainNotice({ domain: 'mobile', present: [fin7], absent: [apt29, apt28] }))
        .toBe('1 of 3 groups present in Mobile: FIN7; APT29, APT28 have no Mobile use');
      expect(profileDomainNotice({ domain: 'ics', present: [], absent: [apt29] }))
        .toBe('0 of 1 group present in ICS; APT29 has no ICS use');
    });
  });

  describe('bundled Enterprise 19.2 prevalence counts', () => {
    let domain: Domain;
    beforeAll(async () => {
      const bundle = await (await fetch('assets/data/enterprise-attack.json')).json();
      TestBed.configureTestingModule({ providers: [{ provide: HttpClient, useValue: { get: () => of({}) } }] });
      domain = (TestBed.inject(DataService) as unknown as { parseBundle(b: unknown, n: string): Domain })
        .parseBundle(bundle, 'Enterprise ATT&CK');
      TestBed.resetTestingModule();   // release the injected DataService so it does not leak into the next spec file (attack-id-currency.spec.ts:37)
    }, 120_000);

    it('Top 20 groups by prevalence cover 167 parent techniques', () => {
      expect(resolveProfile({ kind: 'top-groups', n: 20 }, domain).parentTechniqueIds.size).toBe(167);
    });

    it('all 176 groups cover 203 parent techniques', () => {
      expect(domain.groups.length).toBe(176);   // pins the denominator
      expect(resolveProfile({ kind: 'groups', ids: domain.groups.map((g) => g.id) }, domain).parentTechniqueIds.size).toBe(203);
    });
  });
});
