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
import { rankGroupsByPrevalence, resolveProfile } from './threat-profile';

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

/** Three parents (t1,t2,t3) and one sub (t1a of t1). GA and GB tie on prevalence; GD uses only the sub. */
function fixtureDomain(): Domain {
  const techniques = [tech('t1', 'T1'), tech('t2', 'T2'), tech('t3', 'T3'), tech('t1a', 'T1.001', 't1')];
  const groups = [group('ga', 'G0001'), group('gb', 'G0002'), group('gc', 'G0003'), group('gd', 'G0004')];
  const byId = new Map(techniques.map((t) => [t.id, t]));
  const groupsByTechnique = new Map<string, ThreatGroup[]>([
    ['t1', [groups[0], groups[1], groups[2]]],   // 3
    ['t2', [groups[0], groups[1]]],              // 2
    ['t3', [groups[0]]],                         // 1
    ['t1a', [groups[1]]],                        // 1
  ]);
  const techniquesByGroup = new Map<string, Technique[]>([
    ['ga', [byId.get('t1')!, byId.get('t2')!, byId.get('t3')!]],   // 3+2+1 = 6
    ['gb', [byId.get('t1')!, byId.get('t2')!, byId.get('t1a')!]],  // 3+2+1 = 6 (tie with ga)
    ['gc', [byId.get('t1')!]],                                     // 3
    ['gd', [byId.get('t1a')!]],                                    // sub only
  ]);
  const campaignsByGroup = new Map<string, Campaign[]>([
    ['ga', [{ id: 'c1', attackId: 'C0001', name: 'camp', description: '', url: '', aliases: [], firstSeen: '', lastSeen: '', attributedGroupIds: [] }]],
  ]);
  return {
    name: 'Enterprise ATT&CK', attackVersion: '19.2', attackModified: '', tactics: [], techniques,
    mitigations: [], tacticColumns: [], mitigationsByTechnique: new Map(), techniquesByMitigation: new Map(),
    maxMitigationCount: 0, groups, groupsByTechnique, techniquesByGroup, software: [], softwareByTechnique: new Map(),
    techniquesBySoftware: new Map(), proceduresByTechnique: new Map(), dataSources: [], dataComponents: [],
    techniquesByDataComponent: new Map(), dataComponentsByTechnique: new Map(), campaigns: [], campaignsByTechnique: new Map(),
    techniquesByCampaign: new Map(), softwareByGroup: new Map(), groupsBySoftware: new Map(), softwareByCampaign: new Map(),
    campaignsByGroup, detectionNotesByTechnique: new Map(), supersededBy: new Map(), retiredNames: new Map(),
  };
}

describe('threat-profile model', () => {
  it('ranks groups by prevalence, breaking ties by campaign count then attackId', () => {
    const ranked = rankGroupsByPrevalence(fixtureDomain());
    // ga and gb tie at 6; ga has a campaign so it wins the tie; gc (3) then gd (1).
    expect(ranked.map((g) => g.id)).toEqual(['ga', 'gb', 'gc', 'gd']);
  });

  it('rolls sub-only usage up to the parent in parentTechniqueIds', () => {
    const profile = resolveProfile({ kind: 'groups', ids: ['gd'] }, fixtureDomain());
    expect([...profile.techniqueIds]).toEqual(['t1a']);        // the raw STIX technique used
    expect([...profile.parentTechniqueIds]).toEqual(['t1']);   // rolled up: THE denominator
    expect(profile.weight('t1a')).toBe(1);                     // weight follows the rollup
    expect(profile.weight('t1')).toBe(1);
  });

  it('top-groups counts distinct profile actors per parent (sub usage rolls up)', () => {
    const profile = resolveProfile({ kind: 'top-groups', n: 2 }, fixtureDomain());
    expect(profile.groupIds).toEqual(['ga', 'gb']);
    expect([...profile.parentTechniqueIds].sort()).toEqual(['t1', 't2', 't3']);
    expect(profile.weight('t1')).toBe(2);   // ga uses t1, gb uses t1 → 2
    expect(profile.weight('t1a')).toBe(2);  // rolls to t1 → same 2
    expect(profile.weight('t3')).toBe(1);   // ga only
    expect(profile.usedBy('t2')).toEqual(['grp-G0001', 'grp-G0002']);
    expect(profile.label).toBe('Top 2 groups by prevalence');
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

  it("'all' equals every parent technique", () => {
    const profile = resolveProfile({ kind: 'all' }, fixtureDomain());
    expect([...profile.parentTechniqueIds].sort()).toEqual(['t1', 't2', 't3']);
    expect(profile.techniqueIds.size).toBe(4);   // parents + the sub
    expect(profile.label).toBe('All techniques');
  });

  // The Top-20 and all-groups parent counts over the real bundled Enterprise 19.2.
  // Loaded through parseBundle, the same code path the app runs (bundled-data.spec pattern).
  describe('bundled Enterprise 19.2 prevalence counts', () => {
    let domain: Domain;
    beforeAll(async () => {
      const bundle = await (await fetch('assets/data/enterprise-attack.json')).json();
      TestBed.configureTestingModule({ providers: [{ provide: HttpClient, useValue: { get: () => of({}) } }] });
      domain = (TestBed.inject(DataService) as unknown as { parseBundle(b: unknown, n: string): Domain })
        .parseBundle(bundle, 'Enterprise ATT&CK');
    }, 120_000);

    it('Top 20 groups by prevalence cover 167 parent techniques', () => {
      const profile = resolveProfile({ kind: 'top-groups', n: 20 }, domain);
      expect(profile.parentTechniqueIds.size).toBe(167);
    });

    it('all 176 groups cover 203 parent techniques', () => {
      const profile = resolveProfile({ kind: 'groups', ids: domain.groups.map((g) => g.id) }, domain);
      expect(profile.parentTechniqueIds.size).toBe(203);
    });
  });
});
