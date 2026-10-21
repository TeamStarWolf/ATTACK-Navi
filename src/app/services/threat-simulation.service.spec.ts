// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { ThreatSimulationService } from './threat-simulation.service';
import { PostureService } from './posture.service';
import { AttackCveService } from './attack-cve.service';
import { ExploitdbService } from './exploitdb.service';
import { EpssService } from './epss.service';
import { THREAT_WEIGHT_PROVIDER } from '../models/posture/threat-weight';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { PostureBucket, PostureSubState } from '../models/posture/posture.types';

// P2-12a reshaped the service: it is PROFILE-scoped, not per-actor. simulate(domain)
// runs over the profile's parent techniques (THREAT_WEIGHT_PROVIDER.parents()), and a
// technique is "covered" when its PostureService bucket is covered, proven OR stale
// (P2-07's Yes rule — stale is aged Proven). §10.4 item 13: a GAP is bucket none or
// known, or the contradicted sub-state; partial is NOT a gap (its own number) and
// reference-only (known) never counts as covered.

function tech(id: string, attackId: string, tactic: string): Technique {
  return {
    id, attackId, name: attackId, description: '', url: '', tacticShortnames: [tactic],
    isSubtechnique: false, parentId: null, subtechniques: [], mitigationCount: 0, platforms: [],
    dataSources: [], detectionText: '', defenseBypassed: [], permissionsRequired: [], effectivePermissions: [],
    systemRequirements: [], impactType: [], remoteSupport: false, capecIds: [],
  };
}

// Seven parent techniques in the profile:
//   t1 covered, t2 proven, t3 stale    -> covered (covered + proven + stale)
//   t4 partial                         -> NOT covered and NOT a gap (its own number, item 13)
//   t5 none                            -> a gap
//   t6 known                           -> reference-only: a gap, never covered (item 4)
//   t7 covered + contradicted          -> covered in the %, but a gap via the contradicted sub-state
// So techniquesCovered = 4 (t1,t2,t3,t7), total = 7, coverage 57%, gaps = 3 (t5,t6,t7).
const TECHS = [
  tech('t1', 'T1001', 'execution'),
  tech('t2', 'T1002', 'execution'),
  tech('t3', 'T1003', 'persistence'),
  tech('t4', 'T1004', 'persistence'),
  tech('t5', 'T1005', 'discovery'),
  tech('t6', 'T1006', 'discovery'),
  tech('t7', 'T1007', 'execution'),
];
const BUCKETS = new Map<string, PostureBucket>([
  ['t1', 'covered'], ['t2', 'proven'], ['t3', 'stale'], ['t4', 'partial'],
  ['t5', 'none'], ['t6', 'known'], ['t7', 'covered'],
]);
const SUBSTATES = new Map<string, PostureSubState[]>([['t7', ['contradicted']]]);
// Reference mappings (knownSignals): "mapped" = count with >0, the ctem "Known: mapped" numerator.
// 5 parents are reference-mapped (t1,t2,t3,t6,t7); t4/t5 are not. mapped differs from bucket-'known' (1).
const KNOWN_SIGNALS = new Map<string, number>([['t1', 2], ['t2', 1], ['t3', 1], ['t6', 3], ['t7', 1]]);
const DOMAIN = { techniques: TECHS } as unknown as Domain;

describe('ThreatSimulationService (profile-scoped)', () => {
  let service: ThreatSimulationService;

  function configure(parentIds: string[]): void {
    TestBed.configureTestingModule({
      providers: [
        ThreatSimulationService,
        { provide: PostureService, useValue: { stateFor: (t: Technique) => ({
            bucket: BUCKETS.get(t.id) ?? 'none',
            subStates: SUBSTATES.get(t.id) ?? [],
            excluded: false,
            knownSignals: KNOWN_SIGNALS.get(t.id) ?? 0,
        }) } },
        { provide: THREAT_WEIGHT_PROVIDER, useValue: { weight: () => 0, revision: signal(0), parents: signal(new Set(parentIds)) } },
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => [], getKevCvesForTechnique: () => [] } },
        { provide: ExploitdbService, useValue: { hasExploits: () => false } },
        { provide: EpssService, useValue: { getScore: () => null } },
      ],
    });
    service = TestBed.inject(ThreatSimulationService);
  }

  it('total = profile parent count; covered = covered+proven+stale; per-bucket counts mirror the card', () => {
    configure(['t1', 't2', 't3', 't4', 't5', 't6', 't7']);
    const r = service.simulate(DOMAIN);
    expect(r.techniquesTotal).toBe(7);
    expect(r.techniquesCovered).toBe(4);      // t1 covered + t2 proven + t3 stale + t7 covered
    expect(r.coveragePercent).toBe(57);       // round(4/7*100)
    expect(r.coveredCount).toBe(2);           // bucket covered: t1, t7
    expect(r.provenCount).toBe(1);            // t2
    expect(r.staleCount).toBe(1);             // t3
    expect(r.partialCount).toBe(1);           // t4
    expect(r.knownCount).toBe(1);             // t6 (bucket 'known')
    expect(r.mappedCount).toBe(5);            // t1,t2,t3,t6,t7 have knownSignals>0 — mapped-of-total, NOT bucket-known
    expect(r.noneCount).toBe(1);              // t5
    expect(r.contradictedCount).toBe(1);      // t7
  });

  it('a gap is bucket none or known or contradicted; partial is NOT a gap (item 13)', () => {
    configure(['t1', 't2', 't3', 't4', 't5', 't6', 't7']);
    const r = service.simulate(DOMAIN);
    expect(r.gaps.map(g => g.technique.id).sort()).toEqual(['t5', 't6', 't7']);
    expect(r.gaps.some(g => g.technique.id === 't4')).toBeFalse();   // partial is not a gap
  });

  it('reference-only (known) is a gap, never counted as covered (item 4)', () => {
    configure(['t1', 't6']);                    // one covered, one known
    const r = service.simulate(DOMAIN);
    expect(r.techniquesCovered).toBe(1);        // only t1; the known t6 never counts
    expect(r.knownCount).toBe(1);
    expect(r.gaps.map(g => g.technique.id)).toEqual(['t6']);   // known is the only gap
  });

  it('contradicted is a gap even when the bucket is covered', () => {
    configure(['t7']);                          // covered bucket with a contradicted sub-state
    const r = service.simulate(DOMAIN);
    expect(r.techniquesCovered).toBe(1);        // still covered for the % (bucket covered)
    expect(r.gaps.map(g => g.technique.id)).toEqual(['t7']);   // but a gap via contradicted
  });

  it('scopes to the profile: a smaller parent set gives a smaller total', () => {
    configure(['t1', 't5']);                     // only two parents in the profile
    const r = service.simulate(DOMAIN);
    expect(r.techniquesTotal).toBe(2);
    expect(r.techniquesCovered).toBe(1);         // t1 covered; t5 none is a gap
    expect(r.coveragePercent).toBe(50);
  });

  it('an empty profile yields a zero result, not a crash', () => {
    configure([]);
    const r = service.simulate(DOMAIN);
    expect(r.techniquesTotal).toBe(0);
    expect(r.techniquesCovered).toBe(0);
    expect(r.coveragePercent).toBe(0);
    expect(r.gaps).toEqual([]);
  });

  it('builds a tactic breakdown over the profile parents', () => {
    configure(['t1', 't2', 't3', 't4', 't5', 't6', 't7']);
    const r = service.simulate(DOMAIN);
    const execution = r.tacticBreakdown.find(t => t.tactic === 'execution')!;
    expect(execution.total).toBe(3);           // t1, t2, t7
    expect(execution.covered).toBe(3);         // all three in a covered bucket
    const persistence = r.tacticBreakdown.find(t => t.tactic === 'persistence')!;
    expect(persistence.total).toBe(2);         // t3 stale (covered) + t4 partial (not)
    expect(persistence.covered).toBe(1);
    const discovery = r.tacticBreakdown.find(t => t.tactic === 'discovery')!;
    expect(discovery.total).toBe(2);           // t5 none + t6 known
    expect(discovery.covered).toBe(0);
  });
});
