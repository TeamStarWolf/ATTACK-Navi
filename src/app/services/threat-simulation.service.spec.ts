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
import { PostureBucket } from '../models/posture/posture.types';

// P2-12a reshaped the service: it is PROFILE-scoped, not per-actor. simulate(domain)
// runs over the profile's parent techniques (THREAT_WEIGHT_PROVIDER.parents()), and a
// technique is "covered" when its PostureService bucket is covered, proven OR stale
// (P2-07's Yes rule — stale is aged Proven). partial and known are gaps, as is none;
// reference-only content never counts as covered.

function tech(id: string, attackId: string, tactic: string): Technique {
  return {
    id, attackId, name: attackId, description: '', url: '', tacticShortnames: [tactic],
    isSubtechnique: false, parentId: null, subtechniques: [], mitigationCount: 0, platforms: [],
    dataSources: [], detectionText: '', defenseBypassed: [], permissionsRequired: [], effectivePermissions: [],
    systemRequirements: [], impactType: [], remoteSupport: false, capecIds: [],
  };
}

// Five parent techniques in the profile. buckets: t1 covered, t2 proven, t3 stale,
// t4 partial, t5 none → covered = 3 (covered+proven+stale), total = 5, coverage 60%,
// gaps = 2 (t4 partial and t5 none are NOT covered).
const TECHS = [
  tech('t1', 'T1001', 'execution'),
  tech('t2', 'T1002', 'execution'),
  tech('t3', 'T1003', 'persistence'),
  tech('t4', 'T1004', 'persistence'),
  tech('t5', 'T1005', 'discovery'),
];
const BUCKETS = new Map<string, PostureBucket>([
  ['t1', 'covered'], ['t2', 'proven'], ['t3', 'stale'], ['t4', 'partial'], ['t5', 'none'],
]);
const DOMAIN = { techniques: TECHS } as unknown as Domain;

describe('ThreatSimulationService (profile-scoped)', () => {
  let service: ThreatSimulationService;

  function configure(parentIds: string[]): void {
    TestBed.configureTestingModule({
      providers: [
        ThreatSimulationService,
        { provide: PostureService, useValue: { stateFor: (t: Technique) => ({ bucket: BUCKETS.get(t.id) ?? 'none' }) } },
        { provide: THREAT_WEIGHT_PROVIDER, useValue: { weight: () => 0, revision: signal(0), parents: signal(new Set(parentIds)) } },
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => [], getKevCvesForTechnique: () => [] } },
        { provide: ExploitdbService, useValue: { hasExploits: () => false } },
        { provide: EpssService, useValue: { getScore: () => null } },
      ],
    });
    service = TestBed.inject(ThreatSimulationService);
  }

  it('total is the profile parent count; covered = covered + proven + stale; partial and none are gaps', () => {
    configure(['t1', 't2', 't3', 't4', 't5']);
    const r = service.simulate(DOMAIN);
    expect(r.techniquesTotal).toBe(5);        // the profile's five parent techniques
    expect(r.techniquesCovered).toBe(3);      // t1 covered + t2 proven + t3 stale
    expect(r.coveragePercent).toBe(60);       // 3 / 5
    expect(r.gaps.length).toBe(2);            // t4 partial and t5 none are not covered
    expect(r.gaps.map(g => g.technique.id).sort()).toEqual(['t4', 't5']);
  });

  it('scopes to the profile: a smaller parent set gives a smaller total', () => {
    configure(['t1', 't5']);                   // only two parents in the profile
    const r = service.simulate(DOMAIN);
    expect(r.techniquesTotal).toBe(2);
    expect(r.techniquesCovered).toBe(1);       // t1 covered; t5 none is a gap
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
    configure(['t1', 't2', 't3', 't4', 't5']);
    const r = service.simulate(DOMAIN);
    const execution = r.tacticBreakdown.find(t => t.tactic === 'execution')!;
    expect(execution.total).toBe(2);           // t1, t2
    expect(execution.covered).toBe(2);         // both covered/proven
    const persistence = r.tacticBreakdown.find(t => t.tactic === 'persistence')!;
    expect(persistence.total).toBe(2);         // t3 stale (covered) + t4 partial (not)
    expect(persistence.covered).toBe(1);
  });
});
