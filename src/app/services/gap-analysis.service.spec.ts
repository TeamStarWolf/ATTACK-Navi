// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { GapAnalysisService } from './gap-analysis.service';
import { DataService } from './data.service';
import { SigmaService } from './sigma.service';
import { ElasticService } from './elastic.service';
import { SplunkContentService } from './splunk-content.service';
import { M365DefenderService } from './m365-defender.service';
import { AtomicService } from './atomic.service';
import { CARService } from './car.service';
import { AttackCveService } from './attack-cve.service';
import { CveService } from './cve.service';
import { EpssService } from './epss.service';
import { ExploitdbService } from './exploitdb.service';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { ThreatGroup } from '../models/group';
import { resolveProfile } from '../models/threat-profile';

describe('GapAnalysisService', () => {
  let service: GapAnalysisService;

  beforeEach(() => {
    const stub = {
      getRulesForTechnique: () => [],
      getCachedRules: () => [],
      getRuleCount: () => 0,
      getQueriesForTechnique: () => [],
      getContentForTechnique: () => [],
      getTests: () => [],
      getAnalytics: () => [],
      getCvesForTechnique: () => [],
      getKevCvesForTechnique: () => [],
      getExploitsForTechnique: () => [],
      getCachedCves: () => [],
      fetchScores: () => ({ subscribe: () => {} }),
    };
    TestBed.configureTestingModule({
      providers: [
        GapAnalysisService,
        { provide: DataService, useValue: stub },
        { provide: SigmaService, useValue: stub },
        { provide: ElasticService, useValue: stub },
        { provide: SplunkContentService, useValue: stub },
        { provide: M365DefenderService, useValue: stub },
        { provide: AtomicService, useValue: stub },
        { provide: CARService, useValue: stub },
        { provide: AttackCveService, useValue: stub },
        { provide: CveService, useValue: stub },
        { provide: EpssService, useValue: stub },
        { provide: ExploitdbService, useValue: stub },
      ],
    });
    service = TestBed.inject(GapAnalysisService);
  });

  it('is created', () => {
    expect(service).toBeTruthy();
  });

  it('exposes generateReport, exportCsv, exportPdf, exportXlsx', () => {
    expect(typeof service.generateReport).toBe('function');
    expect(typeof service.exportCsv).toBe('function');
    expect(typeof service.exportPdf).toBe('function');
    expect(typeof service.exportXlsx).toBe('function');
  });
});

// P2-10 "updated on purpose": the gap total rolls a group's sub-only technique use up to
// the parent (previously dropped). Realistic shape: menuPass's only use of T1568 is the
// sub T1568.001 — the PARENT must appear in the report scope.
describe('GapAnalysisService sub-only roll-up (P2-10)', () => {
  function tech(id: string, attackId: string, parentId: string | null = null): Technique {
    return {
      id, attackId, name: attackId, description: '', url: '', tacticShortnames: ['command-and-control'],
      isSubtechnique: parentId !== null, parentId, subtechniques: [], mitigationCount: 0, platforms: [],
      dataSources: [], detectionText: '', defenseBypassed: [], permissionsRequired: [], effectivePermissions: [],
      systemRequirements: [], impactType: [], remoteSupport: false, capecIds: [],
    };
  }
  const T1568 = tech('attack-pattern--t1568', 'T1568');                                  // parent, used by NO group directly
  const T1568_001 = tech('attack-pattern--t1568-001', 'T1568.001', 'attack-pattern--t1568'); // the only use
  const menuPass = { id: 'intrusion-set--menupass', attackId: 'G0045', name: 'menuPass', aliases: [] } as unknown as ThreatGroup;
  const DOMAIN = {
    name: 'Enterprise ATT&CK', attackVersion: '19.2', techniques: [T1568, T1568_001], groups: [menuPass],
    techniquesByGroup: new Map([[menuPass.id, [T1568_001]]]),       // sub only, never the parent
    groupsByTechnique: new Map([[T1568_001.id, [menuPass]]]),
    mitigationsByTechnique: new Map(), campaigns: [], techniquesByCampaign: new Map(), campaignsByGroup: new Map(),
    tacticColumns: [{
      tactic: { id: 'x-mitre-tactic--command-and-control', attackId: 'TA0011', name: 'Command and Control', shortname: 'command-and-control', description: '', url: '', order: 0 },
      techniques: [T1568, T1568_001],
    }],
  } as unknown as Domain;

  let service: GapAnalysisService;
  beforeEach(() => {
    const stub = {
      getRuleCount: () => 0, getQueriesForTechnique: () => [], getTestCount: () => 0, getAnalytics: () => [],
      getKevCvesForTechnique: () => [], getExploitCount: () => 0, getContentForTechnique: () => [], getTests: () => [],
    };
    TestBed.configureTestingModule({
      providers: [
        GapAnalysisService,
        ...[DataService, SigmaService, ElasticService, SplunkContentService, M365DefenderService, AtomicService,
          CARService, AttackCveService, CveService, EpssService, ExploitdbService].map(t => ({ provide: t, useValue: stub })),
      ],
    });
    service = TestBed.inject(GapAnalysisService);
  });

  it('counts the parent reached only through a sub-technique', () => {
    const profile = resolveProfile({ kind: 'groups', ids: [menuPass.id] }, DOMAIN);
    expect([...profile.parentTechniqueIds]).toEqual(['attack-pattern--t1568']);   // rolled up to the parent
    const report = service.generateReport(DOMAIN, profile);
    expect(report.summary.totalTechniques).toBe(1);
    expect(report.summary.actorTechniques).toBe(1);   // the parent T1568 is in scope
  });
});
