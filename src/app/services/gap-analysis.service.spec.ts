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
