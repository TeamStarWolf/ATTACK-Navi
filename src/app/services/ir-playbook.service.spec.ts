// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { IRPlaybookService, IRPlaybook } from './ir-playbook.service';
import { SigmaService } from './sigma.service';
import { ElasticService } from './elastic.service';
import { AtomicService } from './atomic.service';

const STUB_PB: IRPlaybook = {
  techniqueId: 'T1003.001',
  techniqueName: 'LSASS Memory',
  tactic: 'credential-access',
  severity: 'critical',
  summary: 'Detect and contain LSASS dumping',
  steps: [
    {
      phase: 'identify',
      action: 'Confirm LSASS access',
      details: 'Look for Sysmon event 10',
      tools: ['Sysmon'],
      commands: ['get-winevent ...'],
      logSources: ['Sysmon Event 10'],
      automatable: true,
    },
  ],
  indicators: ['lsass.exe access by non-system process'],
  relatedTechniques: ['T1003'],
};

describe('IRPlaybookService', () => {
  let service: IRPlaybookService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        IRPlaybookService,
        { provide: SigmaService, useValue: { getCachedRules: () => [], getRuleCount: () => 0 } },
        { provide: ElasticService, useValue: { getRulesForTechnique: () => [] } },
        { provide: AtomicService, useValue: { getTests: () => [] } },
      ],
    });
    service = TestBed.inject(IRPlaybookService);
  });

  describe('exportMarkdown', () => {
    it('produces markdown containing the technique name and phase headers', () => {
      const md = service.exportMarkdown(STUB_PB);
      expect(md).toContain('LSASS Memory');
      expect(md).toContain('T1003.001');
      // Phase labels
      expect(md.toLowerCase()).toContain('identify');
    });
  });

  describe('exportJson', () => {
    it('round-trips to a parseable JSON string', () => {
      const json = service.exportJson(STUB_PB);
      const parsed = JSON.parse(json);
      expect(parsed.techniqueId).toBe('T1003.001');
      expect(parsed.steps.length).toBe(1);
    });
  });
});
