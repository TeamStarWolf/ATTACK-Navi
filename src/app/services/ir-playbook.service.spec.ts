// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { IRPlaybookService, IRPlaybook, TACTIC_RESPONSES } from './ir-playbook.service';
import { SigmaService } from './sigma.service';
import { ElasticService } from './elastic.service';
import { AtomicService } from './atomic.service';
import { Technique } from '../models/technique';
import { Domain } from '../models/domain';

function technique(attackId: string, name: string, tacticShortnames: string[]): Technique {
  return {
    id: `attack-pattern--${attackId}`, attackId, name, description: '', url: '',
    tacticShortnames, isSubtechnique: attackId.includes('.'), parentId: null, subtechniques: [],
    mitigationCount: 0, platforms: ['Windows'], dataSources: [], detectionText: '',
    defenseBypassed: [], permissionsRequired: [], effectivePermissions: [], systemRequirements: [],
    impactType: [], remoteSupport: false, capecIds: [],
  };
}

const EMPTY_DOMAIN = {
  mitigationsByTechnique: new Map(),
  techniquesByMitigation: new Map(),
  groupsByTechnique: new Map(),
} as unknown as Domain;

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
        { provide: ElasticService, useValue: { getRulesForTechnique: () => [], getRuleCount: () => 0 } },
        { provide: AtomicService, useValue: { getTests: () => [], getTestCount: () => 0 } },
      ],
    });
    service = TestBed.inject(IRPlaybookService);
  });

  describe('generatePlaybook tactic currency (ATT&CK v19)', () => {
    const containActions = (pb: IRPlaybook) => pb.steps.filter(s => s.phase === 'contain').map(s => s.action);

    it('gives a defense-impairment technique (T1685) the defense-impairment response, not Execution', () => {
      const pb = service.generatePlaybook(technique('T1685', 'Disable or Modify Tools', ['defense-impairment']), EMPTY_DOMAIN);
      expect(pb.tactic).toBe('defense impairment');
      expect(containActions(pb)).toEqual(jasmine.arrayContaining(TACTIC_RESPONSES['defense-impairment'].contain));
      expect(containActions(pb)).not.toContain('Terminate malicious process');
    });

    it('gives a stealth technique (T1036) the stealth response', () => {
      const pb = service.generatePlaybook(technique('T1036', 'Masquerading', ['stealth']), EMPTY_DOMAIN);
      expect(containActions(pb)).toEqual(jasmine.arrayContaining(TACTIC_RESPONSES['stealth'].contain));
      expect(containActions(pb)).not.toContain('Terminate malicious process');
    });

    it('still resolves the Mobile 18.1 defense-evasion and ICS evasion slugs', () => {
      const mobile = service.generatePlaybook(technique('T1406', 'Obfuscated Files', ['defense-evasion']), EMPTY_DOMAIN);
      expect(containActions(mobile)).not.toContain('Terminate malicious process');
      const ics = service.generatePlaybook(technique('T0849', 'Masquerading', ['evasion']), EMPTY_DOMAIN);
      expect(containActions(ics)).not.toContain('Terminate malicious process');
    });

    it('falls back to Execution only for a technique with no tactic', () => {
      const pb = service.generatePlaybook(technique('T9999', 'No Tactic', []), EMPTY_DOMAIN);
      expect(containActions(pb)).toContain('Terminate malicious process');
    });
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
