// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { EmulationPlanService, EmulationPlan, EmulationStep } from './emulation-plan.service';
import { DataService } from './data.service';
import { AtomicService } from './atomic.service';
import { SigmaService } from './sigma.service';
import { ElasticService } from './elastic.service';
import { SplunkContentService } from './splunk-content.service';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { Tactic } from '../models/tactic';

const STORAGE_KEY = 'mitre-nav-emulation-plans';

function technique(attackId: string, name: string, tacticShortnames: string[]): Technique {
  return {
    id: `attack-pattern--${attackId}`, attackId, name, description: '', url: '',
    tacticShortnames, isSubtechnique: attackId.includes('.'), parentId: null, subtechniques: [],
    mitigationCount: 0, platforms: ['Windows'], dataSources: [], detectionText: '',
    defenseBypassed: [], permissionsRequired: [], effectivePermissions: [], systemRequirements: [],
    impactType: [], remoteSupport: false, capecIds: [],
  };
}

function tactic(shortname: string, name: string, order: number): Tactic {
  return { id: `x-mitre-tactic--${shortname}`, attackId: 'TA0000', name, shortname, description: '', url: '', order };
}

/** Enterprise v19-shaped domain with one group using techniques across the split tactics. */
function v19Domain(): Domain {
  const techs = [
    technique('T1486', 'Data Encrypted for Impact', ['impact']),
    technique('T1685', 'Disable or Modify Tools', ['defense-impairment']),
    technique('T1003', 'OS Credential Dumping', ['credential-access']),
    technique('T1036', 'Masquerading', ['stealth']),
    technique('T1566', 'Phishing', ['initial-access']),
  ];
  const tactics = [
    tactic('initial-access', 'Initial Access', 0),
    tactic('privilege-escalation', 'Privilege Escalation', 1),
    tactic('stealth', 'Stealth', 2),
    tactic('defense-impairment', 'Defense Impairment', 3),
    tactic('credential-access', 'Credential Access', 4),
    tactic('impact', 'Impact', 5),
  ];
  const group = { id: 'intrusion-set--g1', attackId: 'G0001', name: 'Test Group' };
  return {
    name: 'Enterprise ATT&CK', tactics, techniques: techs, groups: [group],
    techniquesByGroup: new Map([[group.id, techs]]),
  } as unknown as Domain;
}

const STUB_PLAN: EmulationPlan = {
  id: 'plan-test-1',
  name: 'Test Plan',
  actorName: 'TestActor',
  actorId: 'G1234',
  description: 'Synthetic plan for unit tests',
  totalSteps: 2,
  createdAt: '2026-04-17T00:00:00Z',
  steps: [
    {
      order: 1,
      phase: 'Initial Access',
      techniqueId: 'T1566.001',
      techniqueName: 'Spearphishing Attachment',
      objective: 'Gain foothold via',
      atomicTestId: 'AT-001',
      invokeCommand: 'powershell -c "echo phish"',
      expectedDetection: 'Office spawn child',
      expectedLogSource: 'Sysmon Event 1',
      prerequisites: ['admin shell'],
      successCriteria: 'Initial shell obtained',
    },
    {
      order: 2,
      phase: 'Credential Access',
      techniqueId: 'T1003.001',
      techniqueName: 'LSASS Memory',
      objective: 'Harvest creds via',
      atomicTestId: null,
      invokeCommand: '',
      expectedDetection: 'LSASS access',
      expectedLogSource: 'Sysmon Event 10',
      prerequisites: [],
      successCriteria: 'NTLM hashes obtained',
    },
  ],
};

describe('EmulationPlanService', () => {
  let service: EmulationPlanService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        EmulationPlanService,
        { provide: DataService, useValue: {} },
        { provide: AtomicService, useValue: { getTestsForTechnique: () => [], getTests: () => [], generateInvokeCommand: (id: string) => `Invoke-AtomicTest ${id}` } },
        { provide: SigmaService, useValue: { getRulesForTechnique: () => [], getRuleCount: () => 0 } },
        { provide: ElasticService, useValue: { getRulesForTechnique: () => [], getRuleCount: () => 0 } },
        { provide: SplunkContentService, useValue: { getContentForTechnique: () => [], getRuleCount: () => 0 } },
      ],
    });
    service = TestBed.inject(EmulationPlanService);
  });

  afterEach(() => localStorage.clear());

  describe('generatePlan tactic currency (ATT&CK v19)', () => {
    it('orders steps by the loaded domain kill chain, with stealth/defense-impairment before credential access', () => {
      const plan = service.generatePlan('intrusion-set--g1', v19Domain());
      expect(plan.steps.map(s => s.techniqueId)).toEqual(['T1566', 'T1036', 'T1685', 'T1003', 'T1486']);
      expect(plan.steps.map(s => s.tactic)).toEqual(['initial-access', 'stealth', 'defense-impairment', 'credential-access', 'impact']);
    });

    it('labels phases with the domain tactic names instead of raw slugs', () => {
      const plan = service.generatePlan('intrusion-set--g1', v19Domain());
      expect(plan.steps.map(s => s.phase)).toEqual(['Initial Access', 'Stealth', 'Defense Impairment', 'Credential Access', 'Impact']);
    });

    it('uses tactic-specific objective and success templates for the split tactics', () => {
      const plan = service.generatePlan('intrusion-set--g1', v19Domain());
      const stealth = plan.steps.find(s => s.techniqueId === 'T1036')!;
      const impair = plan.steps.find(s => s.techniqueId === 'T1685')!;
      expect(stealth.objective.startsWith('Hide from defenses via')).toBeTrue();
      expect(impair.objective.startsWith('Disable or degrade defenses via')).toBeTrue();
      expect(stealth.objective).not.toMatch(/^Execute /);
      expect(impair.successCriteria).not.toBe('Technique execution verified');
    });

    it('derives the previous-phase prerequisite from the domain order', () => {
      const plan = service.generatePlan('intrusion-set--g1', v19Domain());
      const impair = plan.steps.find(s => s.techniqueId === 'T1685')!;
      expect(impair.prerequisites).toContain('Stealth phase completed');
    });
  });

  describe('exportCalderaProfile phase numbering', () => {
    let blobText: () => Promise<string>;

    beforeEach(() => {
      const aSpy = jasmine.createSpyObj<HTMLAnchorElement>('a', ['click']);
      Object.assign(aSpy, { href: '', download: '' });
      spyOn(document, 'createElement').and.callFake((tag: string) => {
        if (tag === 'a') return aSpy;
        return document.createElement(tag);
      });
      let captured: Blob | null = null;
      spyOn(URL, 'createObjectURL').and.callFake((b: Blob | MediaSource) => { captured = b as Blob; return 'blob:mock'; });
      spyOn(URL, 'revokeObjectURL');
      blobText = () => captured!.text();
    });

    it('places stealth and defense-impairment steps between privilege escalation and credential access', async () => {
      const plan = service.generatePlan('intrusion-set--g1', v19Domain());
      service.exportCalderaProfile(plan);
      const yaml = await blobText();
      const phaseOf = (id: string) => {
        const lines = yaml.split('\n');
        let current = 0;
        for (const line of lines) {
          const m = /^  (\d+):$/.exec(line);
          if (m) current = Number(m[1]);
          if (line.includes(`attack_id: "${id}"`)) return current;
        }
        return -1;
      };
      expect(phaseOf('T1566')).toBe(1);
      expect(phaseOf('T1036')).toBe(5);
      expect(phaseOf('T1685')).toBe(6);
      expect(phaseOf('T1003')).toBe(7);
      expect(phaseOf('T1486')).toBe(13);
      expect(phaseOf('T1036')).toBeLessThan(phaseOf('T1003'));
    });

    it('maps a plan saved before the split (phase "Defense Evasion", no tactic field) to the stealth phase', async () => {
      const legacy: EmulationPlan = {
        ...STUB_PLAN,
        steps: [{ ...STUB_PLAN.steps[0], phase: 'Defense Evasion', techniqueId: 'T1562.001' }],
      };
      service.exportCalderaProfile(legacy);
      const yaml = await blobText();
      expect(yaml).toContain('  5:\n    - technique:\n        attack_id: "T1562.001"');
    });
  });

  describe('exportMarkdown', () => {
    it('produces a markdown string with phase headers and step details', () => {
      const md = service.exportMarkdown(STUB_PLAN);
      expect(md).toContain('TestActor');
      expect(md).toContain('Initial Access');
      expect(md).toContain('Credential Access');
      expect(md).toContain('T1566.001');
      expect(md).toContain('T1003.001');
      expect(md).toContain('LSASS Memory');
    });

    it('includes prerequisites when present', () => {
      const md = service.exportMarkdown(STUB_PLAN);
      expect(md).toContain('admin shell');
    });
  });

  describe('exportScytheCampaign', () => {
    it('triggers a download with .yml extension', () => {
      const aSpy = jasmine.createSpyObj<HTMLAnchorElement>('a', ['click']);
      Object.assign(aSpy, { href: '', download: '' });
      const createSpy = spyOn(document, 'createElement').and.callFake((tag: string) => {
        if (tag === 'a') return aSpy;
        return document.createElement(tag);
      });
      spyOn(URL, 'createObjectURL').and.returnValue('blob:mock');
      spyOn(URL, 'revokeObjectURL');

      service.exportScytheCampaign(STUB_PLAN);

      expect(createSpy).toHaveBeenCalledWith('a');
      expect(aSpy.click).toHaveBeenCalled();
      expect(aSpy.download).toContain('scythe-G1234');
      expect(aSpy.download).toMatch(/\.yml$/);
    });
  });

  describe('exportJson', () => {
    it('triggers a download with .json extension', () => {
      const aSpy = jasmine.createSpyObj<HTMLAnchorElement>('a', ['click']);
      Object.assign(aSpy, { href: '', download: '' });
      spyOn(document, 'createElement').and.callFake((tag: string) => {
        if (tag === 'a') return aSpy;
        return document.createElement(tag);
      });
      spyOn(URL, 'createObjectURL').and.returnValue('blob:mock');
      spyOn(URL, 'revokeObjectURL');

      service.exportJson(STUB_PLAN);

      expect(aSpy.click).toHaveBeenCalled();
      expect(aSpy.download).toContain('emulation-plan-G1234');
      expect(aSpy.download).toMatch(/\.json$/);
    });
  });

  describe('localStorage persistence', () => {
    it('savePlan + getSavedPlans round-trips', () => {
      service.savePlan(STUB_PLAN);
      const plans = service.getSavedPlans();
      expect(plans.length).toBe(1);
      expect(plans[0].id).toBe(STUB_PLAN.id);
      expect(plans[0].steps.length).toBe(2);
    });

    it('savePlan replaces an existing plan with the same id', () => {
      service.savePlan(STUB_PLAN);
      const updated: EmulationPlan = { ...STUB_PLAN, name: 'Renamed' };
      service.savePlan(updated);
      const plans = service.getSavedPlans();
      expect(plans.length).toBe(1);
      expect(plans[0].name).toBe('Renamed');
    });

    it('deletePlan removes the matching id', () => {
      service.savePlan(STUB_PLAN);
      service.deletePlan(STUB_PLAN.id);
      expect(service.getSavedPlans()).toEqual([]);
    });

    it('getSavedPlans returns [] when localStorage empty or invalid', () => {
      expect(service.getSavedPlans()).toEqual([]);
      localStorage.setItem(STORAGE_KEY, 'not-json');
      expect(service.getSavedPlans()).toEqual([]);
    });
  });
});
