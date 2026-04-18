// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { EmulationPlanService, EmulationPlan, EmulationStep } from './emulation-plan.service';
import { DataService } from './data.service';
import { AtomicService } from './atomic.service';
import { SigmaService } from './sigma.service';
import { ElasticService } from './elastic.service';
import { SplunkContentService } from './splunk-content.service';

const STORAGE_KEY = 'mitre-nav-emulation-plans';

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
        { provide: AtomicService, useValue: { getTestsForTechnique: () => [] } },
        { provide: SigmaService, useValue: { getRulesForTechnique: () => [] } },
        { provide: ElasticService, useValue: { getRulesForTechnique: () => [] } },
        { provide: SplunkContentService, useValue: { getContentForTechnique: () => [] } },
      ],
    });
    service = TestBed.inject(EmulationPlanService);
  });

  afterEach(() => localStorage.clear());

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
