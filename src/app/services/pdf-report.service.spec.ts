// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { PdfReportService } from './pdf-report.service';
import { Domain, TacticColumn } from '../models/domain';
import { Technique } from '../models/technique';
import { Tactic } from '../models/tactic';
import { ImplStatus, ImplementationService } from './implementation.service';
import { PostureStub, makePostureStub, postureStubProvider } from '../testing/posture-stub';
import type { PostureBucket } from '../models/posture/posture.types';

describe('PdfReportService', () => {
  let service: PdfReportService;
  // The posture rollup the report reads (P2-07), over the loaded mock domain.
  let loaded: Domain | null;
  let posture: PostureStub;

  // Build a minimal mock Domain for testing
  function makeMockDomain(): Domain {
    const tactic: Tactic = {
      id: 'tactic--1',
      attackId: 'TA0002',
      name: 'Execution',
      shortname: 'execution',
      description: '',
      url: '',
      order: 1,
    };

    const technique: Technique = {
      id: 'attack-pattern--1',
      attackId: 'T1059',
      name: 'Command and Scripting Interpreter',
      description: '',
      url: '',
      tacticShortnames: ['execution'],
      isSubtechnique: false,
      parentId: null,
      subtechniques: [],
      mitigationCount: 2,
      platforms: ['Windows', 'Linux'],
      dataSources: [],
      detectionText: '',
      defenseBypassed: [],
      permissionsRequired: [],
      effectivePermissions: [],
      systemRequirements: [],
      impactType: [],
      remoteSupport: false,
      capecIds: [],
    };

    const uncoveredTechnique: Technique = {
      id: 'attack-pattern--2',
      attackId: 'T1190',
      name: 'Exploit Public-Facing Application',
      description: '',
      url: '',
      tacticShortnames: ['initial-access'],
      isSubtechnique: false,
      parentId: null,
      subtechniques: [],
      mitigationCount: 0,
      platforms: ['Linux'],
      dataSources: [],
      detectionText: '',
      defenseBypassed: [],
      permissionsRequired: [],
      effectivePermissions: [],
      systemRequirements: [],
      impactType: [],
      remoteSupport: false,
      capecIds: [],
    };

    const tacticColumn: TacticColumn = {
      tactic,
      techniques: [technique, uncoveredTechnique],
    };

    return {
      name: 'Enterprise',
      attackVersion: '16.1',
      attackModified: '2024-01-01T00:00:00Z',
      tactics: [tactic],
      techniques: [technique, uncoveredTechnique],
      mitigations: [],
      tacticColumns: [tacticColumn],
      mitigationsByTechnique: new Map(),
      techniquesByMitigation: new Map(),
      maxMitigationCount: 2,
      groups: [],
      groupsByTechnique: new Map(),
      techniquesByGroup: new Map(),
      software: [],
      softwareByTechnique: new Map(),
      techniquesBySoftware: new Map(),
      proceduresByTechnique: new Map(),
      dataSources: [],
      dataComponents: [],
      techniquesByDataComponent: new Map(),
      dataComponentsByTechnique: new Map(),
      campaigns: [],
      campaignsByTechnique: new Map(),
      techniquesByCampaign: new Map(),
      softwareByGroup: new Map(),
      groupsBySoftware: new Map(),
      softwareByCampaign: new Map(),
      campaignsByGroup: new Map(),
      detectionNotesByTechnique: new Map(),
      supersededBy: new Map(),
      retiredNames: new Map(),
    } as Domain;
  }

  beforeEach(() => {
    loaded = null;
    posture = makePostureStub(() => loaded);
    TestBed.configureTestingModule({
      providers: [
        postureStubProvider(posture),
        { provide: ImplementationService, useValue: { summarize: () => ({ implemented: 0 }) } },
      ],
    });
    service = TestBed.inject(PdfReportService);
  });

  it('should create the service', () => {
    expect(service).toBeTruthy();
  });

  it('should create an iframe element when generating a report', () => {
    const domain = makeMockDomain();
    const statusMap = new Map<string, ImplStatus>();
    const createSpy = spyOn(document, 'createElement').and.callThrough();

    service.generateReport(domain, statusMap);

    expect(createSpy).toHaveBeenCalledWith('iframe');
  });

  it('should append the iframe to document.body', () => {
    const domain = makeMockDomain();
    const statusMap = new Map<string, ImplStatus>();
    const appendSpy = spyOn(document.body, 'appendChild').and.callThrough();

    service.generateReport(domain, statusMap);

    expect(appendSpy).toHaveBeenCalled();
    const iframe = appendSpy.calls.mostRecent().args[0] as HTMLElement;
    expect(iframe.tagName.toLowerCase()).toBe('iframe');

    // Clean up: remove the iframe
    if (iframe.parentNode) {
      iframe.parentNode.removeChild(iframe);
    }
  });

  it('should write HTML content to the iframe document', () => {
    const domain = makeMockDomain();
    const statusMap = new Map<string, ImplStatus>();

    // Create a mock iframe with a mock contentDocument
    let writtenHtml = '';
    const mockIframeDoc = {
      open: jasmine.createSpy('open'),
      write: jasmine.createSpy('write').and.callFake((html: string) => { writtenHtml = html; }),
      close: jasmine.createSpy('close'),
    };
    const mockIframe = document.createElement('iframe');
    Object.defineProperty(mockIframe, 'contentDocument', { value: mockIframeDoc });
    Object.defineProperty(mockIframe, 'contentWindow', { value: { print: jasmine.createSpy('print') } });

    spyOn(document, 'createElement').and.returnValue(mockIframe as any);
    spyOn(document.body, 'appendChild').and.stub();
    spyOn(document.body, 'removeChild').and.stub();

    service.generateReport(domain, statusMap);

    expect(mockIframeDoc.open).toHaveBeenCalled();
    expect(mockIframeDoc.write).toHaveBeenCalled();
    expect(writtenHtml).toContain('ATT&amp;CK Mitigation Report');
  });

  it('should include a summary table in the HTML output', () => {
    const domain = makeMockDomain();
    const statusMap = new Map<string, ImplStatus>();

    let writtenHtml = '';
    const mockIframeDoc = {
      open: jasmine.createSpy('open'),
      write: jasmine.createSpy('write').and.callFake((html: string) => { writtenHtml = html; }),
      close: jasmine.createSpy('close'),
    };
    const mockIframe = document.createElement('iframe');
    Object.defineProperty(mockIframe, 'contentDocument', { value: mockIframeDoc });
    Object.defineProperty(mockIframe, 'contentWindow', { value: { print: jasmine.createSpy('print') } });

    spyOn(document, 'createElement').and.returnValue(mockIframe as any);
    spyOn(document.body, 'appendChild').and.stub();
    spyOn(document.body, 'removeChild').and.stub();

    service.generateReport(domain, statusMap);

    expect(writtenHtml).toContain('Summary');
    expect(writtenHtml).toContain('Total Techniques');
  });

  it('should include tactic breakdown in the HTML output', () => {
    const domain = makeMockDomain();
    const statusMap = new Map<string, ImplStatus>();

    let writtenHtml = '';
    const mockIframeDoc = {
      open: jasmine.createSpy('open'),
      write: jasmine.createSpy('write').and.callFake((html: string) => { writtenHtml = html; }),
      close: jasmine.createSpy('close'),
    };
    const mockIframe = document.createElement('iframe');
    Object.defineProperty(mockIframe, 'contentDocument', { value: mockIframeDoc });
    Object.defineProperty(mockIframe, 'contentWindow', { value: { print: jasmine.createSpy('print') } });

    spyOn(document, 'createElement').and.returnValue(mockIframe as any);
    spyOn(document.body, 'appendChild').and.stub();
    spyOn(document.body, 'removeChild').and.stub();

    service.generateReport(domain, statusMap);

    expect(writtenHtml).toContain('Tactic Breakdown');
    expect(writtenHtml).toContain('Execution');
  });

  it('should include the domain version in the HTML output', () => {
    const domain = makeMockDomain();
    const statusMap = new Map<string, ImplStatus>();

    let writtenHtml = '';
    const mockIframeDoc = {
      open: jasmine.createSpy('open'),
      write: jasmine.createSpy('write').and.callFake((html: string) => { writtenHtml = html; }),
      close: jasmine.createSpy('close'),
    };
    const mockIframe = document.createElement('iframe');
    Object.defineProperty(mockIframe, 'contentDocument', { value: mockIframeDoc });
    Object.defineProperty(mockIframe, 'contentWindow', { value: { print: jasmine.createSpy('print') } });

    spyOn(document, 'createElement').and.returnValue(mockIframe as any);
    spyOn(document.body, 'appendChild').and.stub();
    spyOn(document.body, 'removeChild').and.stub();

    service.generateReport(domain, statusMap);

    expect(writtenHtml).toContain('16.1');
  });

  describe('Known / posture split (E1.1, P2-07)', () => {
    function capture(domain: Domain, buckets: Record<string, PostureBucket>): string {
      loaded = domain;
      posture.set(buckets);
      let writtenHtml = '';
      const mockIframeDoc = {
        open: jasmine.createSpy('open'),
        write: jasmine.createSpy('write').and.callFake((html: string) => { writtenHtml = html; }),
        close: jasmine.createSpy('close'),
      };
      const mockIframe = document.createElement('iframe');
      Object.defineProperty(mockIframe, 'contentDocument', { value: mockIframeDoc });
      Object.defineProperty(mockIframe, 'contentWindow', { value: { print: jasmine.createSpy('print') } });
      spyOn(document, 'createElement').and.returnValue(mockIframe as any);
      spyOn(document.body, 'appendChild').and.stub();
      spyOn(document.body, 'removeChild').and.stub();
      service.generateReport(domain, new Map<string, ImplStatus>());
      return writtenHtml;
    }

    it('labels the summary Known: mapped with the Theoretical sub-line; no Covered words on a fresh profile', () => {
      const html = capture(makeMockDomain(), {});
      expect(html).toContain('Known: mapped');
      expect(html).toContain('Theoretical: mitigation mapped');
      expect(html).toContain('<div class="num"><span data-posture="known-mapped">1</span> (50%)</div>');
      expect(html).toContain('<div class="num">1 (50%)</div>\n    <div class="lbl">Theoretical: mitigation mapped</div>');
      expect(html).not.toContain('data-posture="covered"');
      expect(html).toContain('No data of yours recorded yet');
      const visible = new DOMParser().parseFromString(html, 'text/html').body.textContent ?? '';
      expect(visible).not.toMatch(/\bcovered\b|\bproven\b|\bdefended\b/i);
      expect(html).not.toContain('<div class="lbl">Uncovered</div>');
      expect(html).not.toContain('<div class="lbl">Coverage</div>');
      expect(html).not.toContain('Coverage %');
      expect(html).not.toContain('Top Uncovered Techniques');
    });

    it('takes Covered, partial, Proven and stale from the posture rollup', () => {
      const html = capture(makeMockDomain(), { T1059: 'partial', T1190: 'proven' });
      expect(html).toContain('<div class="num" data-share-pct="0"><span data-posture="covered">0</span> (0%)</div>\n    <div class="lbl">Covered (self-attested), of <span data-posture="assessable">2</span> assessable</div>');
      expect(html).toContain('<div class="num" data-posture="partial">1</div>\n    <div class="lbl">partial, by cause</div>\n    <div class="lbl" data-partial-cause>partial (broad mitigation, not confirmed per technique): 1</div>');
      expect(html).toContain('<div class="num" data-posture="proven">1</div>\n    <div class="lbl">Proven</div>');
      expect(html).toContain('<div class="num" data-posture="stale">0</div>');
    });

    // RP-F decision 36: a telemetry-only range partial is counted under its own cause.
    it('a PDF report built from telemetry-only range rows names the telemetry cause and counts it', () => {
      posture.telemetry(['T1059']);
      const html = capture(makeMockDomain(), { T1059: 'partial' });
      expect(html).toContain('<div class="lbl" data-partial-cause>partial (range telemetry, no alert credited): 1</div>');
      expect(html).not.toContain('broad mitigation');
    });

    it('R16: the Covered share divides by assessable; the Total Techniques box keeps every parent', () => {
      posture.exclude(['T1190']);
      const html = capture(makeMockDomain(), { T1059: 'covered' });
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const grid = doc.querySelector('.summary-grid')!;
      const o = posture.rollup().overall;
      expect([o.total, o.assessable, o.covered]).toEqual([2, 1, 1]);
      expect(grid.querySelector('[data-posture="known-total"]')!.textContent).toBe('2');
      expect(grid.querySelector('[data-posture="assessable"]')!.textContent).toBe('1');
      expect(grid.querySelector('[data-share-pct]')!.getAttribute('data-share-pct')).toBe('100');
      expect(html).toContain('<span data-posture="covered">1</span> (100%)');
    });

    it('shows the split per tactic', () => {
      const html = capture(makeMockDomain(), { T1059: 'covered' });
      // The Execution column holds T1059 (mapped, covered) and T1190 (not mapped).
      expect(html).toContain('<td style="text-align:center">2</td>\n        <td style="text-align:center">1</td>\n        <td style="text-align:center">1 (50%)</td>\n        <td style="text-align:center" data-posture="covered">1</td>');
    });
  });
});
