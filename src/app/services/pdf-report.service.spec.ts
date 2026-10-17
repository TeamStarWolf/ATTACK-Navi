// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { PdfReportService } from './pdf-report.service';
import { Domain, TacticColumn } from '../models/domain';
import { Technique } from '../models/technique';
import { Tactic } from '../models/tactic';
import { ImplStatus } from './implementation.service';
import { MitigationRelationship } from '../models/mitigation';

describe('PdfReportService', () => {
  let service: PdfReportService;

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
    TestBed.configureTestingModule({});
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

  describe('Theoretical / Implemented split (E1.1)', () => {
    function capture(domain: Domain, statusMap: Map<string, ImplStatus>): string {
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
      return writtenHtml;
    }

    /** The mock domain with T1059's two mitigations wired into mitigationsByTechnique. */
    function mappedDomain(): Domain {
      const domain = makeMockDomain();
      domain.mitigationsByTechnique.set('attack-pattern--1', [
        { mitigation: { id: 'course-of-action--m1' } },
        { mitigation: { id: 'course-of-action--m2' } },
      ] as unknown as MitigationRelationship[]);
      return domain;
    }

    it('labels the summary Theoretical and Implemented (self-attested), not Covered / Coverage', () => {
      const html = capture(mappedDomain(), new Map());
      expect(html).toContain('Theoretical: mitigation mapped');
      expect(html).toContain('Implemented (self-attested)');
      expect(html).toContain('<div class="num">1 (50%)</div>');
      expect(html).toContain('<div class="num">0 (0%)</div>');
      expect(html).not.toContain('<div class="lbl">Covered</div>');
      expect(html).not.toContain('<div class="lbl">Uncovered</div>');
      expect(html).not.toContain('<div class="lbl">Coverage</div>');
      expect(html).not.toContain('Coverage %');
      expect(html).not.toContain('Top Uncovered Techniques');
    });

    it('counts Implemented only from mitigations the owner marked implemented', () => {
      const planned = capture(mappedDomain(), new Map<string, ImplStatus>([['course-of-action--m1', 'planned']]));
      expect(planned).not.toContain('<div class="num">1 (50%)</div>\n    <div class="lbl">Implemented (self-attested)</div>');
      expect(planned).toContain('<div class="num">0 (0%)</div>\n    <div class="lbl">Implemented (self-attested)</div>');
    });

    it('shows the split per tactic', () => {
      const html = capture(mappedDomain(), new Map<string, ImplStatus>([['course-of-action--m2', 'implemented']]));
      expect(html).toContain('<div class="num">1 (50%)</div>\n    <div class="lbl">Implemented (self-attested)</div>');
      // The Execution column holds T1059 (mapped) and T1190 (not mapped).
      expect(html).toContain('<td style="text-align:center">2</td>\n        <td style="text-align:center">1 (50%)</td>\n        <td style="text-align:center">1 (50%)</td>');
    });
  });
});
