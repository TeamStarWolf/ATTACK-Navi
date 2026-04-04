import { TestBed } from '@angular/core/testing';
import { PdfReportService } from './pdf-report.service';
import { Domain, TacticColumn } from '../models/domain';
import { Technique } from '../models/technique';
import { Tactic } from '../models/tactic';
import { ImplStatus } from './implementation.service';

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
    expect(writtenHtml).toContain('ATT&amp;CK Coverage Report');
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
});
