// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import {
  ImplementationService,
  ImplStatus,
  IMPL_STATUS_LABELS,
  IMPL_STATUS_COLORS,
} from './implementation.service';
import { SettingsPanelComponent } from '../components/settings-panel/settings-panel.component';
import { SettingsService } from './settings.service';
import { DataService } from './data.service';
import { TimelineService } from './timeline.service';
import { OpenCtiService } from './opencti.service';
import { MispService } from './misp.service';
import { TaxiiService } from './taxii.service';
import { ExportActionsService } from './export-actions.service';
import { DocumentationService } from './documentation.service';
import { BrowserFileService } from './browser-file.service';
import { FilterService } from './filter.service';
import { MatrixExportService } from './matrix-export.service';
import { HtmlReportService } from './html-report.service';
import { ReportConfigService } from './report-config.service';
import { PdfReportService } from './pdf-report.service';
import { XlsxExportService } from './xlsx-export.service';
import { CustomMitigationService } from './custom-mitigation.service';
import { NavigatorLayerService } from './navigator-layer.service';
import { AnnotationService } from './annotation.service';
import { UserLayerService } from './user-layer.service';
import { makePostureStub, postureStubProvider } from '../testing/posture-stub';
import { Domain } from '../models/domain';
import { Mitigation } from '../models/mitigation';

const STORAGE_KEY = 'mitre-nav-impl-v1';

describe('ImplementationService', () => {
  let service: ImplementationService;

  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);

    TestBed.configureTestingModule({});
    service = TestBed.inject(ImplementationService);
  });

  afterEach(() => {
    localStorage.removeItem(STORAGE_KEY);
  });

  // --- Status labels and colors constants ---

  it('should define labels for all status values', () => {
    const statuses: ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];
    for (const s of statuses) {
      expect(IMPL_STATUS_LABELS[s]).toBeTruthy();
    }
  });

  it('should define colors for all status values', () => {
    const statuses: ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];
    for (const s of statuses) {
      expect(IMPL_STATUS_COLORS[s]).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });

  // --- setStatus() ---

  it('should set a status for a mitigation', () => {
    service.setStatus('M1036', 'implemented');
    expect(service.getStatus('M1036')).toBe('implemented');
  });

  it('should update an existing status', () => {
    service.setStatus('M1036', 'planned');
    service.setStatus('M1036', 'implemented');
    expect(service.getStatus('M1036')).toBe('implemented');
  });

  it('should remove a status when set to null', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1036', null);
    expect(service.getStatus('M1036')).toBeNull();
  });

  // --- getStatus() ---

  it('should return null for an untracked mitigation', () => {
    expect(service.getStatus('M9999')).toBeNull();
  });

  // --- clearStatus (set to null) ---

  it('should clear a status via setStatus(null)', () => {
    service.setStatus('M1036', 'in-progress');
    expect(service.getStatus('M1036')).toBe('in-progress');

    service.setStatus('M1036', null);
    expect(service.getStatus('M1036')).toBeNull();
  });

  // --- getStatusMap() ---

  it('should return the full status map', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'planned');

    const map = service.getStatusMap();
    expect(map.size).toBe(2);
    expect(map.get('M1036')).toBe('implemented');
    expect(map.get('M1050')).toBe('planned');
  });

  // --- getImplementedIds() ---

  it('should return only implemented mitigation IDs', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'planned');
    service.setStatus('M1049', 'implemented');

    const ids = service.getImplementedIds();
    expect(ids.size).toBe(2);
    expect(ids.has('M1036')).toBeTrue();
    expect(ids.has('M1049')).toBeTrue();
    expect(ids.has('M1050')).toBeFalse();
  });

  // --- summarize() ---

  it('should return correct counts by status', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'planned');
    service.setStatus('M1049', 'implemented');
    service.setStatus('M1048', 'in-progress');
    service.setStatus('M1047', 'not-started');

    const summary = service.summarize();
    expect(summary['implemented']).toBe(2);
    expect(summary['planned']).toBe(1);
    expect(summary['in-progress']).toBe(1);
    expect(summary['not-started']).toBe(1);
  });

  // --- exportJson() / importJson() ---

  it('should export and re-import status data', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'planned');

    const json = service.exportJson();
    service.resetAll();
    expect(service.getStatus('M1036')).toBeNull();

    service.importJson(json);
    expect(service.getStatus('M1036')).toBe('implemented');
    expect(service.getStatus('M1050')).toBe('planned');
  });

  it('should throw on invalid import data', () => {
    expect(() => service.importJson('not-json')).toThrow();
  });

  it('should throw on non-array import data', () => {
    expect(() => service.importJson('{"a": 1}')).toThrow();
  });

  it('should filter invalid status values during import', () => {
    const data = JSON.stringify([
      ['M1036', 'implemented'],
      ['M1050', 'invalid-status'],
    ]);
    service.importJson(data);
    expect(service.getStatus('M1036')).toBe('implemented');
    expect(service.getStatus('M1050')).toBeNull();
  });

  // --- resetAll() ---

  it('should clear all statuses', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'planned');

    service.resetAll();

    expect(service.getStatus('M1036')).toBeNull();
    expect(service.getStatus('M1050')).toBeNull();
    expect(service.getStatusMap().size).toBe(0);
  });

  it('should remove localStorage on resetAll', () => {
    service.setStatus('M1036', 'implemented');
    expect(localStorage.getItem(STORAGE_KEY)).toBeTruthy();

    service.resetAll();
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  // --- status$ observable ---

  it('should emit updated map via status$', () => {
    let emittedMap: Map<string, ImplStatus> = new Map();
    service.status$.subscribe(val => { emittedMap = val; });

    service.setStatus('M1036', 'implemented');
    expect(emittedMap.get('M1036')).toBe('implemented');

    service.setStatus('M1036', null);
    expect(emittedMap.has('M1036')).toBeFalse();
  });

  // --- localStorage persistence ---

  it('should persist statuses to localStorage', () => {
    service.setStatus('M1036', 'implemented');

    const raw = localStorage.getItem(STORAGE_KEY);
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw!);
    expect(parsed).toEqual([['M1036', 'implemented']]);
  });

  it('should restore statuses from localStorage on construction', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'in-progress');

    // Create new instance (simulating app reload)
    const service2 = new ImplementationService();
    expect(service2.getStatus('M1036')).toBe('implemented');
    expect(service2.getStatus('M1050')).toBe('in-progress');
  });

  it('should handle corrupted localStorage gracefully', () => {
    localStorage.setItem(STORAGE_KEY, 'not-valid-json');

    const service2 = new ImplementationService();
    expect(service2.getStatusMap().size).toBe(0);
  });

  it('should handle non-array localStorage gracefully', () => {
    localStorage.setItem(STORAGE_KEY, '"just-a-string"');

    const service2 = new ImplementationService();
    expect(service2.getStatusMap().size).toBe(0);
  });
});

// ─── P2-06: header-driven CSV import with a preview that writes the one map ───
describe('ImplementationService CSV import (P2-06)', () => {
  const SETTINGS_KEY = 'mitre-nav-settings-v1';
  const AAA = 'course-of-action--aaa';   // M1036
  const BBB = 'course-of-action--bbb';   // M1015

  function mit(id: string, attackId: string, name: string): Mitigation {
    return { id, attackId, name, description: '', url: '' };
  }
  const DOMAIN = {
    name: 'Enterprise ATT&CK',
    mitigations: [mit(AAA, 'M1036', 'Account Use Policies'), mit(BBB, 'M1015', 'Active Directory Configuration')],
    techniquesByMitigation: new Map(),
  } as unknown as Domain;

  let service: ImplementationService;
  let domain$: BehaviorSubject<Domain | null>;

  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(SETTINGS_KEY);
    domain$ = new BehaviorSubject<Domain | null>(DOMAIN);
    TestBed.configureTestingModule({
      imports: [SettingsPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$, getCurrentDomain: () => domain$.value, getCurrentAttackDomain: () => 'enterprise' } },
        { provide: TimelineService, useValue: { snapshots$: new BehaviorSubject([]), getStorageSizeKb: () => 0 } },
        { provide: OpenCtiService, useValue: {
            connected$: new BehaviorSubject(false), error$: new BehaviorSubject<string | null>(null), loading$: new BehaviorSubject(false),
            getConfig: () => ({ url: '', token: '', mode: 'direct', proxyUrl: '', connected: false }),
        } },
        { provide: MispService, useValue: {
            connected$: new BehaviorSubject(false), serverError$: new BehaviorSubject<string | null>(null), serverLoading$: new BehaviorSubject(false),
            getConfig: () => ({ url: '', apiKey: '', orgId: '', mode: 'direct', proxyUrl: '', connected: false }),
        } },
        { provide: TaxiiService, useValue: { servers$: new BehaviorSubject([]) } },
        // The settings panel reads PostureService.ownerWords (P2-14 repair round 1); this stub DataService cannot feed the real one.
        postureStubProvider(makePostureStub(() => null)),
      ],
    });
    TestBed.inject(SettingsService).reset();
    service = TestBed.inject(ImplementationService);
  });

  afterEach(() => {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(SETTINGS_KEY);
  });

  it('previewStatusCsv delegates to the parser; applyStatusCsv writes only matched rows', () => {
    const preview = service.previewStatusCsv('mitigation_id,status\nM1036,implemented\nT1059,planned', DOMAIN);
    expect(preview.matched.length).toBe(1);
    expect(preview.unmatched.length).toBe(1);   // the T-id row
    expect(service.applyStatusCsv(preview)).toBe(1);
    expect(service.getStatus(AAA)).toBe('implemented');
    expect(service.getStatusMap().size).toBe(1);   // the T-id row wrote nothing
  });

  it('the settings reset control is two-step and empties the status map and status$', () => {
    let live: Map<string, ImplStatus> = new Map();
    service.status$.subscribe((m) => (live = m));
    service.setStatus(AAA, 'implemented');
    const c = TestBed.createComponent(SettingsPanelComponent).componentInstance;

    c.resetImplementationStatuses();                  // first click: arm the confirm only
    expect(c.confirmingResetImpl).toBeTrue();
    expect(service.getStatusMap().size).toBe(1);      // nothing cleared yet

    c.resetImplementationStatuses();                  // second click: reset
    expect(c.confirmingResetImpl).toBeFalse();
    expect(service.getStatusMap().size).toBe(0);
    expect(live.size).toBe(0);                        // status$ emitted the empty map
  });

  it('round-trips the REAL Settings export and overwrites only the named mitigation (R8)', async () => {
    let live: Map<string, ImplStatus> = new Map();
    service.status$.subscribe((m) => (live = m));
    const invariant = () => expect(service.getStatusMap()).toBe(live);   // getStatusMap() === status$ value

    service.setStatus(AAA, 'implemented');
    service.setStatus(BBB, 'implemented');
    invariant();

    // Export through the real settings-panel code; capture the Blob it hands to the download.
    const fixture = TestBed.createComponent(SettingsPanelComponent);
    let captured: Blob | null = null;
    spyOn(URL, 'createObjectURL').and.callFake((b: Blob) => { captured = b; return 'blob:fake'; });
    spyOn(URL, 'revokeObjectURL');
    fixture.componentInstance.exportImplCsv();
    expect(captured).withContext('export produced a CSV blob').toBeTruthy();
    const csv = await (captured as unknown as Blob).text();
    expect(csv.split(/\r?\n/)[0]).toBe('Mitigation ID,Mitigation Name,Status,Mapped Techniques');

    // Change one status, then re-import the original export: that one reverts.
    service.setStatus(AAA, 'planned');
    invariant();
    const preview = service.previewStatusCsv(csv, DOMAIN);
    expect(preview.matched.length).toBe(2);   // both tracked rows matched (fixes the zero-row bug)
    expect(preview.unmatched.length).toBe(0);
    expect(preview.errors).toBe(0);
    service.applyStatusCsv(preview);
    expect(service.getStatus(AAA)).toBe('implemented');
    expect(service.getStatus(BBB)).toBe('implemented');
    invariant();

    // setStatus(id, null) after an import clears exactly that mitigation.
    service.setStatus(AAA, null);
    expect(service.getStatus(AAA)).toBeNull();
    expect(service.getStatus(BBB)).toBe('implemented');
    invariant();

    // resetAll() after an import leaves an empty map.
    service.resetAll();
    expect(service.getStatusMap().size).toBe(0);
    invariant();
  });
});

// The Export Hub "Implementation Plan" export (export-actions.service.ts) run through
// its REAL code and fed back to the parser, so a header drift there fails this spec.
describe('ImplementationService CSV import: real Implementation Plan export round-trip (P2-06)', () => {
  const AAA = 'course-of-action--aaa';   // M1036
  const BBB = 'course-of-action--bbb';   // M1015
  function mit(id: string, attackId: string, name: string): Mitigation {
    return { id, attackId, name, description: '', url: '' };
  }
  const DOMAIN = {
    name: 'Enterprise ATT&CK',
    mitigations: [mit(AAA, 'M1036', 'Account Use Policies'), mit(BBB, 'M1015', 'Active Directory Configuration')],
    techniquesByMitigation: new Map(),
    mitigationsByTechnique: new Map(),
  } as unknown as Domain;

  let service: ImplementationService;
  let exportActions: ExportActionsService;
  let captured: string | null;

  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);
    captured = null;
    const domain$ = new BehaviorSubject<Domain | null>(DOMAIN);
    const currentDomain$ = new BehaviorSubject('enterprise');
    const emptyDoc = { notes: '', owner: '', dueDate: '', controlRefs: '', evidenceUrl: '' };
    const stub = {};
    TestBed.configureTestingModule({
      providers: [
        { provide: DataService, useValue: { domain$, currentDomain$, getCurrentDomain: () => domain$.value, getCurrentAttackDomain: () => 'enterprise' } },
        { provide: DocumentationService, useValue: { getMitDoc: () => emptyDoc } },
        { provide: BrowserFileService, useValue: { downloadText: (c: string) => { captured = c; } } },
        { provide: FilterService, useValue: stub },
        { provide: MatrixExportService, useValue: stub },
        { provide: HtmlReportService, useValue: stub },
        { provide: ReportConfigService, useValue: stub },
        { provide: PdfReportService, useValue: stub },
        { provide: XlsxExportService, useValue: stub },
        { provide: CustomMitigationService, useValue: stub },
        { provide: TimelineService, useValue: stub },
        { provide: NavigatorLayerService, useValue: stub },
        { provide: AnnotationService, useValue: stub },
        { provide: UserLayerService, useValue: stub },
      ],
    });
    service = TestBed.inject(ImplementationService);
    exportActions = TestBed.inject(ExportActionsService);
  });

  afterEach(() => localStorage.removeItem(STORAGE_KEY));

  it('round-trips the REAL Implementation Plan export: both tracked rows matched, 0 unmatched, 0 errors', () => {
    service.setStatus(AAA, 'implemented');
    service.setStatus(BBB, 'planned');

    exportActions.exportImplPlanCsv();
    expect(captured).withContext('plan export produced a CSV').toBeTruthy();
    expect(captured!.split(/\r?\n/)[0]).toBe(
      'Mitigation ID,Mitigation Name,Status,Owner,Target Date,Security Controls,Evidence URL,Mapped Techniques,Unique Coverage,Notes',
    );

    const preview = service.previewStatusCsv(captured!, DOMAIN);
    expect(preview.matched.length).toBe(2);
    expect(preview.unmatched.length).toBe(0);
    expect(preview.errors).toBe(0);
  });
});
