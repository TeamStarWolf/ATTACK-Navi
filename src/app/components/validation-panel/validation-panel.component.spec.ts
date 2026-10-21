// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectorRef } from '@angular/core';
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ValidationPanelComponent } from './validation-panel.component';
import { DataService } from '../../services/data.service';
import { ValidationService } from '../../services/validation.service';
import { EventLoggingService } from '../../services/event-logging.service';
import { AtomicService } from '../../services/atomic.service';
import { SigmaService } from '../../services/sigma.service';
import { SiemQueryService } from '../../services/siem-query.service';
import { LibraryService } from '../../services/library.service';
import { TelemetryCoverageService } from '../../services/telemetry-coverage.service';
import { makePostureStub, postureStubProvider } from '../../testing/posture-stub';

describe('ValidationPanelComponent', () => {
  let component: ValidationPanelComponent;
  let fixture: ComponentFixture<ValidationPanelComponent>;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      imports: [ValidationPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ValidationService, useValue: {
            runs$: new BehaviorSubject([]),
            all: [],
            statusCounts: () => ({ passed: 0, partial: 0, failed: 0, 'no-telemetry': 0, untested: 0, 'not-reproducible': 0 }),
            migrationDropped: [],
            uniqueTechniqueCount: () => 0,
            forTechnique: () => [],
            latestFor: () => null,
            record: jasmine.createSpy(),
            update: jasmine.createSpy(),
            delete: jasmine.createSpy(),
            exportJson: () => '{}',
            importJson: () => ({ ok: true, imported: 0 }),
            importRangeContract: () => ({ ok: true, bySource: { 'lylat-range:SYNTH-MISSION-A': { added: 8, replaced: 0 } }, dropped: [] }),
            buildNavigatorLayer: () => ({}),
        }},
        { provide: EventLoggingService, useValue: { getLoggingConfig: () => [] } },
        { provide: AtomicService, useValue: { getTestCount: () => 0, getTests: () => [] } },
        { provide: SigmaService, useValue: { getRuleCount: () => 0 } },
        { provide: SiemQueryService, useValue: { hasCuratedQueries: () => false } },
        { provide: LibraryService, useValue: { getAssetsForTactic: () => [] } },
        { provide: TelemetryCoverageService, useValue: {
            status$: new BehaviorSubject(new Set<string>()),
            buildMatrix: () => [],
            summary: () => ({ total: 0, configured: 0, pct: 0 }),
            toggle: jasmine.createSpy(),
            clearAll: jasmine.createSpy(),
        }},
        // The summary header mounts the posture card (P2-07).
        postureStubProvider(makePostureStub(() => null)),
      ],
    });
    fixture = TestBed.createComponent(ValidationPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => localStorage.clear());

  /** The panel is OnPush: mark its own view before re-rendering a changed stub. */
  function rerender(): void {
    fixture.debugElement.injector.get(ChangeDetectorRef).markForCheck();
    fixture.detectChanges();
  }

  it('is created on the overview tab', () => {
    expect(component).toBeTruthy();
    expect(component.currentTab).toBe('overview');
  });

  it('setTab updates the active tab', () => {
    component.setTab('techniques');
    expect(component.currentTab).toBe('techniques');
    component.setTab('telemetry');
    expect(component.currentTab).toBe('telemetry');
    component.setTab('runs');
    expect(component.currentTab).toBe('runs');
    component.setTab('evidence');
    expect(component.currentTab).toBe('evidence');
  });

  it('statusLabel returns short uppercase labels', () => {
    expect(component.statusLabel('passed')).toBe('PASS');
    expect(component.statusLabel('failed')).toBe('FAIL');
    expect(component.statusLabel('partial')).toBe('PARTIAL');
    expect(component.statusLabel('no-telemetry')).toBe('NO TELEMETRY');
    expect(component.statusLabel('untested')).toBe('UNTESTED');
  });

  // P2-20: "Import range results" reads a range export locally (FileReader only,
  // never a URL) and reports the per-mission result.
  it('importRangeResults reads a file locally and shows a per-source message', async () => {
    const svc = TestBed.inject(ValidationService) as unknown as { importRangeContract: jasmine.Spy };
    svc.importRangeContract = jasmine.createSpy('importRangeContract').and.returnValue(
      { ok: true, bySource: { 'lylat-range:SYNTH-MISSION-A': { added: 8, replaced: 0 } }, dropped: [] });
    const file = { text: () => Promise.resolve('{"schema":"lylat-validated-detections/1","generated_at":"x","rows":[]}') };
    const input = { files: [file], value: 'picked' } as unknown as HTMLInputElement;

    await component.importRangeResults({ target: input } as unknown as Event);

    expect(svc.importRangeContract).toHaveBeenCalledWith('{"schema":"lylat-validated-detections/1","generated_at":"x","rows":[]}');
    expect(component.rangeImportMessage).toContain('lylat-range:SYNTH-MISSION-A: 8 added');
    expect(input.value).toBe('');
  });

  it('importRangeResults surfaces the error from a refused file', async () => {
    const svc = TestBed.inject(ValidationService) as unknown as { importRangeContract: jasmine.Spy };
    svc.importRangeContract = jasmine.createSpy('importRangeContract').and.returnValue(
      { ok: false, bySource: {}, dropped: [], error: 'Invalid range results file: rows[0].evidence_ref: refused by the privacy check' });
    const file = { text: () => Promise.resolve('{}') };
    const input = { files: [file], value: 'picked' } as unknown as HTMLInputElement;

    await component.importRangeResults({ target: input } as unknown as Event);

    expect(component.rangeImportMessage).toContain('privacy check');
  });

  // P2-02 round 1: 'not-reproducible' has its own KPI tile and is a recorded
  // outcome, so it is counted out of "Untested (in scope)" and into "Coverage so far".
  it('shows a not-reproducible KPI tile and counts it as recorded, not untested', () => {
    const svc = TestBed.inject(ValidationService) as unknown as { statusCounts: () => Record<string, number> };
    svc.statusCounts = () => ({ passed: 1, partial: 0, failed: 1, 'no-telemetry': 0, untested: 4, 'not-reproducible': 2 });
    rerender();
    expect(component.recordedCount).toBe(4);
    const el: HTMLElement = fixture.nativeElement;
    const tile = (s: string) => el.querySelector(`.vp-kpi[data-status="${s}"] .vp-kpi-value`)!.textContent!.trim();
    expect(tile('not-reproducible')).toBe('2');
    expect(el.querySelector('.vp-kpi[data-status="not-reproducible"] .vp-kpi-label')!.textContent!.trim())
      .toBe('Not reproducible (patched target)');
    expect(tile('untested')).toBe(String(component.totalCards - 4));
    expect(el.textContent).toContain('Coverage so far: 4 validations recorded');
  });

  it('names v1 runs the copy-forward could not carry, and is silent when there are none', () => {
    const el: HTMLElement = fixture.nativeElement;
    expect(component.migrationNotice).toBeNull();
    expect(el.querySelector('.vp-migration-msg')).toBeNull();
    (TestBed.inject(ValidationService) as unknown as { migrationDropped: unknown }).migrationDropped =
      [{ row: 2, reason: 'missing techniqueId' }];
    rerender();
    expect(el.querySelector('.vp-migration-msg')!.textContent).toContain('row 2: missing techniqueId');
    expect(component.migrationNotice).toContain('attacknavi.validation-runs.v1');
  });

  it('cancelRecord closes the modal and clears selectedTechnique', () => {
    (component as any).showRecordModal = true;
    (component as any).selectedTechnique = { attackId: 'T1003.001' };
    component.cancelRecord();
    expect(component.showRecordModal).toBe(false);
    expect(component.selectedTechnique).toBeNull();
  });
});
