// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectorRef } from '@angular/core';
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ValidationPanelComponent } from './validation-panel.component';
import { DataService } from '../../services/data.service';
import { ATTACK_DID_NOT_EXECUTE, ValidationService, statusFromInputs } from '../../services/validation.service';
import { EventLoggingService } from '../../services/event-logging.service';
import { AtomicService } from '../../services/atomic.service';
import { SigmaService } from '../../services/sigma.service';
import { SiemQueryService } from '../../services/siem-query.service';
import { LibraryService } from '../../services/library.service';
import { TelemetryCoverageService } from '../../services/telemetry-coverage.service';
import { makePostureStub, postureStubProvider } from '../../testing/posture-stub';
import { PanelNavService } from '../../services/panel-nav.service';
import { RecordRunRequestService } from '../../services/record-run-request.service';

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
        // "Record a run" (RP-F decision 31) opens this panel through PanelNavService.
        { provide: PanelNavService, useValue: { open: jasmine.createSpy('open') } },
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

  // Round 2 (item 1): "Import range results" is disabled until a domain loads,
  // because range rows are keyed to the loaded domain at import; a cold import
  // would key to nothing and silently drop every row.
  it('disables "Import range results" until a domain is loaded', () => {
    const el: HTMLElement = fixture.nativeElement;
    const input = () => el.querySelector('#vp-import-range') as HTMLInputElement;
    const label = () => el.querySelector('label[for="vp-import-range"]')!;

    expect(component.domainLoaded).toBeFalse();
    expect(input().disabled).toBeTrue();
    expect(label().getAttribute('aria-disabled')).toBe('true');
    expect(label().getAttribute('title')).toContain('ATT&CK data still loading');

    // A domain arrives: the control enables.
    (TestBed.inject(DataService) as unknown as { domain$: BehaviorSubject<unknown> }).domain$
      .next({ name: 'Enterprise ATT&CK', techniques: [] });
    rerender();
    expect(component.domainLoaded).toBeTrue();
    expect(input().disabled).toBeFalse();
    expect(label().getAttribute('aria-disabled')).toBe('false');
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
    expect(tile('untested')).toBe('0');   // no technique in scope: distinct techniques, never cards minus runs (RP-F decision 20)
    expect(el.textContent).toContain('Coverage so far: 4 validations recorded');
  });

  // RP-F decision 20: "Untested (in scope)" was totalCards minus a RUN count, so several
  // runs on one technique drove it below zero; round 3 read -3 on Detect > Validation.
  it('"Untested (in scope)" counts distinct in-scope techniques with no recorded run, never cards minus runs (it read -3)', () => {
    const svc = TestBed.inject(ValidationService) as unknown as Record<string, unknown>;
    const runsFor: Record<string, { status: string; runDate: string }[]> = {
      T1: ['passed', 'failed', 'passed', 'partial', 'failed', 'no-telemetry']
        .map((status, i) => ({ status, runDate: `2026-10-1${i}T00:00:00.000Z` })),
      T2: [{ status: 'untested', runDate: '2026-10-20T00:00:00.000Z' }],
      T3: [],
    };
    svc['forTechnique'] = (id: string) => runsFor[id] ?? [];
    svc['latestFor'] = (id: string) => (runsFor[id] ?? []).at(-1) ?? null;
    svc['statusCounts'] = () => ({ passed: 2, partial: 1, failed: 2, 'no-telemetry': 1, untested: 1, 'not-reproducible': 0 });
    (TestBed.inject(SigmaService) as unknown as { getRuleCount: () => number }).getRuleCount = () => 1;
    const tech = (n: number) => ({ id: `attack-pattern--t${n}`, attackId: `T${n}`, name: `T${n}`, isSubtechnique: false, tacticShortnames: ['execution'] });
    (TestBed.inject(DataService) as unknown as { domain$: BehaviorSubject<unknown> }).domain$.next({ techniques: [tech(1), tech(2), tech(3)] });
    rerender();
    expect(component.totalCards).toBe(3);
    expect(component.recordedCount).toBe(6);              // the old reading: 3 - 6 = -3
    expect(component.untestedInScope).toBe(2);            // T2 (untested only) and T3 (no run)
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.vp-kpi[data-status="untested"] .vp-kpi-value')!.textContent!.trim()).toBe('2');
  });

  // RP-F decision 30d: a run date that cannot be parsed ('yesterday') made the DatePipe
  // throw, so the workbench tile's "Last run" read blank in round 5. It reads 'date unknown'.
  describe('run dates and fired rules in the workbench (RP-F decisions 30b and 30d)', () => {
    const yesterday = {
      id: 'y1', techniqueId: 'T1113', techniqueName: 'Screen Capture', runDate: 'yesterday', operator: '', status: 'passed',
      detectionsExpected: [], detectionsFired: [], outcomes: [{ detectionRef: 'edr:x', outcome: 'blocked' }],
      telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '', attackResult: 'executed',
      responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '',
    };
    const dated = { ...yesterday, id: 'd1', techniqueId: 'T1005', runDate: '2026-10-21T19:49:00', detectionsFired: ['siem:a'], outcomes: [] };

    function withRuns(): HTMLElement {
      const svc = TestBed.inject(ValidationService) as unknown as Record<string, unknown>;
      const runsFor: Record<string, unknown[]> = { T1113: [yesterday], T1005: [dated] };
      svc['forTechnique'] = (id: string) => runsFor[id] ?? [];
      svc['latestFor'] = (id: string) => (runsFor[id] ?? []).at(-1) ?? null;
      svc['all'] = [yesterday, dated];
      // A card is listed only for a technique with a validation input (a Sigma rule here).
      (TestBed.inject(SigmaService) as unknown as { getRuleCount: () => number }).getRuleCount = () => 1;
      const tech = (attackId: string, name: string) => ({ id: `attack-pattern--${attackId}`, attackId, name, isSubtechnique: false, tacticShortnames: ['collection'] });
      (TestBed.inject(DataService) as unknown as { domain$: BehaviorSubject<unknown> }).domain$
        .next({ techniques: [tech('T1113', 'Screen Capture'), tech('T1005', 'Data from Local System')] });
      return fixture.nativeElement as HTMLElement;
    }
    const squash = (t: string | null | undefined) => (t ?? '').replace(/\s+/g, ' ').trim();

    it("runDate 'yesterday': the tile reads 'Last run date unknown', never blank; a readable date is printed as the pill prints it", () => {
      const el = withRuns();
      component.setTab('techniques');
      rerender();
      const runline = (attackId: string) => {
        const card = [...el.querySelectorAll('.vp-tcard')].find(c => c.querySelector('.vp-tid')?.textContent?.trim() === attackId);
        return squash(card?.querySelector('.vp-tcard-runline')?.textContent);
      };
      // RP-F decision 33: more rules fired than expected reads 'N fired, M expected', never a fraction.
      expect(runline('T1113')).toBe('Last run date unknown · 1 fired, 0 expected');
      expect(runline('T1005')).toBe('Last run 10/21/26, 7:49 PM · 1 fired, 0 expected');
      expect(component.runWhen('yesterday')).toBe('date unknown');
      expect(component.runWhen('')).toBe('date unknown');
      expect(component.runWhen('2026-02-30')).toBe('date unknown');
    });

    it("the run history and the evidence list read 'date unknown' too, and count fired rules through firedRules", () => {
      const el = withRuns();
      component.setTab('runs');
      rerender();
      const rows = [...el.querySelectorAll('tbody tr')].map(r => [...r.querySelectorAll('td')].map(td => squash(td.textContent)));
      const y = rows.find(r => r[1].startsWith('T1113'))!;
      expect(y[0]).toBe('date unknown');
      expect(y[3]).toBe('1 fired, 0 expected');
      component.setTab('evidence');
      rerender();
      const whens = [...el.querySelectorAll('.vp-evidence-when')].map(w => squash(w.textContent));
      expect(whens).toContain('date unknown');
      expect(whens).not.toContain('');
    });
  });

  it("firedWords: 'fired N/M' within expected, 'N fired, M expected' beyond it (RP-F decision 33)", () => {
    const run = (expected: string[], fired: string[]) => ({ detectionsExpected: expected, detectionsFired: fired }) as never;
    expect(component.firedWords(run(['a', 'b'], ['a']), 'fired ')).toBe('fired 1/2');
    expect(component.firedWords(run(['a'], ['a']))).toBe('1/1');
    expect(component.firedWords(run(['a'], ['a', 'b']), 'fired ')).toBe('2 fired, 1 expected');
  });

  // RP-F decision 34: the Run History sorts through the one latest-run comparator
  // (decision 24): by instant, newest first; on the same instant the run that proves
  // less first; 'date unknown' rows last. It sorted runDate strings, so an offset
  // timestamp or a date-only day sat in the wrong place and 'yesterday' sorted first.
  it('the Run History sorts newest first by instant through the shared comparator, date unknown last', () => {
    const run = (id: string, runDate: string, status = 'passed') => ({
      id, techniqueId: 'T1005', techniqueName: 'Data from Local System', runDate, operator: '', status,
      detectionsExpected: [], detectionsFired: [], outcomes: [], telemetryRequired: [], telemetryAvailable: [],
      atomicTestId: '', atomicCommand: '', attackResult: 'executed', responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '',
    });
    const all = [
      run('yesterday', 'yesterday'),
      run('offset', '2026-10-21T01:00:00+05:00'),          // 2026-10-20T20:00Z
      run('utc', '2026-10-20T21:00:00.000Z'),
      run('tie-pass', '2026-10-19T10:00:00.000Z', 'passed'),
      run('tie-fail', '2026-10-19T10:00:00.000Z', 'failed'),
      run('blank', ''),
    ];
    (TestBed.inject(ValidationService) as unknown as { all: unknown[] }).all = all;
    expect(component.allRuns.map(r => r.id)).toEqual(['utc', 'offset', 'tie-fail', 'tie-pass', 'blank', 'yesterday']);
    component.setTab('runs');
    rerender();
    const whens = [...(fixture.nativeElement as HTMLElement).querySelectorAll('tbody tr td:first-child')].map(td => (td.textContent ?? '').trim());
    expect(whens.slice(-2)).toEqual(['date unknown', 'date unknown']);
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

  // RP-F decision 31: the evidence card's "Record a run" on a range telemetry partial
  // opens Detect > Validation with the technique preselected: the Techniques tab,
  // filtered to it, and the Record Run form open on it.
  describe('"Record a run" from the evidence card (RP-F decision 31)', () => {
    const tech = (attackId: string, isSubtechnique = false) =>
      ({ id: `attack-pattern--${attackId}`, attackId, name: `Name ${attackId}`, isSubtechnique, tacticShortnames: ['initial-access'] });
    const domain$ = () => (TestBed.inject(DataService) as unknown as { domain$: BehaviorSubject<unknown> }).domain$;

    it('a request made before the domain loads opens the form once the domain is there, even for a technique with no card', () => {
      const requests = TestBed.inject(RecordRunRequestService);
      requests.request('T1200');
      expect(TestBed.inject(PanelNavService).open).toHaveBeenCalledOnceWith('validation');
      expect(component.showRecordModal).toBeFalse();
      domain$().next({ techniques: [tech('T1059'), tech('T1200')] });
      expect(component.showRecordModal).toBeTrue();
      expect(component.selectedTechnique?.attackId).toBe('T1200');
      expect(component.currentTab).toBe('techniques');
      expect(component.searchText).toBe('T1200');
      expect(requests.take()).toBeNull();   // consumed once
    });

    it('a request while the panel is on screen opens the form at once, for a sub-technique too', () => {
      domain$().next({ techniques: [tech('T1003'), tech('T1003.001', true)] });
      TestBed.inject(RecordRunRequestService).request('T1003.001');
      expect(component.showRecordModal).toBeTrue();
      expect(component.selectedTechnique?.attackId).toBe('T1003.001');
      const el: HTMLElement = fixture.nativeElement;
      rerender();
      expect(el.querySelector('.vp-modal-head h3')?.textContent).toContain('T1003.001');
    });

    it('an id the loaded domain does not carry is dropped', () => {
      domain$().next({ techniques: [tech('T1059')] });
      TestBed.inject(RecordRunRequestService).request('T9999');
      expect(component.showRecordModal).toBeFalse();
      expect(TestBed.inject(RecordRunRequestService).take()).toBeNull();
    });
  });

  // RP-F decision 32: every outcome the Record Run modal offers is classified, and the
  // ones that mean the attack did not execute store untested whatever rules are ticked.
  it('the Record Run outcomes: Failed prerequisite and Errored store untested with every rule ticked; Executed and Blocked do not', () => {
    (TestBed.inject(DataService) as unknown as { domain$: BehaviorSubject<unknown> }).domain$
      .next({ techniques: [{ id: 'attack-pattern--T1200', attackId: 'T1200', name: 'Hardware Additions', isSubtechnique: false, tacticShortnames: [] }] });
    TestBed.inject(RecordRunRequestService).request('T1200');
    rerender();
    const options = [...(fixture.nativeElement as HTMLElement).querySelectorAll('.vp-modal select option')]
      .map(o => [(o as HTMLOptionElement).value, (o.textContent ?? '').trim()]);
    expect(options).toEqual([
      ['executed', 'Executed'], ['failed-prereq', 'Failed prerequisite'], ['blocked', 'Blocked by control'], ['errored', 'Errored'],
    ]);
    const ticked = { telemetryRequired: [], telemetryAvailable: [], detectionsExpected: ['sigma:1'], detectionsFired: ['sigma:1'] };
    const stored = Object.fromEntries(options.map(([value]) =>
      [value, statusFromInputs({ ...ticked, attackResult: value as keyof typeof ATTACK_DID_NOT_EXECUTE })]));
    expect(stored).toEqual({ executed: 'passed', 'failed-prereq': 'untested', blocked: 'passed', errored: 'untested' });
    // saveRun hands the chosen outcome to record(), which computes the status from it.
    component.formAttackResult = 'failed-prereq';
    component.formDetectionsExpected = ['sigma:1'];
    component.formDetectionsFired = { 'sigma:1': true };
    component.saveRun();
    expect(TestBed.inject(ValidationService).record).toHaveBeenCalledWith(jasmine.objectContaining({
      attackResult: 'failed-prereq', detectionsFired: ['sigma:1'],
    }));
  });

  it('cancelRecord closes the modal and clears selectedTechnique', () => {
    (component as any).showRecordModal = true;
    (component as any).selectedTechnique = { attackId: 'T1003.001' };
    component.cancelRecord();
    expect(component.showRecordModal).toBe(false);
    expect(component.selectedTechnique).toBeNull();
  });
});
