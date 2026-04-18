// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ValidationPanelComponent } from './validation-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ValidationService } from '../../services/validation.service';
import { EventLoggingService } from '../../services/event-logging.service';
import { AtomicService } from '../../services/atomic.service';
import { SigmaService } from '../../services/sigma.service';
import { SiemQueryService } from '../../services/siem-query.service';
import { LibraryService } from '../../services/library.service';
import { TelemetryCoverageService } from '../../services/telemetry-coverage.service';

describe('ValidationPanelComponent', () => {
  let component: ValidationPanelComponent;
  let fixture: ComponentFixture<ValidationPanelComponent>;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      imports: [ValidationPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ValidationService, useValue: {
            runs$: new BehaviorSubject([]),
            all: [],
            statusCounts: () => ({ passed: 0, partial: 0, failed: 0, 'no-telemetry': 0, untested: 0 }),
            uniqueTechniqueCount: () => 0,
            forTechnique: () => [],
            latestFor: () => null,
            record: jasmine.createSpy(),
            update: jasmine.createSpy(),
            delete: jasmine.createSpy(),
            exportJson: () => '{}',
            importJson: () => ({ ok: true, imported: 0 }),
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
      ],
    });
    fixture = TestBed.createComponent(ValidationPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => localStorage.clear());

  it('is created and starts hidden on the overview tab', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
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

  it('cancelRecord closes the modal and clears selectedTechnique', () => {
    (component as any).showRecordModal = true;
    (component as any).selectedTechnique = { attackId: 'T1003.001' };
    component.cancelRecord();
    expect(component.showRecordModal).toBe(false);
    expect(component.selectedTechnique).toBeNull();
  });
});
