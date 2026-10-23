// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture, fakeAsync, tick } from '@angular/core/testing';
import { BehaviorSubject, filter, take } from 'rxjs';
import { provideRouter } from '@angular/router';
import { GapAnalysisPanelComponent } from './gap-analysis-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { GapAnalysisService } from '../../services/gap-analysis.service';
import { LibraryService } from '../../services/library.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { AttackCveService } from '../../services/attack-cve.service';

describe('GapAnalysisPanelComponent', () => {
  let component: GapAnalysisPanelComponent;
  let fixture: ComponentFixture<GapAnalysisPanelComponent>;

  // The CTID mapping stub: outcome$ drives settled$() as the real service does.
  let outcome: BehaviorSubject<'pending' | 'loaded' | 'failed'>;
  let loaded: BehaviorSubject<boolean>;
  let generateReport: jasmine.Spy;

  beforeEach(() => {
    outcome = new BehaviorSubject<'pending' | 'loaded' | 'failed'>('pending');
    loaded = new BehaviorSubject(false);
    generateReport = jasmine.createSpy('generateReport').and.returnValue(null);
    const profileSource = { kind: 'top-groups' as const, n: 20 };
    TestBed.configureTestingModule({
      imports: [GapAnalysisPanelComponent],
      providers: [
        provideRouter([]),
        { provide: FilterService, useValue: {
            selectTechnique: jasmine.createSpy(),
            toggleThreatGroup: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: GapAnalysisService, useValue: {
            generateReport,
            exportCsv: jasmine.createSpy(),
            exportPdf: jasmine.createSpy(),
            exportXlsx: jasmine.createSpy(),
        }},
        { provide: LibraryService, useValue: { getAssetsForTactic: () => [] }},
        { provide: AttackCveService, useValue: {
            loadOnDemand: () => undefined,
            loaded$: loaded,
            settled$: () => outcome.pipe(filter(o => o !== 'pending'), take(1)),
        }},
        // The shared picker (child) needs these:
        { provide: LibraryLayerService, useValue: { manifest$: new BehaviorSubject([]) }},
        { provide: ThreatProfileService, useValue: {
            get current() { return { source: profileSource }; },
            profile$: new BehaviorSubject({ source: profileSource }),
            setSource: jasmine.createSpy(),
            absentGroups: () => [], unresolvedGroups: () => [],
        }},
      ],
    });
    fixture = TestBed.createComponent(GapAnalysisPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  describe('Generate and the on-demand CTID mapping (the KEV counts)', () => {
    const indicator = () => (fixture.nativeElement.querySelector('.generating-indicator')?.textContent ?? '').trim();

    beforeEach(() => {
      (component as unknown as { domain: unknown }).domain = { techniques: [] };
    });

    it('waits for the mapping and says so, then generates', fakeAsync(() => {
      component.generate();
      fixture.detectChanges();
      expect(indicator()).toBe('Loading the CVE mappings for the KEV counts...');
      tick(1000);
      expect(generateReport).not.toHaveBeenCalled();

      outcome.next('loaded');
      fixture.detectChanges();
      expect(indicator()).toBe('Analyzing techniques and computing gaps...');
      tick(0);
      expect(generateReport).toHaveBeenCalledTimes(1);
      expect(component.generating).toBeFalse();
    }));

    it('with the mapping already in, generates on the next tick as before', fakeAsync(() => {
      outcome.next('loaded');
      component.generate();
      fixture.detectChanges();
      expect(component.waitingForCves).toBeFalse();
      expect(indicator()).toBe('Analyzing techniques and computing gaps...');
      tick(0);
      expect(generateReport).toHaveBeenCalledTimes(1);
    }));

    it('a report generated after the mapping failed is generated again when a retry brings it in', fakeAsync(() => {
      generateReport.and.returnValue({ prioritizedGaps: [], detectionCoverage: {
        sigma: { covered: 0, total: 0 }, elastic: { covered: 0, total: 0 }, splunk: { covered: 0, total: 0 },
        m365: { covered: 0, total: 0 }, atomic: { covered: 0, total: 0 }, car: { covered: 0, total: 0 } } });
      outcome.next('failed');
      component.generate();
      tick(0);
      expect(generateReport).toHaveBeenCalledTimes(1);
      loaded.next(true);
      tick(0);
      expect(generateReport).toHaveBeenCalledTimes(2);
    }));
  });
});
