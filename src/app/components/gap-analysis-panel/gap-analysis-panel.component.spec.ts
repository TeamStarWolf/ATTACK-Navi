// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { provideRouter } from '@angular/router';
import { GapAnalysisPanelComponent } from './gap-analysis-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { GapAnalysisService } from '../../services/gap-analysis.service';
import { LibraryService } from '../../services/library.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { ThreatProfileService } from '../../services/threat-profile.service';

describe('GapAnalysisPanelComponent', () => {
  let component: GapAnalysisPanelComponent;
  let fixture: ComponentFixture<GapAnalysisPanelComponent>;

  beforeEach(() => {
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
            generateReport: () => null,
            exportCsv: jasmine.createSpy(),
            exportPdf: jasmine.createSpy(),
            exportXlsx: jasmine.createSpy(),
        }},
        { provide: LibraryService, useValue: { getAssetsForTactic: () => [] }},
        // The shared picker (child) needs these:
        { provide: LibraryLayerService, useValue: { manifest$: new BehaviorSubject([]) }},
        { provide: ThreatProfileService, useValue: {
            get current() { return { source: profileSource }; },
            profile$: new BehaviorSubject({ source: profileSource }),
            setSource: jasmine.createSpy(),
            absentGroups: () => [],
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
});
