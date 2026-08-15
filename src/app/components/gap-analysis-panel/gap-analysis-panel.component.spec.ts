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

describe('GapAnalysisPanelComponent', () => {
  let component: GapAnalysisPanelComponent;
  let fixture: ComponentFixture<GapAnalysisPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [GapAnalysisPanelComponent],
      providers: [
        provideRouter([]),
        { provide: FilterService, useValue: {
            selectTechnique: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: GapAnalysisService, useValue: {
            generateReport: () => null,
            exportCsv: jasmine.createSpy(),
            exportPdf: jasmine.createSpy(),
            exportXlsx: jasmine.createSpy(),
        }},
        { provide: LibraryService, useValue: { getAssetsForTactic: () => [] }},
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
