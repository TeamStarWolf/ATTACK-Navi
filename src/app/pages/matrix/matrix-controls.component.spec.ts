// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { MatrixControlsComponent } from './matrix-controls.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { MatrixControlService } from '../../services/matrix-control.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { HEATMAP_MODES } from '../../models/heatmap-modes';

describe('MatrixControlsComponent', () => {
  let component: MatrixControlsComponent;
  let fixture: ComponentFixture<MatrixControlsComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [MatrixControlsComponent],
      providers: [
        { provide: FilterService, useValue: {
            activeMitigationFilters$: new BehaviorSubject([]),
            techniqueQuery$: new BehaviorSubject(''),
            searchScope$: new BehaviorSubject('name'),
            searchFilterMode$: new BehaviorSubject(false),
            platformMulti$: new BehaviorSubject(new Set()),
            activeDataSource$: new BehaviorSubject(null),
            implStatusFilter$: new BehaviorSubject(null),
            heatmapMode$: new BehaviorSubject('coverage'),
            sortMode$: new BehaviorSubject('alpha'),
            dimUncovered$: new BehaviorSubject(false),
            activeThreatGroupIds$: new BehaviorSubject(new Set()),
            setTechniqueQuery: jasmine.createSpy(),
            setHeatmapMode: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: MatrixControlService, useValue: {
            multiSelectMode$: new BehaviorSubject(false),
            expandAll: jasmine.createSpy(),
            collapseAll: jasmine.createSpy(),
            toggleMultiSelect: jasmine.createSpy(),
            requestGapView: jasmine.createSpy(),
        }},
        { provide: AttackCveService, useValue: { getMappingForCve: () => null }},
      ],
    });
    fixture = TestBed.createComponent(MatrixControlsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('renders the technique search with the canonical placeholder', () => {
    const input = fixture.nativeElement.querySelector('input[placeholder*="Search techniques"]');
    expect(input).toBeTruthy();
  });

  it('heatmap dropdown lists every mode from the single source of truth', () => {
    component.toggleViewMenu();
    fixture.detectChanges();
    const buttons = fixture.nativeElement.querySelectorAll('.heatmap-mode-btn');
    expect(buttons.length).toBe(HEATMAP_MODES.length);
  });

  it('gap view request goes through MatrixControlService', () => {
    const svc = TestBed.inject(MatrixControlService) as any;
    component.onGapView();
    expect(svc.requestGapView).toHaveBeenCalled();
  });

  it('trigger label uses the short name from heatmap-modes', () => {
    expect(component.heatmapShort).toBe('Coverage');
  });
});
