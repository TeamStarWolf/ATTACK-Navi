// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { EmulationPlanPanelComponent } from './emulation-plan-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { EmulationPlanService } from '../../services/emulation-plan.service';
import { LibraryService } from '../../services/library.service';

describe('EmulationPlanPanelComponent', () => {
  let component: EmulationPlanPanelComponent;
  let fixture: ComponentFixture<EmulationPlanPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [EmulationPlanPanelComponent],
      providers: [
        provideRouter([]),
        { provide: FilterService, useValue: {} },
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: EmulationPlanService, useValue: {
            generatePlan: () => null,
            getSavedPlans: () => [],
            savePlan: jasmine.createSpy(),
            deletePlan: jasmine.createSpy(),
        }},
        { provide: LibraryService, useValue: { getAssetsForTactic: () => [] }},
      ],
    });
    fixture = TestBed.createComponent(EmulationPlanPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('exposes 6 quick-pick threat actors', () => {
    expect(component.quickPicks.length).toBe(6);
    expect(component.quickPicks).toContain('APT29');
  });

  it('starts with no selectedGroup or plan', () => {
    expect(component.selectedGroup).toBeNull();
    expect(component.plan).toBeNull();
  });
});
