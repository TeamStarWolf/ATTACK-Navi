// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { QuickFiltersComponent } from './quick-filters.component';
import { FilterService } from '../../services/filter.service';
import { ImplementationService } from '../../services/implementation.service';
import { DataService } from '../../services/data.service';
import { AttackCveService } from '../../services/attack-cve.service';

describe('QuickFiltersComponent', () => {
  let component: QuickFiltersComponent;
  let fixture: ComponentFixture<QuickFiltersComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [QuickFiltersComponent],
      providers: [
        { provide: FilterService, useValue: {
            heatmapMode$: new BehaviorSubject('coverage'),
            implStatusFilter$: new BehaviorSubject(null),
            activePanel$: new BehaviorSubject(null),
            setHeatmapMode: jasmine.createSpy(),
            setImplStatusFilter: jasmine.createSpy(),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: AttackCveService, useValue: { getKevCvesForTechnique: () => [] } },
      ],
    });
    fixture = TestBed.createComponent(QuickFiltersComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
