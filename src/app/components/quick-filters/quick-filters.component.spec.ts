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

  // Post-Phase-1 QA (R9c repair): the 'detection' heatmap this preset switches
  // on scores Sigma, CAR, D3FEND and Atomic, while 'detection content mapped'
  // elsewhere means Sigma or CAR only. The tooltip names the scored sources and
  // does not call them all detection content.
  it('the No Detection preset names the sources the detection heatmap scores', () => {
    const preset = component.presets.find(p => p.id === 'no-detection')!;
    expect(preset.heatmapMode).toBe('detection');
    expect(preset.description).toBe('Show techniques with no Sigma rules, CAR analytics, D3FEND countermeasures or Atomic tests mapped');
    expect(preset.description).not.toMatch(/detection content|coverage/i);
  });
});
