// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ComparisonPanelComponent } from './comparison-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';

describe('ComparisonPanelComponent', () => {
  let component: ComparisonPanelComponent;
  let fixture: ComponentFixture<ComparisonPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ComparisonPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(ComparisonPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts closed', () => {
    expect(component).toBeTruthy();
    expect(component.open).toBe(false);
  });

  it('groups list starts empty', () => {
    expect(component.groups).toEqual([]);
  });

  it('close() invokes filterService.setActivePanel(null)', () => {
    const fs = TestBed.inject(FilterService) as any;
    component.close();
    expect(fs.setActivePanel).toHaveBeenCalledWith(null);
  });
});
