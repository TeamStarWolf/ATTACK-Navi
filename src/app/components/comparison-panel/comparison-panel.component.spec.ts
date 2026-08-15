// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
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
        provideRouter([]),
        { provide: FilterService, useValue: {
            selectTechnique: jasmine.createSpy(),
            toggleThreatGroup: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(ComparisonPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('groups list starts empty', () => {
    expect(component.groups).toEqual([]);
  });
});
