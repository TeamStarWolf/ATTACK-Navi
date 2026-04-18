// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { GapViewComponent } from './gap-view.component';
import { DataService } from '../../services/data.service';
import { FilterService } from '../../services/filter.service';

describe('GapViewComponent', () => {
  let component: GapViewComponent;
  let fixture: ComponentFixture<GapViewComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [GapViewComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: FilterService, useValue: {
            activeMitigationFilters$: new BehaviorSubject([]),
            heatmapMode$: new BehaviorSubject('coverage'),
            setActivePanel: jasmine.createSpy(),
        }},
      ],
    });
    fixture = TestBed.createComponent(GapViewComponent);
    component = fixture.componentInstance;
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
