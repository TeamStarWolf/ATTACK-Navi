// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { ControlsPanelComponent } from './controls-panel.component';
import { ControlsService } from '../../services/controls.service';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';

describe('ControlsPanelComponent', () => {
  let component: ControlsPanelComponent;
  let fixture: ComponentFixture<ControlsPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ControlsPanelComponent],
      providers: [
        provideRouter([]),
        { provide: ControlsService, useValue: { controls$: new BehaviorSubject([]) } },
        { provide: FilterService, useValue: {
            filterByMitigation: jasmine.createSpy(),
            addMitigationFilter: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(ControlsPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
