// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { CustomMitPanelComponent } from './custom-mit-panel.component';
import { FilterService } from '../../services/filter.service';
import { CustomMitigationService } from '../../services/custom-mitigation.service';
import { DataService } from '../../services/data.service';

describe('CustomMitPanelComponent', () => {
  let component: CustomMitPanelComponent;
  let fixture: ComponentFixture<CustomMitPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [CustomMitPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: CustomMitigationService, useValue: { mitigations$: new BehaviorSubject([]), all: [] } },
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(CustomMitPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts hidden', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });
});
