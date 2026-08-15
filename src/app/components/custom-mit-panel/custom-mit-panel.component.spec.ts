// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { CustomMitPanelComponent } from './custom-mit-panel.component';
import { CustomMitigationService } from '../../services/custom-mitigation.service';
import { DataService } from '../../services/data.service';

describe('CustomMitPanelComponent', () => {
  let component: CustomMitPanelComponent;
  let fixture: ComponentFixture<CustomMitPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [CustomMitPanelComponent],
      providers: [
        { provide: CustomMitigationService, useValue: { mitigations$: new BehaviorSubject([]), all: [] } },
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(CustomMitPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
