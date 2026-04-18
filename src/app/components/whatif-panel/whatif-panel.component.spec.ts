// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { WhatifPanelComponent } from './whatif-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';

describe('WhatifPanelComponent', () => {
  let component: WhatifPanelComponent;
  let fixture: ComponentFixture<WhatifPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [WhatifPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            whatIfMitigationIds$: new BehaviorSubject(new Set()),
            setActivePanel: jasmine.createSpy(),
            setWhatIfMitigationIds: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
      ],
    });
    fixture = TestBed.createComponent(WhatifPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts hidden', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });
});
