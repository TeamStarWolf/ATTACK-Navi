// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { DatasourcePanelComponent } from './datasource-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';

describe('DatasourcePanelComponent', () => {
  let component: DatasourcePanelComponent;
  let fixture: ComponentFixture<DatasourcePanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [DatasourcePanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(DatasourcePanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts hidden', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });
});
