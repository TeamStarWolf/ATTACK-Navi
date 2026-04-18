// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { SoftwarePanelComponent } from './software-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';

describe('SoftwarePanelComponent', () => {
  let component: SoftwarePanelComponent;
  let fixture: ComponentFixture<SoftwarePanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [SoftwarePanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            activeSoftwareIds$: new BehaviorSubject(new Set()),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(SoftwarePanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts closed', () => {
    expect(component).toBeTruthy();
    expect(component.open).toBe(false);
  });

  it('exposes activeSoftwareIds initialized as empty Set', () => {
    expect(component.activeSoftwareIds.size).toBe(0);
  });
});
