// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { KillchainPanelComponent } from './killchain-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';

describe('KillchainPanelComponent', () => {
  let component: KillchainPanelComponent;
  let fixture: ComponentFixture<KillchainPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [KillchainPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(KillchainPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts hidden', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });

  it('selectedTacticId starts null', () => {
    expect(component.selectedTacticId).toBeNull();
  });
});
