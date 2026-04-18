// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ActorProfilePanelComponent } from './actor-profile-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';

describe('ActorProfilePanelComponent', () => {
  let component: ActorProfilePanelComponent;
  let fixture: ComponentFixture<ActorProfilePanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ActorProfilePanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
      ],
    });
    fixture = TestBed.createComponent(ActorProfilePanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts closed', () => {
    expect(component).toBeTruthy();
    expect(component.open).toBe(false);
  });

  it('searchText starts empty', () => {
    expect(component.searchText).toBe('');
  });
});
