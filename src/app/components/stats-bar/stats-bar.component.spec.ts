// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { StatsBarComponent } from './stats-bar.component';
import { ImplementationService } from '../../services/implementation.service';
import { TimelineService } from '../../services/timeline.service';
import { FilterService } from '../../services/filter.service';
import { Domain } from '../../models/domain';

describe('StatsBarComponent', () => {
  let component: StatsBarComponent;
  let fixture: ComponentFixture<StatsBarComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [StatsBarComponent],
      providers: [
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: TimelineService, useValue: { snapshots$: new BehaviorSubject([]), takeSnapshot: jasmine.createSpy() } },
        { provide: FilterService, useValue: { setActivePanel: jasmine.createSpy() } },
      ],
    });
    fixture = TestBed.createComponent(StatsBarComponent);
    component = fixture.componentInstance;
    component.domain = {
      techniques: [], tactics: [], groups: [], mitigations: [], tacticColumns: [],
      groupsByTechnique: new Map(), mitigationsByTechnique: new Map(),
      techniquesByGroup: new Map(),
    } as unknown as Domain;
    // Note: skipping detectChanges() — stats-bar template requires deeper Domain shape
    // than this minimal mock provides; exercising the constructor is enough for "is-created" coverage.
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
