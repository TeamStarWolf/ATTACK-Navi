// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { RoadmapPanelComponent } from './roadmap-panel.component';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { makePostureStub, postureStubProvider } from '../../testing/posture-stub';

describe('RoadmapPanelComponent', () => {
  let component: RoadmapPanelComponent;
  let fixture: ComponentFixture<RoadmapPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [RoadmapPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => [] } },
        // P2-08: the Known count and the posture line read PostureService.rollup.
        postureStubProvider(makePostureStub(() => null)),
      ],
    });
    fixture = TestBed.createComponent(RoadmapPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
