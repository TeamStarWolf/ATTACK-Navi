// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { RoadmapPanelComponent } from './roadmap-panel.component';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { EnrichmentService } from '../../services/enrichment.service';
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
        { provide: EnrichmentService, useValue: { mappedRollup: () => ({ overall: { total: 0, mapped: 0, pct: 0 }, byTactic: [] }) } },
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
