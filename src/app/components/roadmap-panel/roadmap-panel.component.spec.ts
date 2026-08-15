// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { RoadmapPanelComponent } from './roadmap-panel.component';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { AttackCveService } from '../../services/attack-cve.service';

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
