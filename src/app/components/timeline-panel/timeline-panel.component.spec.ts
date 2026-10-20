// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { TimelinePanelComponent } from './timeline-panel.component';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { TimelineService } from '../../services/timeline.service';
import { makePostureStub, postureStubProvider } from '../../testing/posture-stub';

describe('TimelinePanelComponent', () => {
  let component: TimelinePanelComponent;
  let fixture: ComponentFixture<TimelinePanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TimelinePanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: TimelineService, useValue: { snapshots$: new BehaviorSubject([]), getAll: () => [] }},
        // P2-08: snapshots and the posture line read PostureService.rollup.
        postureStubProvider(makePostureStub(() => null)),
      ],
    });
    fixture = TestBed.createComponent(TimelinePanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
