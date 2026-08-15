// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { TimelinePanelComponent } from './timeline-panel.component';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { TimelineService } from '../../services/timeline.service';

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
