// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { CoverageDiffPanelComponent } from './coverage-diff-panel.component';
import { TimelineService } from '../../services/timeline.service';

describe('CoverageDiffPanelComponent', () => {
  let component: CoverageDiffPanelComponent;
  let fixture: ComponentFixture<CoverageDiffPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [CoverageDiffPanelComponent],
      providers: [
        { provide: TimelineService, useValue: { snapshots$: new BehaviorSubject([]), getAll: () => [] } },
      ],
    });
    fixture = TestBed.createComponent(CoverageDiffPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
