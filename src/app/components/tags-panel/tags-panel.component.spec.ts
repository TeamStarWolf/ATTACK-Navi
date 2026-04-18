// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { TagsPanelComponent } from './tags-panel.component';
import { FilterService } from '../../services/filter.service';
import { TaggingService } from '../../services/tagging.service';
import { DataService } from '../../services/data.service';

describe('TagsPanelComponent', () => {
  let component: TagsPanelComponent;
  let fixture: ComponentFixture<TagsPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TagsPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: TaggingService, useValue: {
            tagsByTechnique$: new BehaviorSubject(new Map()),
            tags$: new BehaviorSubject(new Map()),
            getAllUsedTags: () => [],
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(TagsPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts hidden', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });
});
