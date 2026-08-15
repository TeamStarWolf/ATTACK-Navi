// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
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
        provideRouter([]),
        { provide: FilterService, useValue: {
            setTechniqueQuery: jasmine.createSpy(),
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

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
