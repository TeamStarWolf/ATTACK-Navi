// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ChangelogPanelComponent } from './changelog-panel.component';
import { FilterService } from '../../services/filter.service';
import { ChangelogService } from '../../services/changelog.service';

describe('ChangelogPanelComponent', () => {
  let component: ChangelogPanelComponent;
  let fixture: ComponentFixture<ChangelogPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ChangelogPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: ChangelogService, useValue: {
            releases$: new BehaviorSubject([]),
            loaded$: new BehaviorSubject(true),
        }},
      ],
    });
    fixture = TestBed.createComponent(ChangelogPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('starts hidden until activePanel === changelog', () => {
    expect(component.visible).toBe(false);
  });

  it('starts with empty releases list', () => {
    expect(component.releases).toEqual([]);
  });

  it('expandedRelease starts null', () => {
    expect(component.expandedRelease).toBeNull();
  });
});
