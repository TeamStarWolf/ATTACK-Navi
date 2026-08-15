// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ChangelogPanelComponent } from './changelog-panel.component';
import { ChangelogService } from '../../services/changelog.service';
import { DataService } from '../../services/data.service';

describe('ChangelogPanelComponent', () => {
  let component: ChangelogPanelComponent;
  let fixture: ComponentFixture<ChangelogPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ChangelogPanelComponent],
      providers: [
        { provide: ChangelogService, useValue: {
            releases$: new BehaviorSubject([]),
            loaded$: new BehaviorSubject(true),
        }},
        { provide: DataService, useValue: { getCurrentDomain: () => null }},
      ],
    });
    fixture = TestBed.createComponent(ChangelogPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('starts with empty releases list', () => {
    expect(component.releases).toEqual([]);
  });

  it('expandedRelease starts null', () => {
    expect(component.expandedRelease).toBeNull();
  });
});
