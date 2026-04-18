// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { IRPlaybookPanelComponent } from './ir-playbook-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { IRPlaybookService } from '../../services/ir-playbook.service';

describe('IRPlaybookPanelComponent', () => {
  let component: IRPlaybookPanelComponent;
  let fixture: ComponentFixture<IRPlaybookPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [IRPlaybookPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: IRPlaybookService, useValue: { generatePlaybook: () => null } },
      ],
    });
    fixture = TestBed.createComponent(IRPlaybookPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts closed', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });

  it('search starts empty with no results', () => {
    expect(component.searchText).toBe('');
    expect(component.searchResults).toEqual([]);
    expect(component.playbook).toBeNull();
  });
});
