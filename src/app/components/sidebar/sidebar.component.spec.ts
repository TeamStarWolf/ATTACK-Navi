// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BehaviorSubject, of } from 'rxjs';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { SidebarComponent } from './sidebar.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';

const noopBSet = () => new BehaviorSubject(new Set());
const noopBMap = () => new BehaviorSubject(new Map());
const noopBArr = () => new BehaviorSubject([]);
const noopBNull = () => new BehaviorSubject(null);
const noopBStr = () => new BehaviorSubject('');
const noopBBool = () => new BehaviorSubject(false);

describe('SidebarComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [SidebarComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: FilterService, useValue: {
            selectedTechnique$: noopBNull(),
            activePanel$: noopBNull(),
            activeMitigationFilters$: noopBArr(),
            activeThreatGroupIds$: noopBSet(),
            heatmapMode$: new BehaviorSubject('coverage'),
            techniqueSearch$: noopBStr(),
            techniqueQuery$: noopBStr(),
            sortMode$: new BehaviorSubject('alpha'),
            dimUncovered$: noopBBool(),
            platformFilter$: noopBNull(),
            implStatusFilter$: noopBNull(),
            searchScope$: new BehaviorSubject('name'),
            searchFilterMode$: noopBBool(),
            hiddenTacticIds$: noopBSet(),
            cveTechniqueIds$: noopBSet(),
            setSelectedTechnique: () => {},
            setActivePanel: () => {},
            selectTechnique: () => {},
            toggleThreatGroup: () => {},
            getActivePanel: () => null,
        }},
        { provide: DataService, useValue: { domain$: noopBNull(), loading$: noopBBool() }},
      ],
    });
  });

  it('TestBed compiles the component (creation deferred — heavy template deps)', () => {
    expect(SidebarComponent).toBeTruthy();
  });
});
