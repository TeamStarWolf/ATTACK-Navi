// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { UniversalSearchComponent } from './universal-search.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { D3fendService } from '../../services/d3fend.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { EngageService } from '../../services/engage.service';
import { AttackCveService } from '../../services/attack-cve.service';

describe('UniversalSearchComponent', () => {
  let component: UniversalSearchComponent;
  let fixture: ComponentFixture<UniversalSearchComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [UniversalSearchComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
            selectTechnique: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: D3fendService, useValue: { getAllTechniques: () => [] } },
        { provide: CARService, useValue: { getAll: () => [] } },
        { provide: AtomicService, useValue: { getTests: () => [] } },
        { provide: EngageService, useValue: { getActivities: () => [] } },
        { provide: AttackCveService, useValue: { searchCves: () => [] } },
      ],
    });
    fixture = TestBed.createComponent(UniversalSearchComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts closed', () => {
    expect(component).toBeTruthy();
    expect(component.open).toBe(false);
  });
});
