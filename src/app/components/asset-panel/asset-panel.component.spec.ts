// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject, of } from 'rxjs';
import { AssetPanelComponent } from './asset-panel.component';
import { FilterService } from '../../services/filter.service';
import { AssetInventoryService } from '../../services/asset-inventory.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { CveService } from '../../services/cve.service';
import { DataService } from '../../services/data.service';

describe('AssetPanelComponent', () => {
  let component: AssetPanelComponent;
  let fixture: ComponentFixture<AssetPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AssetPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: AssetInventoryService, useValue: {
            assets$: new BehaviorSubject([]),
            exposureMap$: new BehaviorSubject(new Map()),
            getAll: () => [],
            addAsset: jasmine.createSpy(),
            removeAsset: jasmine.createSpy(),
            getExposureDetails: () => [],
        }},
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => [] } },
        { provide: CveService, useValue: { kev$: new BehaviorSubject([]), getCachedCves: () => [], fetchCveDetails: () => of([]) } },
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(AssetPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
