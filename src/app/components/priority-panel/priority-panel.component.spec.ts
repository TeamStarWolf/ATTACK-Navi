// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { PriorityPanelComponent } from './priority-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { CveService } from '../../services/cve.service';
import { AtomicService } from '../../services/atomic.service';
import { SigmaService } from '../../services/sigma.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { NistMappingService } from '../../services/nist-mapping.service';

describe('PriorityPanelComponent', () => {
  let component: PriorityPanelComponent;
  let fixture: ComponentFixture<PriorityPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [PriorityPanelComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: CveService, useValue: { getCachedCves: () => [], loadKev: jasmine.createSpy(), kev$: new BehaviorSubject([]) } },
        { provide: AtomicService, useValue: { getTestCount: () => 0 } },
        { provide: SigmaService, useValue: { getRuleCount: () => 0 } },
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => [], getKevCvesForTechnique: () => [] } },
        { provide: NistMappingService, useValue: { getControlsForTechnique: () => [], loaded$: new BehaviorSubject(true) } },
      ],
    });
    fixture = TestBed.createComponent(PriorityPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts hidden', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });
});
