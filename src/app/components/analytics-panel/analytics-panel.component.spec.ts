// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { AnalyticsPanelComponent } from './analytics-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { CveService } from '../../services/cve.service';
import { SigmaService } from '../../services/sigma.service';
import { NistMappingService } from '../../services/nist-mapping.service';

describe('AnalyticsPanelComponent', () => {
  let component: AnalyticsPanelComponent;
  let fixture: ComponentFixture<AnalyticsPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AnalyticsPanelComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: CveService, useValue: { kev$: new BehaviorSubject([]), kevTechScores$: new BehaviorSubject(new Map()), getCachedCves: () => [] } },
        { provide: SigmaService, useValue: { getRuleCount: () => 0 } },
        { provide: NistMappingService, useValue: { loaded$: new BehaviorSubject(true), getControlsForTechnique: () => [] } },
      ],
    });
    fixture = TestBed.createComponent(AnalyticsPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
