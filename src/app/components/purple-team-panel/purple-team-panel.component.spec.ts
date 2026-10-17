// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { PurpleTeamPanelComponent, PURPLE_DEPTH_FLOORS } from './purple-team-panel.component';
import { referenceDepthBand } from '../../models/reference-depth';
import { FilterService } from '../../services/filter.service';
import { D3fendService } from '../../services/d3fend.service';
import { EngageService } from '../../services/engage.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { DataService } from '../../services/data.service';

describe('PurpleTeamPanelComponent', () => {
  let component: PurpleTeamPanelComponent;
  let fixture: ComponentFixture<PurpleTeamPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [PurpleTeamPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            selectedTechnique$: new BehaviorSubject(null),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: D3fendService, useValue: { getCountermeasures: () => [] } },
        { provide: EngageService, useValue: { getActivities: () => [] } },
        { provide: CARService, useValue: { getAnalytics: () => [] } },
        { provide: AtomicService, useValue: { getTests: () => [] } },
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(PurpleTeamPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});

// E1.1: the purple-team 'excellent / good / partial / poor' grades are gone;
// the D3FEND + Engage + CAR + Atomic total is shown as a reference-depth band.
describe('PurpleTeamPanelComponent reference depth instead of grades (E1.1)', () => {
  // total = D3FEND + Engage + CAR + Atomic, all put on the D3FEND count here.
  const totals: Record<string, number> = { T0001: 0, T0002: 2, T0003: 5, T0004: 8, T0005: 12 };

  function render() {
    const techniques = Object.keys(totals).map(id => ({
      id: `attack-pattern--${id}`, attackId: id, name: `Technique ${id}`, tacticShortnames: ['execution'], isSubtechnique: false,
    }));
    TestBed.configureTestingModule({
      imports: [PurpleTeamPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            selectedTechnique$: new BehaviorSubject(null),
            selectTechnique: jasmine.createSpy('selectTechnique'),
            setHeatmapMode: jasmine.createSpy('setHeatmapMode'),
        }},
        { provide: D3fendService, useValue: { getCountermeasures: (id: string) => new Array(totals[id] ?? 0).fill({}) } },
        { provide: EngageService, useValue: { getActivities: () => [] } },
        { provide: CARService, useValue: { getAnalytics: () => [] } },
        { provide: AtomicService, useValue: { getTests: () => [] } },
        { provide: DataService, useValue: { domain$: new BehaviorSubject({ techniques }) } },
      ],
    });
    const fixture = TestBed.createComponent(PurpleTeamPanelComponent);
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement, component: fixture.componentInstance };
  }

  const text = (el: Element): string => (el.textContent ?? '').replace(/\s+/g, ' ').trim();

  it('keeps the old grade boundaries but names them as reference-depth bands', () => {
    expect([0, 1, 2, 3, 6, 7, 11, 12].map(n => referenceDepthBand(n, PURPLE_DEPTH_FLOORS)))
      .toEqual(['none', 'thin', 'thin', 'some', 'some', 'deep', 'deep', 'deepest']);
  });

  it('lists the least-mapped techniques with a reference-depth band, not a grade', () => {
    const { fixture, el, component } = render();
    component.setViewMode('gaps');
    fixture.detectChanges();
    const t = text(el);
    expect(t).toContain('Reference depth');
    expect(t).toContain('None mapped');
    expect(t).toContain('Thin');
    expect(t).not.toMatch(/\b(excellent|good|partial|poor)\b/i);
    expect(t).not.toMatch(/\bRating\b/);
    expect(t).not.toContain('Coverage Gaps');
    expect(t).not.toContain('Best Covered');
    expect(el.querySelector('[class*="rating-"]')).toBeNull();
    // Same membership as before: no content mapped, or a thin amount (1-2).
    const ids = Array.from(el.querySelectorAll('.gap-row:not(.header-row) .gt-id')).map(e => text(e));
    expect(ids).toEqual(['T0001', 'T0002']);
  });
});
