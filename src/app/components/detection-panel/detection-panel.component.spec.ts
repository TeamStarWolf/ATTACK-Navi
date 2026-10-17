// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { DetectionPanelComponent, DETECTION_DEPTH_FLOORS } from './detection-panel.component';
import { REFERENCE_DEPTH_BANDS, referenceDepthBand } from '../../models/reference-depth';
import { DataService } from '../../services/data.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { D3fendService } from '../../services/d3fend.service';

describe('DetectionPanelComponent', () => {
  let component: DetectionPanelComponent;
  let fixture: ComponentFixture<DetectionPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [DetectionPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: CARService, useValue: { getAnalytics: () => [] } },
        { provide: AtomicService, useValue: { getTests: () => [] } },
        { provide: D3fendService, useValue: { getCountermeasures: () => [] } },
      ],
    });
    fixture = TestBed.createComponent(DetectionPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created with the overview tab active', () => {
    expect(component).toBeTruthy();
    expect(component.activeTab).toBe('overview');
  });
});

// E1.1: the Detect letter grades ('Excellent', 'High', 'Low', ...) are gone.
// CAR / Atomic / D3FEND counts are Known-rung reference content, so they are
// shown as reference-depth bands with the plan 4.1 Known wording.
describe('DetectionPanelComponent reference depth instead of grades (E1.1)', () => {
  // weighted score = CAR×3 + D3FEND×2 + Atomic×1
  const counts: Record<string, { car: number; atomic: number; d3fend: number }> = {
    T0001: { car: 0, atomic: 0, d3fend: 0 }, // 0  -> none
    T0002: { car: 0, atomic: 3, d3fend: 0 }, // 3  -> thin
    T0003: { car: 1, atomic: 1, d3fend: 0 }, // 4  -> some
    T0004: { car: 2, atomic: 0, d3fend: 0 }, // 6  -> some
    T0005: { car: 1, atomic: 0, d3fend: 2 }, // 7  -> deep
    T0006: { car: 3, atomic: 1, d3fend: 0 }, // 10 -> deepest
  };

  function render(): { el: HTMLElement; component: DetectionPanelComponent; fixture: ComponentFixture<DetectionPanelComponent> } {
    const techniques = Object.keys(counts).map(id => ({
      id: `attack-pattern--${id}`, attackId: id, name: `Technique ${id}`, tacticShortnames: ['execution'], isSubtechnique: false,
    }));
    TestBed.configureTestingModule({
      imports: [DetectionPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject({ techniques }) } },
        { provide: CARService, useValue: { getAnalytics: (id: string) => new Array(counts[id].car).fill({}) } },
        { provide: AtomicService, useValue: { getTestCount: (id: string) => counts[id].atomic } },
        { provide: D3fendService, useValue: { getCountermeasures: (id: string) => new Array(counts[id].d3fend).fill({}) } },
      ],
    });
    const fixture = TestBed.createComponent(DetectionPanelComponent);
    fixture.detectChanges();
    return { el: fixture.nativeElement as HTMLElement, component: fixture.componentInstance, fixture };
  }

  const text = (el: Element): string => (el.textContent ?? '').replace(/\s+/g, ' ').trim();

  it('keeps the old grade boundaries but names them as reference-depth bands', () => {
    const { component } = render();
    expect([0, 1, 3, 4, 6, 7, 9, 10, 40].map(s => component.scoreBracket(s)))
      .toEqual(['none', 'thin', 'thin', 'some', 'some', 'deep', 'deep', 'deepest', 'deepest']);
    expect(component.scoreDistribution).toEqual([1, 1, 2, 1, 1]);
  });

  it('shows no letter grade or grade word anywhere in the panel', () => {
    const { el, component, fixture } = render();
    for (const tab of ['overview', 'gaps', 'top', 'tactic'] as const) {
      component.setTab(tab);
      fixture.detectChanges();
      const t = text(el);
      expect(t).withContext(tab).not.toMatch(/\b(Excellent|Good|Poor|Fair|Low|Medium|High)\b/);
      expect(t).withContext(tab).not.toMatch(/\bGrade\b/i);
      expect(t).withContext(tab).not.toContain('Detection Coverage');
      expect(t).withContext(tab).not.toContain('No Detection');
      expect(t).withContext(tab).not.toContain('great work');
      // No grade-coloured class survives.
      expect(el.querySelector('[class*="excellent"], [class*="score-low"], [class*="score-high"], [class*="score-medium"]'))
        .withContext(tab).toBeNull();
    }
  });

  it('labels the summary bar with the Known wording from plan 4.1', () => {
    const { el } = render();
    const bar = text(el.querySelector('.stats-bar')!);
    expect(bar).toContain('Reference depth');
    expect(bar).toContain('None mapped (0)');
    expect(bar).toContain('Thin (1–3)');
    expect(bar).toContain('Some (4–6)');
    expect(bar).toContain('Deep (7–9)');
    expect(bar).toContain('Deepest (10+)');
    expect(text(el.querySelector('.panel-title')!)).toBe('Detection content available');
    expect(text(el.querySelector('.header-subtitle')!)).toContain('reference content mapped');
  });

  it('shares its bands with the reference-depth helper', () => {
    expect(REFERENCE_DEPTH_BANDS).toEqual(['none', 'thin', 'some', 'deep', 'deepest']);
    expect(referenceDepthBand(Number.NaN, DETECTION_DEPTH_FLOORS)).toBe('none');
    expect(referenceDepthBand(-5, DETECTION_DEPTH_FLOORS)).toBe('none');
  });
});
