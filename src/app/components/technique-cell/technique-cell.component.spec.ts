// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { TechniqueCellComponent } from './technique-cell.component';
import { SettingsService } from '../../services/settings.service';
import { Technique } from '../../models/technique';
import { LENS_NA_COLOR } from '../../models/heatmap-modes';
import { type PostureCellVM, postureFill } from '../../models/posture/posture-ramp';
import { ThemeService } from '../../services/theme.service';
import { provenColor, statusStopFill } from '../../models/posture/lens-ramps';
import { myMarkFill } from '../../models/posture/gap';

const STUB_TECH = {
  id: 'attack-pattern--abc',
  attackId: 'T1059',
  name: 'Command and Scripting Interpreter',
  isSubtechnique: false,
  mitigationCount: 3,
  platforms: [],
  tacticShortnames: [],
} as unknown as Technique;

type CellDisplay = {
  exposureBadge: boolean; softwareBadge: boolean; campaignBadge: boolean;
  metricBadge: boolean; noteDot: boolean; annotationDot: boolean; watchIndicator: boolean;
  myMarks?: boolean;
};

function makeSettings(cellDisplay: Partial<CellDisplay> = {}): any {
  return {
    matrixCellSize: 'normal',
    showTechniqueIds: true,
    showTechniqueName: true,
    showMitigationCount: true,
    showSubtechniqueCount: true,
    colorblindSafe: false,
    heatmapColorTheme: 'default',
    cellDisplay: {
      exposureBadge: true, softwareBadge: true, campaignBadge: true,
      metricBadge: true, noteDot: true, annotationDot: true, watchIndicator: true,
      ...cellDisplay,
    },
  };
}

describe('TechniqueCellComponent', () => {
  let component: TechniqueCellComponent;
  let fixture: ComponentFixture<TechniqueCellComponent>;
  let settings$: BehaviorSubject<any>;

  function configure(cellDisplay: Partial<CellDisplay> = {}): void {
    settings$ = new BehaviorSubject<any>(makeSettings(cellDisplay));
    const stub = {
      settings$,
      get current() { return settings$.value; },
      getCoverageColors: () => ['#111111', '#222222', '#333333', '#444444', '#555555'],
    };
    TestBed.configureTestingModule({
      imports: [TechniqueCellComponent],
      providers: [{ provide: SettingsService, useValue: stub }],
    });
    fixture = TestBed.createComponent(TechniqueCellComponent);
    component = fixture.componentInstance;
    component.technique = STUB_TECH;
  }

  function render(inputs: Partial<TechniqueCellComponent> = {}): HTMLElement {
    Object.assign(component, inputs);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('is created', () => {
    configure();
    expect(component).toBeTruthy();
  });

  it('exposes a "selected" output emitter', () => {
    configure();
    expect(component.selected).toBeTruthy();
    expect(typeof component.selected.emit).toBe('function');
  });

  it('reads all cellDisplay flags into component fields on settings emission', () => {
    configure({ exposureBadge: false, metricBadge: false, watchIndicator: false });
    render();
    expect(component.showExposureBadge).toBe(false);
    expect(component.showMetricBadge).toBe(false);
    expect(component.showWatchIndicator).toBe(false);
    expect(component.showSoftwareBadge).toBe(true);
    expect(component.showCampaignBadge).toBe(true);
    expect(component.showNoteDot).toBe(true);
    expect(component.showAnnotationDot).toBe(true);
  });

  describe('exposure badge', () => {
    it('shows when the score is positive and the flag is true', () => {
      configure();
      const el = render({ exposureScore: 4 });
      expect(el.querySelector('.exposure-badge')).not.toBeNull();
    });
    it('hides when the flag is false', () => {
      configure({ exposureBadge: false });
      const el = render({ exposureScore: 4 });
      expect(el.querySelector('.exposure-badge')).toBeNull();
    });
  });

  describe('software badge', () => {
    it('shows when the score is positive and the flag is true', () => {
      configure();
      const el = render({ softwareScore: 2 });
      expect(el.querySelector('.software-badge')).not.toBeNull();
    });
    it('hides when the flag is false', () => {
      configure({ softwareBadge: false });
      const el = render({ softwareScore: 2 });
      expect(el.querySelector('.software-badge')).toBeNull();
    });
  });

  describe('campaign badge', () => {
    it('shows when the score is positive and the flag is true', () => {
      configure();
      const el = render({ campaignScore: 1 });
      expect(el.querySelector('.campaign-badge')).not.toBeNull();
    });
    it('hides when the flag is false', () => {
      configure({ campaignBadge: false });
      const el = render({ campaignScore: 1 });
      expect(el.querySelector('.campaign-badge')).toBeNull();
    });
  });

  describe('metric badge (mode-gated d3fend/atomic/cri)', () => {
    it('shows the d3fend badge in d3fend mode when the flag is true', () => {
      configure();
      const el = render({ heatmapMode: 'd3fend', d3fendScore: 3 });
      expect(el.querySelector('.d3fend-badge')).not.toBeNull();
    });
    it('hides the d3fend badge when metricBadge is false', () => {
      configure({ metricBadge: false });
      const el = render({ heatmapMode: 'd3fend', d3fendScore: 3 });
      expect(el.querySelector('.d3fend-badge')).toBeNull();
    });
    it('shows the atomic badge in atomic mode when the flag is true', () => {
      configure();
      const el = render({ heatmapMode: 'atomic', atomicScore: 2 });
      expect(el.querySelector('.atomic-badge')).not.toBeNull();
    });
    it('hides the atomic badge when metricBadge is false', () => {
      configure({ metricBadge: false });
      const el = render({ heatmapMode: 'atomic', atomicScore: 2 });
      expect(el.querySelector('.atomic-badge')).toBeNull();
    });
    it('keeps the per-mode guard: no d3fend badge outside d3fend mode even when metricBadge is true', () => {
      configure();
      const el = render({ heatmapMode: 'unified', d3fendScore: 3 });
      expect(el.querySelector('.d3fend-badge')).toBeNull();
    });
  });

  describe('note dot', () => {
    it('shows when hasNote and the flag is true', () => {
      configure();
      const el = render({ hasNote: true });
      expect(el.querySelector('.note-dot')).not.toBeNull();
    });
    it('hides when the flag is false', () => {
      configure({ noteDot: false });
      const el = render({ hasNote: true });
      expect(el.querySelector('.note-dot')).toBeNull();
    });
  });

  describe('annotation dot', () => {
    const ann = { color: 'red', note: 'flagged' } as any;
    it('shows when annotated and the flag is true', () => {
      configure();
      const el = render({ annotation: ann });
      expect(el.querySelector('.ann-red')).not.toBeNull();
    });
    it('hides when the flag is false', () => {
      configure({ annotationDot: false });
      const el = render({ annotation: ann });
      expect(el.querySelector('.ann-red')).toBeNull();
    });
  });

  describe('watch indicator', () => {
    it('shows when watched and the flag is true', () => {
      configure();
      const el = render({ isWatched: true });
      expect(el.querySelector('.watch-indicator')).not.toBeNull();
    });
    it('hides when the flag is false', () => {
      configure({ watchIndicator: false });
      const el = render({ isWatched: true });
      expect(el.querySelector('.watch-indicator')).toBeNull();
    });
  });

  it('renders every badge/indicator by default (no visual regression)', () => {
    configure();
    const el = render({
      exposureScore: 4, softwareScore: 2, campaignScore: 1,
      heatmapMode: 'd3fend', d3fendScore: 3,
      hasNote: true, isWatched: true,
      annotation: { color: 'red', note: 'flagged' } as any,
    });
    expect(el.querySelector('.exposure-badge')).not.toBeNull();
    expect(el.querySelector('.software-badge')).not.toBeNull();
    expect(el.querySelector('.campaign-badge')).not.toBeNull();
    expect(el.querySelector('.d3fend-badge')).not.toBeNull();
    expect(el.querySelector('.note-dot')).not.toBeNull();
    expect(el.querySelector('.ann-red')).not.toBeNull();
    expect(el.querySelector('.watch-indicator')).not.toBeNull();
  });

  // E1.2 PR 2: a lens with no data for the domain on screen paints the neutral
  // n/a hatch, never its zero colour, and shows no zero metric badge.
  describe('lens n/a in this domain (E1.2)', () => {
    function set(inputs: Record<string, unknown>): HTMLElement {
      for (const [k, v] of Object.entries(inputs)) fixture.componentRef.setInput(k, v);
      fixture.detectChanges();
      return fixture.nativeElement as HTMLElement;
    }

    it('paints the neutral n/a colour with the hatch class instead of the lens zero colour', () => {
      configure();
      set({ technique: STUB_TECH, heatmapMode: 'd3fend', d3fendScore: 0 });
      const zeroColour = component.bgColor;
      const el = set({ lensUnavailable: true });
      expect(component.bgColor).toBe(LENS_NA_COLOR);
      expect(component.bgColor).not.toBe(zeroColour);
      expect(el.querySelector('.cell')!.classList).toContain('lens-na');
    });

    it('shows no zero metric badge for an n/a lens', () => {
      configure();
      let el = set({ technique: STUB_TECH, heatmapMode: 'd3fend', d3fendScore: 0 });
      expect(el.querySelector('.d3fend-badge')).not.toBeNull();
      el = set({ lensUnavailable: true });
      expect(el.querySelector('.d3fend-badge')).toBeNull();
    });

    it('is off by default', () => {
      configure();
      const el = set({ technique: STUB_TECH, heatmapMode: 'coverage' });
      expect(component.lensUnavailable).toBeFalse();
      expect(el.querySelector('.cell')!.classList).not.toContain('lens-na');
    });
  });
});

// P2-13: the one new cell input. On a registry-hosted lens the cell paints the
// lens's own colour for its posture, draws the sub-state patterns and the check
// mark, and names the posture in its aria-label and tooltip; on every legacy
// lens the input is null and the cell renders exactly as before.
describe('TechniqueCellComponent: posture input (P2-13)', () => {
  let fixture: ComponentFixture<TechniqueCellComponent>;
  let component: TechniqueCellComponent;
  let settings$: BehaviorSubject<any>;
  let isLight$: BehaviorSubject<boolean>;

  const vm = (bucket: PostureCellVM['bucket'], subStates: PostureCellVM['subStates'] = [], label = 'Known: mapped'): PostureCellVM =>
    ({ bucket, subStates, proofScope: bucket === 'proven' || bucket === 'stale' ? 'own-run' : null, label });

  function set(inputs: Record<string, unknown>): HTMLElement {
    for (const [k, v] of Object.entries(inputs)) fixture.componentRef.setInput(k, v);
    fixture.detectChanges();
    return (fixture.nativeElement as HTMLElement).querySelector('.cell') as HTMLElement;
  }

  beforeEach(() => {
    settings$ = new BehaviorSubject<any>({ colorblindSafe: false, cellDisplay: null });
    isLight$ = new BehaviorSubject<boolean>(false);
    TestBed.configureTestingModule({
      imports: [TechniqueCellComponent],
      providers: [
        { provide: SettingsService, useValue: {
          settings$, get current() { return settings$.value; }, getCoverageColors: () => ['#111111', '#222222', '#333333', '#444444', '#555555'],
        } },
        { provide: ThemeService, useValue: { isLight$, get isLight() { return isLight$.value; } } },
      ],
    });
    fixture = TestBed.createComponent(TechniqueCellComponent);
    component = fixture.componentInstance;
  });

  it('paints the posture ramp fill for its bucket, in the current theme', () => {
    set({ technique: STUB_TECH, heatmapMode: 'posture', posture: vm('covered', [], 'Covered (self-attested)') });
    expect(component.bgColor).toBe(postureFill('covered', 'dark'));
    isLight$.next(true);
    expect(component.bgColor).toBe(postureFill('covered', 'light'));
  });

  it('ignores the colorblind-safe setting on Posture (safe by default)', () => {
    set({ technique: STUB_TECH, heatmapMode: 'posture', posture: vm('proven', [], 'Proven (your run)') });
    const before = component.bgColor;
    settings$.next({ colorblindSafe: true, cellDisplay: null });
    expect(component.bgColor).toBe(before);
  });

  it('draws the check mark on recorded detections and names the posture, stale included', () => {
    let el = set({ technique: STUB_TECH, heatmapMode: 'posture', posture: vm('stale', ['stale'], 'Proven (your run) (stale)') });
    expect(el.querySelector('.posture-check')).not.toBeNull();
    expect(el.getAttribute('aria-label')).toBe('T1059: Command and Scripting Interpreter, Proven (your run) (stale)');
    expect(el.getAttribute('aria-label')).toContain('stale');
    el = set({ posture: vm('known') });
    expect(el.querySelector('.posture-check')).toBeNull();
  });

  it('shows the posture label in its tooltip', () => {
    set({ technique: STUB_TECH, heatmapMode: 'posture', posture: vm('stale', ['stale'], 'Proven (your run) (stale)') });
    component.onMouseEnter(new MouseEvent('mouseenter', { clientX: 10, clientY: 10 }));
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('.tt-posture')!.textContent!.trim()).toBe('Proven (your run) (stale)');
  });

  it('marks partial, contradicted and not reproducible with their pattern classes', () => {
    let el = set({ technique: STUB_TECH, heatmapMode: 'posture', posture: vm('partial', ['partial']) });
    expect(el.classList).toContain('posture-partial');
    expect(component.bgColor).toBe(postureFill('known', 'dark'));
    el = set({ posture: vm('known', ['contradicted']) });
    expect(el.classList).toContain('posture-contradicted');
    expect(el.classList).not.toContain('posture-partial');
    el = set({ posture: vm('covered', ['not-reproducible']) });
    expect(el.classList).toContain('posture-not-reproducible');
  });

  it('paints the n/a hatch, not a posture colour, when the lens is unavailable', () => {
    const el = set({ technique: STUB_TECH, heatmapMode: 'posture', posture: vm('partial', ['partial']), lensUnavailable: true });
    expect(component.bgColor).toBe(LENS_NA_COLOR);
    expect(el.classList).not.toContain('posture-partial');
  });

  it('a legacy lens with no posture input renders as before: same colour, same aria-label, no posture marks', () => {
    const el = set({ technique: STUB_TECH, heatmapMode: 'coverage' });
    expect(component.bgColor).toBe('#444444');
    expect(el.getAttribute('aria-label')).toBe('T1059: Command and Scripting Interpreter');
    expect([...el.classList].filter(c => c.startsWith('posture-'))).toEqual([]);
    expect(el.querySelector('.posture-check')).toBeNull();
  });

  // P2-14: the status lens is registry-hosted on the Covered ordinal ramp, so
  // its status-colour cases moved here from the cell's own hex branch.
  const STATUS_CASES: Array<[string, number]> = [
    ['none', 0], ['not-started', 1], ['planned', 2], ['in-progress', 3], ['partial', 4], ['implemented', 5],
  ];
  for (const [stop, score] of STATUS_CASES) {
    it(`status lens: the ${stop} stop paints its Covered-ramp fill`, () => {
      const el = set({
        technique: STUB_TECH, heatmapMode: 'status',
        posture: { bucket: stop === 'partial' ? 'partial' : 'none', subStates: [], proofScope: null, label: `Status: ${stop}`, score, implStop: stop },
      });
      expect(component.bgColor).toBe(statusStopFill(stop as never, 'dark'));
      expect(el.classList.contains('posture-partial')).toBe(stop === 'partial');
      expect(el.querySelector('.posture-check')).toBeNull();
    });
  }

  it('status lens ignores the colorblind-safe setting (the ordinal ramp is safe by default)', () => {
    settings$.next({ colorblindSafe: true, cellDisplay: null });
    set({ technique: STUB_TECH, heatmapMode: 'status', posture: { bucket: 'none', subStates: [], proofScope: null, label: 'x', score: 5, implStop: 'implemented' } });
    expect(component.bgColor).toBe(statusStopFill('implemented', 'dark'));
  });

  it('coverage lens: the implementation dot names a partial implementation and dashes it', () => {
    const el = set({ technique: STUB_TECH, heatmapMode: 'coverage', implStatus: 'implemented', implPartialVia: 'M1038' });
    const dot = el.querySelector('.impl-dot') as HTMLElement;
    expect(dot.getAttribute('title')).toBe('Status: implemented, partial via M1038');
    expect(dot.classList).toContain('impl-dot-partial');
    set({ implPartialVia: null });
    expect(dot.getAttribute('title')).toBe('Status: implemented');
    expect(component.implDotColor).toBe(statusStopFill('implemented', 'dark'));
  });

  it("proven lens: the check mark on every scored cell, and the 'lab' badge only on range proof", () => {
    let el = set({ technique: STUB_TECH, heatmapMode: 'proven', posture: { bucket: 'proven', subStates: [], proofScope: 'range', label: 'x', score: 2 } });
    expect(component.bgColor).toBe(provenColor({ score: 2 }, { theme: 'dark', colorblindSafe: false }));
    expect(el.querySelector('.posture-check')).not.toBeNull();
    expect(el.querySelector('.proof-lab-badge')!.textContent!.trim()).toBe('lab');
    el = set({ posture: { bucket: 'proven', subStates: [], proofScope: 'own-run', label: 'x', score: 2 } });
    expect(el.querySelector('.proof-lab-badge')).toBeNull();
    el = set({ heatmapMode: 'posture', posture: { bucket: 'proven', subStates: [], proofScope: 'range', label: 'x' } });
    expect(el.querySelector('.proof-lab-badge')).toBeNull();
  });
});

// P2-17: the My marks bar and the Threat gaps outline sit over any lens fill.
describe('TechniqueCellComponent: My marks and Threat gaps (P2-17)', () => {
  let fixture: ComponentFixture<TechniqueCellComponent>;
  let component: TechniqueCellComponent;
  let settings$: BehaviorSubject<any>;
  let isLight$: BehaviorSubject<boolean>;

  function set(inputs: Record<string, unknown>): HTMLElement {
    for (const [k, v] of Object.entries(inputs)) fixture.componentRef.setInput(k, v);
    fixture.detectChanges();
    return (fixture.nativeElement as HTMLElement).querySelector('.cell') as HTMLElement;
  }

  beforeEach(() => {
    settings$ = new BehaviorSubject<any>(makeSettings());
    isLight$ = new BehaviorSubject<boolean>(false);
    TestBed.configureTestingModule({
      imports: [TechniqueCellComponent],
      providers: [
        { provide: SettingsService, useValue: {
          settings$, get current() { return settings$.value; }, getCoverageColors: () => ['#111111', '#222222', '#333333', '#444444', '#555555'],
        } },
        { provide: ThemeService, useValue: { isLight$, get isLight() { return isLight$.value; } } },
      ],
    });
    fixture = TestBed.createComponent(TechniqueCellComponent);
    component = fixture.componentInstance;
  });

  it('renders neither by default: same fill, same aria-label', () => {
    const el = set({ technique: STUB_TECH, heatmapMode: 'frequency' });
    expect(el.querySelector('.my-mark')).toBeNull();
    expect(el.querySelector('.threat-gap-outline')).toBeNull();
    expect(el.getAttribute('aria-label')).toBe('T1059: Command and Scripting Interpreter');
  });

  it('draws the bar with its bucket and posture token colour, over an unchanged lens fill', () => {
    let el = set({ technique: STUB_TECH, heatmapMode: 'frequency', frequencyScore: 2, maxFrequencyScore: 4 });
    const fill = component.bgColor;
    el = set({ myMark: 'covered' });
    const bar = el.querySelector('.my-mark') as HTMLElement;
    expect(bar.getAttribute('data-bucket')).toBe('covered');
    expect(bar.getAttribute('aria-hidden')).toBe('true');
    expect(bar.style.getPropertyValue('--my-mark-color')).toBe(myMarkFill('covered', 'dark'));
    expect(component.bgColor).toBe(fill);
    isLight$.next(true);
    fixture.detectChanges();
    expect(bar.style.getPropertyValue('--my-mark-color')).toBe(myMarkFill('covered', 'light'));
    el = set({ myMark: 'partial' });
    expect(el.querySelector('.my-mark')!.getAttribute('data-bucket')).toBe('partial');
    el = set({ myMark: null });
    expect(el.querySelector('.my-mark')).toBeNull();
  });

  it('hides the bar when AppSettings.cellDisplay.myMarks is false', () => {
    let el = set({ technique: STUB_TECH, heatmapMode: 'coverage', myMark: 'proven' });
    expect(el.querySelector('.my-mark')).not.toBeNull();
    settings$.next(makeSettings({ myMarks: false }));
    fixture.detectChanges();
    el = (fixture.nativeElement as HTMLElement).querySelector('.cell') as HTMLElement;
    expect(el.querySelector('.my-mark')).toBeNull();
  });

  it('draws the threat-gap outline and says so in the aria-label, fill unchanged', () => {
    let el = set({ technique: STUB_TECH, heatmapMode: 'frequency', frequencyScore: 1, maxFrequencyScore: 4 });
    const fill = component.bgColor;
    el = set({ threatGap: true });
    expect(el.querySelector('.threat-gap-outline')!.getAttribute('aria-hidden')).toBe('true');
    expect(el.getAttribute('aria-label')).toBe('T1059: Command and Scripting Interpreter, threat gap');
    expect(component.bgColor).toBe(fill);
  });
});
