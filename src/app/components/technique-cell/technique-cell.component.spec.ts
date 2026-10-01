// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { TechniqueCellComponent } from './technique-cell.component';
import { SettingsService } from '../../services/settings.service';
import { Technique } from '../../models/technique';

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
});
