// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { LegendComponent } from './legend.component';
import { FilterService, HeatmapMode } from '../../services/filter.service';
import { AttackDomain, DataService } from '../../services/data.service';
import { SettingsService } from '../../services/settings.service';
import { heatmapModeDef } from '../../models/heatmap-modes';

describe('LegendComponent', () => {
  let component: LegendComponent;
  let fixture: ComponentFixture<LegendComponent>;
  let heatmapMode$: BehaviorSubject<HeatmapMode>;
  let currentDomain$: BehaviorSubject<AttackDomain>;
  let domain$: BehaviorSubject<{ attackVersion: string } | null>;
  let freshness$: BehaviorSubject<'bundled' | 'cached' | 'live' | null>;

  const text = (sel: string): string => (fixture.nativeElement.querySelector(sel)?.textContent ?? '').trim();
  const stopLabels = (): string[] =>
    Array.from(fixture.nativeElement.querySelectorAll('.legend-stop')).map((el: any) => el.querySelector('.stop-label').textContent.trim());
  const show = (mode: HeatmapMode): void => { heatmapMode$.next(mode); fixture.detectChanges(); };

  beforeEach(async () => {
    localStorage.removeItem('mitre-nav-settings-v1');
    heatmapMode$ = new BehaviorSubject<HeatmapMode>('coverage');
    currentDomain$ = new BehaviorSubject<AttackDomain>('enterprise');
    domain$ = new BehaviorSubject<{ attackVersion: string } | null>({ attackVersion: '19.2' });
    freshness$ = new BehaviorSubject<'bundled' | 'cached' | 'live' | null>('bundled');

    await TestBed.configureTestingModule({
      imports: [LegendComponent],
      providers: [
        { provide: FilterService, useValue: { heatmapMode$: heatmapMode$.asObservable() } },
        { provide: DataService, useValue: { currentDomain$, domain$, freshness$ } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(LegendComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render correct color stops for coverage mode', () => {
    expect(stopLabels()).toEqual(['0', '1', '2', '3', '4+']);
  });

  it('should show the mode label from the registry', () => {
    expect(text('.legend-label')).toBe('Mitigations mapped');
  });

  it('shows the rung badge and the lens question (4.7 title)', () => {
    expect(text('.rung-badge')).toBe('KNOWN');
    expect(text('.legend-question')).toBe(heatmapModeDef('coverage')!.question);
    show('status');
    expect(text('.rung-badge')).toBe('COVERED self-attested');
    show('frequency');
    expect(text('.rung-badge')).toBe('THREAT');
    show('my-exposure');
    expect(text('.rung-badge')).toBe('EXPOSURE');
  });

  it('shows the vintage: the loaded ATT&CK release and where it came from', () => {
    expect(text('.legend-sources')).toBe('Sources: Enterprise ATT&CK 19.2 (bundled)');
    domain$.next({ attackVersion: '18.1' });
    freshness$.next('cached');
    fixture.detectChanges();
    expect(text('.legend-sources')).toBe('Sources: Enterprise ATT&CK 18.1 (cached)');
  });

  it('shows pinned and mapped-vs versions for third-party sources, and unpinned ones as unpinned', () => {
    show('nist');
    expect(text('.legend-sources')).toContain('CTID NIST 800-53 (rev5; mapped vs ATT&CK 16.1)');
    show('sigma');
    expect(text('.legend-sources')).toContain('SigmaHQ coverage (fetched at runtime, unpinned)');
  });

  it('states what zero means for the lens', () => {
    expect(text('.legend-zero')).toBe(heatmapModeDef('coverage')!.zeroMeaning);
    expect(text('.legend-zero')).toContain('not safe');
  });

  it('shows the n/a domain line only when the lens has no data for the current domain', () => {
    expect(fixture.nativeElement.querySelector('.legend-domain')).toBeNull();
    currentDomain$.next('ics');
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.legend-domain')).toBeNull(); // Mitigations has ICS data
    show('sigma');
    expect(text('.legend-domain')).toBe('n/a for ICS ATT&CK (no source data)');
  });

  it('labels relative ramps as shares of the highest score, not invented counts', () => {
    show('exposure');
    expect(text('.legend-label')).toBe('Selected adversaries');
    expect(stopLabels()).toEqual(['0', '<25%', '25-49%', '50-74%', '75-100%']);
    expect(text('.scale-arrow')).toBe('share of the highest score');
  });

  it('shows the six unified bands the renderer paints', () => {
    show('unified');
    expect(stopLabels()).toEqual(['0-15', '16-30', '31-50', '51-65', '66-80', '81-100']);
  });

  it('should show a scale note for count modes', () => {
    expect(text('.scale-arrow')).toBe('fewer to more');
  });

  it('should not show a scale note for categorical mode (status)', () => {
    show('status');
    expect(fixture.nativeElement.querySelector('.scale-arrow')).toBeFalsy();
    expect(stopLabels()).toEqual(['none', 'not started', 'in progress', 'planned', 'implemented']);
  });

  it('paints coverage swatches from the heatmap colour theme, as the cells do', () => {
    const swatches = fixture.nativeElement.querySelectorAll('.legend-stop .swatch');
    expect(swatches.length).toBe(5);
    expect(swatches[0].style.background).toContain('rgb(211, 47, 47)');
    expect(swatches[4].style.background).toContain('rgb(27, 94, 32)');
  });

  it('mirrors the colorblind-safe unified ramp', () => {
    TestBed.inject(SettingsService).update({ colorblindSafe: true });
    show('unified');
    const swatches = fixture.nativeElement.querySelectorAll('.legend-stop .swatch');
    expect(swatches.length).toBe(6);
    expect(swatches[0].style.background).toContain('rgb(68, 1, 84)');
    expect(swatches[5].style.background).toContain('rgb(253, 231, 37)');
    TestBed.inject(SettingsService).update({ colorblindSafe: false });
  });

  // E1.1 relabel (plan 4.1 / 4.7): legend titles use the Known vocabulary.
  const RELABELLED: Array<[HeatmapMode, string]> = [
    ['coverage', 'Mitigations mapped'],
    ['unified', 'Reference depth'],
    ['detection', 'Detection content available'],
    ['exposure', 'Selected adversaries'],
    ['risk', 'Threat-weighted mapping gap'],
    ['wazuh', 'Wazuh stock rules (curated)'],
  ];
  for (const [mode, title] of RELABELLED) {
    it(`titles the ${mode} legend '${title}'`, () => {
      heatmapMode$.next(mode);
      fixture.detectChanges();
      expect(fixture.nativeElement.querySelector('.legend-label').textContent.trim()).toBe(title);
    });
  }

  it('labels the Reference depth stops without posture words', () => {
    heatmapMode$.next('unified');
    fixture.detectChanges();
    const labels = Array.from(fixture.nativeElement.querySelectorAll('.stop-label'))
      .map((el: any) => el.textContent.trim());
    // E1.2: the legend shows the six numeric bands the renderer paints (4.7),
    // so the stops carry no posture words at all.
    expect(labels).toEqual(['0-15', '16-30', '31-50', '51-65', '66-80', '81-100']);
    for (const banned of ['covered', 'exposed', 'protected', 'strong']) {
      expect(labels).not.toContain(banned);
    }
  });
});
