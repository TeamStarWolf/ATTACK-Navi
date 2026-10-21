// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { LegendComponent } from './legend.component';
import { FilterService, HeatmapMode } from '../../services/filter.service';
import { AttackDomain, DataService } from '../../services/data.service';
import { SettingsService } from '../../services/settings.service';
import { heatmapModeDef, lensAvailability } from '../../models/heatmap-modes';
import { LensCardService } from '../../services/lens-card.service';
import { ThemeService } from '../../services/theme.service';
import { PostureStub, makePostureStub, postureStubProvider } from '../../testing/posture-stub';
import { POSTURE_BUCKETS, postureFill, postureLegendStops } from '../../models/posture/posture-ramp';
import type { Domain } from '../../models/domain';

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

  // E1.2 PR 2: the legend states why a lens is n/a and opens its definition card.
  it('states the reason under the n/a domain line', () => {
    currentDomain$.next('ics');
    show('sigma');
    expect(text('.legend-na-reason')).toBe(lensAvailability(heatmapModeDef('sigma')!, 'ics').reason!);
    currentDomain$.next('enterprise');
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.legend-na-reason')).toBeNull();
  });

  it("opens the active lens's definition card from 'What is this lens?'", () => {
    const cards = TestBed.inject(LensCardService);
    show('kev');
    const btn = fixture.nativeElement.querySelector('.lens-help-btn') as HTMLButtonElement;
    expect(btn.textContent!.trim()).toBe('What is this lens?');
    expect(btn.getAttribute('aria-haspopup')).toBe('dialog');
    expect(btn.getAttribute('aria-label')).toBe('What is the KEV lens?');
    btn.click();
    expect(cards.openMode()).toBe('kev');
  });
});

// P2-13: the Posture lens's legend shows its stops, coloured by the lens's own
// colour function in the current theme. Its stop labels and its question name
// Covered and Proven, so they render only under hasOwnerWords(); a fresh
// profile sees the ramp and 'No data of yours recorded' (§1.3).
describe('LegendComponent: the Posture lens (P2-13)', () => {
  let fixture: ComponentFixture<LegendComponent>;
  let heatmapMode$: BehaviorSubject<HeatmapMode>;
  let isLight$: BehaviorSubject<boolean>;
  let posture: PostureStub;

  const DOMAIN = {
    techniques: [
      { id: 'attack-pattern--1', attackId: 'T1001', isSubtechnique: false, mitigationCount: 2 },
      { id: 'attack-pattern--2', attackId: 'T1002', isSubtechnique: false, mitigationCount: 0 },
    ],
    tacticColumns: [],
  } as unknown as Domain;

  const el = (): HTMLElement => fixture.nativeElement as HTMLElement;
  const render = (): void => fixture.detectChanges();

  /** Every string a reader sees or hears: the text, and title, aria-label, placeholder and alt. */
  function visibleStrings(): string[] {
    const out = [el().textContent ?? ''];
    for (const node of Array.from(el().querySelectorAll('*'))) {
      for (const attr of ['title', 'aria-label', 'placeholder', 'alt']) {
        const v = node.getAttribute(attr);
        if (v) out.push(v);
      }
    }
    return out;
  }

  beforeEach(async () => {
    localStorage.removeItem('mitre-nav-settings-v1');
    heatmapMode$ = new BehaviorSubject<HeatmapMode>('posture');
    isLight$ = new BehaviorSubject<boolean>(false);
    posture = makePostureStub(() => DOMAIN);
    await TestBed.configureTestingModule({
      imports: [LegendComponent],
      providers: [
        { provide: FilterService, useValue: { heatmapMode$: heatmapMode$.asObservable() } },
        { provide: DataService, useValue: {
          currentDomain$: new BehaviorSubject<AttackDomain>('enterprise'),
          domain$: new BehaviorSubject({ attackVersion: '19.2' }),
          freshness$: new BehaviorSubject('bundled'),
        } },
        { provide: ThemeService, useValue: { isLight$, get isLight() { return isLight$.value; } } },
        postureStubProvider(posture),
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(LegendComponent);
    render();
  });

  it('fresh profile: shows the ramp and "No data of yours recorded", and no covered or proven string', () => {
    expect(posture.ownerWords()).toBeFalse();
    expect(el().querySelectorAll('.posture-stop .swatch').length).toBe(8);
    expect(el().querySelectorAll('.stop-label').length).toBe(0);
    expect(el().querySelector('.legend-no-data')!.textContent!.trim()).toBe('No data of yours recorded');
    expect(el().querySelector('.legend-question')).toBeNull();
    expect(el().querySelector('.rung-badge')!.textContent!.trim()).toBe('MIXED');
    expect(el().querySelector('.legend-label')!.textContent!.trim()).toBe('Posture');
    const hits = visibleStrings().filter(v => /\b(?:covered|proven)\b/i.test(v));
    expect(hits).toEqual([]);
  });

  it('with owner data: names every stop from the vocabulary and asks the lens question', () => {
    posture.set({ T1001: 'covered', T1002: 'proven' });
    render();
    expect(posture.ownerWords()).toBeTrue();
    const labels = Array.from(el().querySelectorAll('.posture-stop .stop-label')).map(n => n.textContent!.trim());
    expect(labels).toEqual(postureLegendStops('dark').map(s => s.label));
    expect(el().querySelector('.legend-question')!.textContent!.trim()).toBe(heatmapModeDef('posture')!.question);
    expect(el().querySelector('.legend-no-data')).toBeNull();
  });

  it('fills the swatches through the lens colour function, in the current theme', () => {
    const fills = (): string[] => Array.from(el().querySelectorAll<HTMLElement>('.posture-stop .swatch'))
      .slice(0, POSTURE_BUCKETS.length).map(n => n.style.backgroundColor);
    const asRgb = (hex: string): string => {
      const n = parseInt(hex.slice(1), 16);
      return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
    };
    expect(fills()).toEqual(POSTURE_BUCKETS.map(b => asRgb(postureFill(b, 'dark'))));
    isLight$.next(true);
    render();
    expect(fills()).toEqual(POSTURE_BUCKETS.map(b => asRgb(postureFill(b, 'light'))));
  });

  it('marks partial, contradicted and not reproducible by pattern class, and the recorded detections with a check', () => {
    const swatch = (key: string) => el().querySelector(`.posture-stop[data-stop="${key}"] .swatch`)!;
    expect(swatch('partial').classList).toContain('posture-partial');
    expect(swatch('contradicted').classList).toContain('posture-contradicted');
    expect(swatch('not-reproducible').classList).toContain('posture-not-reproducible');
    expect(swatch('covered').classList).not.toContain('posture-partial');
    expect(swatch('proven').querySelector('.swatch-check')).not.toBeNull();
    expect(swatch('stale').querySelector('.swatch-check')).not.toBeNull();
    expect(swatch('covered').querySelector('.swatch-check')).toBeNull();
  });

  it('says how many proofs go stale within 7 days, only when some do', () => {
    expect(el().querySelector('.legend-expiring')).toBeNull();
    posture.set({ T1001: 'proven' });
    posture.setExpiringSoon(3);
    render();
    expect(el().querySelector('.legend-expiring')!.textContent!.trim()).toBe('3 proofs go stale within 7 days');
    posture.setExpiringSoon(1);
    render();
    expect(el().querySelector('.legend-expiring')!.textContent!.trim()).toBe('1 proof goes stale within 7 days');
    posture.setExpiringSoon(0);
    render();
    expect(el().querySelector('.legend-expiring')).toBeNull();
  });

  it('leaves a legacy lens legend as it was', () => {
    heatmapMode$.next('coverage');
    render();
    expect(el().querySelectorAll('.posture-stop').length).toBe(0);
    expect(Array.from(el().querySelectorAll('.legend-stop .stop-label')).map(n => n.textContent!.trim()))
      .toEqual(['0', '1', '2', '3', '4+']);
    expect(el().querySelector('.legend-question')!.textContent!.trim()).toBe(heatmapModeDef('coverage')!.question);
  });
});
