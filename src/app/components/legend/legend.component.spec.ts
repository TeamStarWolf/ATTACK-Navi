// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { LegendComponent } from './legend.component';
import { DEFAULT_HEATMAP_MODE, FilterService, HeatmapMode } from '../../services/filter.service';
import { AttackDomain, DataService } from '../../services/data.service';
import { SettingsService } from '../../services/settings.service';
import { heatmapModeDef, lensAvailability } from '../../models/heatmap-modes';
import { LensCardService } from '../../services/lens-card.service';
import { ThemeService } from '../../services/theme.service';
import { PostureStub, makePostureStub, postureStubProvider } from '../../testing/posture-stub';
import { POSTURE_BUCKETS, postureFill, postureLegendStops } from '../../models/posture/posture-ramp';
import type { Domain } from '../../models/domain';
import { controlsLegendStops, statusLegendStops } from '../../models/posture/lens-ramps';
import { hexToRgb } from '../../models/cvd';
import { signal as ngSignal } from '@angular/core';
import { THREAT_WEIGHT_PROVIDER } from '../../models/posture/threat-weight';
import { THREAT_GAP_EMPTY_PROFILE_NOTE, THREAT_GAP_EXPOSURE_NOTE, THREAT_GAP_TOGGLE_LABEL } from '../../models/posture/gap';

/** '#rrggbb' as the browser reports a style colour. */
const rgb = (hex: string): string => `rgb(${hexToRgb(hex).join(', ')})`;

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
        { provide: FilterService, useValue: { heatmapMode$: heatmapMode$.asObservable(), threatGapOverlay$: new BehaviorSubject(false) } },
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
    // P2-14: the ordinal stops, with the breadth guard's partial stop between in progress and implemented.
    expect(stopLabels()).toEqual(['none', 'not started', 'planned', 'in progress', 'implemented, partial via a broad mitigation', 'implemented']);
  });

  it('paints the status swatches from the lens colour function on the Covered ordinal ramp (P2-14)', () => {
    show('status');
    const stops = statusLegendStops('dark');
    const swatches = Array.from(fixture.nativeElement.querySelectorAll('.legend-stop .swatch')) as HTMLElement[];
    expect(swatches.length).toBe(6);
    swatches.forEach((sw, i) => expect(sw.style.backgroundColor).withContext(stops[i].key).toBe(rgb(stops[i].fill)));
    expect(swatches[4].classList).toContain('posture-partial');
    expect(text('.legend-question')).toBe(heatmapModeDef('status')!.question);
    // The colorblind-safe setting does not change an ordinal ramp that is safe by default.
    TestBed.inject(SettingsService).update({ colorblindSafe: true });
    fixture.detectChanges();
    const safe = Array.from(fixture.nativeElement.querySelectorAll('.legend-stop .swatch')) as HTMLElement[];
    safe.forEach((sw, i) => expect(sw.style.backgroundColor).toBe(rgb(stops[i].fill)));
    TestBed.inject(SettingsService).update({ colorblindSafe: false });
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
        { provide: FilterService, useValue: { heatmapMode$: heatmapMode$.asObservable(), threatGapOverlay$: new BehaviorSubject(false) } },
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

  // P2-14: the controls, Proven and Covered legends. Covered and Proven stop
  // words render only under owner words; Proven and Covered say 'No data of
  // yours recorded' on a fresh profile, Controls keeps its question.
  it('controls: swatches from the lens colour function; Covered stop words only with owner data', () => {
    heatmapMode$.next('controls');
    render();
    const stops = controlsLegendStops('dark');
    const swatches = Array.from(el().querySelectorAll('.legend-stop .swatch')) as HTMLElement[];
    expect(swatches.map(sw => sw.style.backgroundColor)).toEqual(stops.map(s => rgb(s.fill)));
    expect(swatches[2].classList).toContain('posture-partial');
    const labels = () => Array.from(el().querySelectorAll('.stop-label')).map(n => n.textContent!.trim());
    expect(labels()).toEqual(['none', 'planned']);
    expect(el().querySelector('.legend-question')!.textContent!.trim()).toBe(heatmapModeDef('controls')!.question);
    posture.set({ T1001: 'covered' });
    render();
    expect(labels()).toEqual(['none', 'planned', 'Covered (self-attested), partial via a broad mitigation', 'Covered (self-attested)']);
  });

  // Design §10.4 item 14: the Proven and Covered lenses are not named for an
  // empty user, so on a fresh profile heat=proven or heat=covered shows the
  // default lens's legend (lensOnScreen) until the matrix page moves the lens.
  for (const mode of ['proven', 'covered'] as const) {
    it(`${mode}: a fresh profile sees the default lens's legend and no covered or proven string`, () => {
      heatmapMode$.next(mode);
      render();
      expect(el().querySelector('.legend-label')!.textContent!.trim()).toBe(heatmapModeDef(DEFAULT_HEATMAP_MODE)!.label);
      expect(el().querySelector('.legend')!.getAttribute('aria-label')).toBe('Legend: ' + heatmapModeDef(DEFAULT_HEATMAP_MODE)!.label);
      expect(el().querySelector('.legend-question')!.textContent!.trim()).toBe(heatmapModeDef(DEFAULT_HEATMAP_MODE)!.question);
      expect(el().querySelector('.posture-stop')).toBeNull();
      const hits = visibleStrings().filter(v => /\b(?:covered|proven)\b/i.test(v));
      expect(hits).withContext(hits.join(' | ')).toEqual([]);
      const cards = TestBed.inject(LensCardService);
      (el().querySelector('.lens-help-btn') as HTMLButtonElement).click();
      expect(cards.openMode()).toBe(DEFAULT_HEATMAP_MODE);
      cards.close();
    });

    it(`${mode}: with owner data, names the lens, shows its ramp and asks its question`, () => {
      heatmapMode$.next(mode);
      posture.set({ T1001: 'proven' });
      render();
      expect(el().querySelector('.legend-label')!.textContent!.trim()).toBe(heatmapModeDef(mode)!.label);
      expect(el().querySelectorAll('.posture-stop .swatch').length).toBe(mode === 'proven' ? 4 : 3);
      expect(el().querySelector('.legend-no-data')).toBeNull();
      expect(el().querySelector('.legend-question')!.textContent!.trim()).toBe(heatmapModeDef(mode)!.question);
    });
  }
});

// P2-17: while the Threat gaps overlay is on, the legend names it, states its
// threshold (q75 from the THREAT_WEIGHT_PROVIDER token, recomputed when the
// profile's revision moves) and says exposure counts on Enterprise only, on
// every domain, ICS included, where the exposure term is 0 (§1.16).
describe('LegendComponent (Threat gaps overlay, P2-17)', () => {
  let fixture: ComponentFixture<LegendComponent>;
  let overlay$: BehaviorSubject<boolean>;
  let currentDomain$: BehaviorSubject<AttackDomain>;
  const revision = ngSignal(0);
  const parents = ngSignal<ReadonlySet<string>>(new Set());
  let weights: Record<string, number> = {};

  beforeEach(async () => {
    localStorage.removeItem('mitre-nav-settings-v1');
    overlay$ = new BehaviorSubject(false);
    currentDomain$ = new BehaviorSubject<AttackDomain>('enterprise');
    weights = { a: 1, b: 2, c: 3, d: 4 };
    parents.set(new Set(Object.keys(weights)));
    await TestBed.configureTestingModule({
      imports: [LegendComponent],
      providers: [
        { provide: FilterService, useValue: { heatmapMode$: new BehaviorSubject<HeatmapMode>('frequency'), threatGapOverlay$: overlay$ } },
        { provide: DataService, useValue: {
          currentDomain$, domain$: new BehaviorSubject({ attackVersion: '19.2' }), freshness$: new BehaviorSubject('bundled'),
        } },
        { provide: THREAT_WEIGHT_PROVIDER, useValue: { revision, parents, weight: (id: string) => weights[id] ?? 0 } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(LegendComponent);
    fixture.detectChanges();
  });

  const el = (): HTMLElement => fixture.nativeElement as HTMLElement;

  it('shows nothing about Threat gaps while the overlay is off', () => {
    expect(el().querySelector('.legend-threat-gaps')).toBeNull();
    expect(el().textContent).not.toContain(THREAT_GAP_EXPOSURE_NOTE);
  });

  it('names the overlay, its threshold and the Enterprise-only exposure line when on', () => {
    overlay$.next(true);
    fixture.detectChanges();
    const line = el().querySelector('.legend-threat-gaps')!.textContent!.replace(/\s+/g, ' ').trim();
    expect(line).toContain(THREAT_GAP_TOGGLE_LABEL);
    // Weights 1 2 3 4: nearest-rank 75th percentile = 3.
    expect(line).toContain('used by 3 or more');
    expect(el().querySelector('.legend-threat-gaps-exposure')!.textContent!.trim()).toBe('Exposure counts on Enterprise only');
  });

  it('ICS: the legend line renders (the exposure term is 0 there)', () => {
    currentDomain$.next('ics');
    overlay$.next(true);
    fixture.detectChanges();
    expect(el().querySelector('.legend-threat-gaps')).not.toBeNull();
    expect(el().querySelector('.legend-threat-gaps-exposure')!.textContent!.trim()).toBe(THREAT_GAP_EXPOSURE_NOTE);
  });

  it('recomputes the threshold when the threat profile changes (provider revision)', () => {
    overlay$.next(true);
    fixture.detectChanges();
    expect(el().querySelector('.legend-threat-gaps')!.textContent).toContain('used by 3 or more');
    weights = { x: 9 };
    parents.set(new Set(['x']));
    revision.update(n => n + 1);
    fixture.detectChanges();
    expect(el().querySelector('.legend-threat-gaps')!.textContent).toContain('used by 9 or more');
  });

  // RP-F item 6: tgap=1 with an empty stored profile marked 0 techniques with no note.
  it('says no threat profile is set when the overlay is on and the profile holds no techniques', () => {
    overlay$.next(true);
    fixture.detectChanges();
    expect(el().querySelector('.legend-threat-gaps-empty')).withContext('a profile with techniques: no note').toBeNull();
    parents.set(new Set());
    revision.update(n => n + 1);
    fixture.detectChanges();
    const note = el().querySelector('.legend-threat-gaps-empty')!;
    expect(note.textContent!.trim()).toBe(THREAT_GAP_EMPTY_PROFILE_NOTE);
    expect(note.getAttribute('role')).toBe('status');
    overlay$.next(false);
    fixture.detectChanges();
    expect(el().querySelector('.legend-threat-gaps-empty')).withContext('overlay off: no note').toBeNull();
  });
});
