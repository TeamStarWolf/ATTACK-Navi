// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { MatrixPageComponent } from './matrix-page.component';
import { DataService } from '../../services/data.service';
import { DEFAULT_HEATMAP_MODE, FilterService, HeatmapMode } from '../../services/filter.service';
import { PostureService } from '../../services/posture.service';
import { LensCardService } from '../../services/lens-card.service';
import { heatmapModeDef, lensAvailability } from '../../models/heatmap-modes';
import { BehaviorSubject, of } from 'rxjs';
import { OwnerDataService, PREVALENCE_BANNER_TEXT } from '../../services/owner-data.service';
import { MatrixComponent } from '../../components/matrix/matrix.component';
import { Domain } from '../../models/domain';
import { parseFixtureDomain, resetBrowserState } from '../../testing/lens-harness';

describe('MatrixPageComponent', () => {
  let ownerData: BehaviorSubject<boolean>;

  beforeEach(async () => {
    ownerData = new BehaviorSubject(false);
    await TestBed.configureTestingModule({
      imports: [MatrixPageComponent],
      providers: [
        provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]),
        {
          provide: OwnerDataService,
          useValue: { hasOwnerData$: ownerData.asObservable(), counts$: of({ implementation: 0, validation: 0, stack: 0 }) },
        },
      ],
    }).compileComponents();
  });

  // E1.5 (D4): a fresh profile opens on Prevalence with a one-line banner that
  // says what the lens is and that it is reference data, until owner data exists.
  describe('first-glance Prevalence banner (E1.5, D4)', () => {
    const bannerOf = (el: HTMLElement) => el.querySelector('.first-glance-banner') as HTMLElement | null;

    it('shows on the default lens of a fresh profile and opens the lens card', () => {
      const fixture = TestBed.createComponent(MatrixPageComponent);
      fixture.detectChanges();
      expect(fixture.componentInstance.heatmapMode).toBe('frequency');
      const banner = bannerOf(fixture.nativeElement)!;
      expect(banner).toBeTruthy();
      expect(banner.querySelector('.first-glance-text')!.textContent!.trim()).toBe(PREVALENCE_BANNER_TEXT);
      (banner.querySelector('.lens-na-help') as HTMLButtonElement).click();
      expect(TestBed.inject(LensCardService).openMode()).toBe('frequency');
      TestBed.inject(LensCardService).close();
    });

    it('goes away once owner data exists, and returns if it is cleared', () => {
      const fixture = TestBed.createComponent(MatrixPageComponent);
      fixture.detectChanges();
      ownerData.next(true);
      fixture.detectChanges();
      expect(bannerOf(fixture.nativeElement)).toBeNull();
      ownerData.next(false);
      fixture.detectChanges();
      expect(bannerOf(fixture.nativeElement)).toBeTruthy();
    });

    it('is not shown on another lens', () => {
      const fixture = TestBed.createComponent(MatrixPageComponent);
      fixture.detectChanges();
      TestBed.inject(FilterService).setHeatmapMode('unified');
      fixture.detectChanges();
      expect(bannerOf(fixture.nativeElement)).toBeNull();
    });
  });

  // Phase 2 design P2-05 (Revision 3): the banner predicate is
  // showPrevalenceBanner(mode, hasOwnerData || posture.ownerWords()), on the
  // real stores and the real PostureService over the lens fixture. Updated on
  // purpose: a controls-only profile now hides the banner (owner words), and a
  // planned-only profile shows it (D4 exact).
  describe('banner predicate: D4 or owner words (P2-05)', () => {
    let domain: Domain;
    const bannerOf = (el: HTMLElement) => el.querySelector('.first-glance-banner');

    function render(seed: (d: Domain) => void) {
      TestBed.resetTestingModule();
      resetBrowserState();
      domain = parseFixtureDomain();
      seed(domain);
      TestBed.configureTestingModule({
        imports: [MatrixPageComponent],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])],
      });
      // The grid itself is not under test here: render the page chrome only.
      TestBed.overrideTemplate(MatrixComponent, '');
      (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
      const fixture = TestBed.createComponent(MatrixPageComponent);
      fixture.detectChanges();
      expect(fixture.componentInstance.heatmapMode).toBe('frequency');
      return fixture;
    }
    const m1047 = (d: Domain) => d.mitigations.find(m => m.attackId === 'M1047')!.id;

    afterEach(() => resetBrowserState());

    it('controls-only (one implemented control) on heat=frequency: no banner', () => {
      const fixture = render(d => localStorage.setItem('mitre-nav-controls-v1', JSON.stringify([{
        id: 'c1', name: 'EDR policy', framework: 'Custom', controlRef: 'c1', description: '', mitigationIds: [m1047(d)], status: 'implemented',
      }])));
      expect(bannerOf(fixture.nativeElement)).toBeNull();
    });

    it('a fresh profile: banner', () => {
      const fixture = render(() => undefined);
      expect(bannerOf(fixture.nativeElement)).toBeTruthy();
    });

    it('planned-only: banner', () => {
      const fixture = render(d => localStorage.setItem('mitre-nav-impl-v1', JSON.stringify([[m1047(d), 'planned']])));
      expect(bannerOf(fixture.nativeElement)).toBeTruthy();
    });
  });

  // Design §10.4 item 14: the Proven and Covered lenses are not named for an
  // empty user, so a heat=proven or heat=covered link opened with no owner
  // data moves to the default lens (lensOnScreen). It waits for the domain:
  // before one loads, ownerWords() is false for every profile.
  describe('heat=proven and heat=covered need owner data (§10.4 item 14)', () => {
    function mount(seed: (d: Domain) => void) {
      TestBed.resetTestingModule();
      resetBrowserState();
      const domain = parseFixtureDomain();
      seed(domain);
      TestBed.configureTestingModule({
        imports: [MatrixPageComponent],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])],
      });
      TestBed.overrideTemplate(MatrixComponent, '');
      const fixture = TestBed.createComponent(MatrixPageComponent);
      fixture.detectChanges();
      const loadDomain = (): void => {
        (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
        TestBed.tick();
        fixture.detectChanges();
      };
      const setLens = (mode: HeatmapMode): void => {
        TestBed.inject(FilterService).setHeatmapMode(mode);
        TestBed.tick();
        fixture.detectChanges();
      };
      return { fixture, loadDomain, setLens };
    }
    const m1047 = (d: Domain) => d.mitigations.find(m => m.attackId === 'M1047')!.id;
    const implementedControl = (d: Domain) => localStorage.setItem('mitre-nav-controls-v1', JSON.stringify([{
      id: 'c1', name: 'EDR policy', framework: 'Custom', controlRef: 'c1', description: '', mitigationIds: [m1047(d)], status: 'implemented',
    }]));

    afterEach(() => resetBrowserState());

    for (const mode of ['proven', 'covered'] as const) {
      it(`an empty user on heat=${mode} moves to the default lens once the domain loads`, () => {
        const { fixture, loadDomain, setLens } = mount(() => undefined);
        setLens(mode);
        expect(fixture.componentInstance.heatmapMode).withContext('no domain yet: left alone').toBe(mode);
        loadDomain();
        expect(fixture.componentInstance.heatmapMode).toBe(DEFAULT_HEATMAP_MODE);
        setLens(mode);
        expect(fixture.componentInstance.heatmapMode).withContext('picked again with no owner data').toBe(DEFAULT_HEATMAP_MODE);
      });

      it(`with owner data, heat=${mode} stays`, () => {
        const { fixture, loadDomain, setLens } = mount(implementedControl);
        setLens(mode);
        loadDomain();
        expect(TestBed.inject(PostureService).ownerWords()).toBeTrue();
        expect(fixture.componentInstance.heatmapMode).toBe(mode);
      });
    }

    it('leaves every other lens alone for an empty user, Posture included', () => {
      const { fixture, loadDomain, setLens } = mount(() => undefined);
      loadDomain();
      for (const mode of ['posture', 'status', 'controls', 'unified'] as const) {
        setLens(mode);
        expect(fixture.componentInstance.heatmapMode).withContext(mode).toBe(mode);
      }
    });
  });

  it('creates the matrix region and renders no matrix before a domain arrives', () => {
    const fixture = TestBed.createComponent(MatrixPageComponent);
    fixture.detectChanges();
    expect(fixture.componentInstance).toBeTruthy();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.matrix-region')).toBeTruthy();
    expect(el.querySelector('app-matrix')).toBeNull();
  });

  it('reports zero selected techniques with no matrix mounted', () => {
    const fixture = TestBed.createComponent(MatrixPageComponent);
    fixture.detectChanges();
    expect(fixture.componentInstance.selectedTechniqueCount).toBe(0);
    expect(fixture.nativeElement.querySelector('.bulk-action-bar')).toBeNull();
  });

  // E1.2 PR 2: when the active lens has no data for the domain on screen, a
  // status banner says so and why, so the hatched matrix never reads as zeros.
  it('announces an n/a lens with its reason and opens its definition card', () => {
    const fixture = TestBed.createComponent(MatrixPageComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const banner = el.querySelector('.lens-na-banner') as HTMLElement;
    expect(banner.getAttribute('role')).toBe('status');
    expect(banner.classList).not.toContain('shown');
    expect(banner.textContent!.trim()).toBe('');

    TestBed.inject(DataService).currentDomain$.next('ics');
    TestBed.inject(FilterService).setHeatmapMode('sigma');
    fixture.detectChanges();
    expect(banner.classList).toContain('shown');
    expect(banner.textContent).toContain(lensAvailability(heatmapModeDef('sigma')!, 'ics').reason!);
    expect(banner.textContent).toContain('not as zero');

    (banner.querySelector('.lens-na-help') as HTMLButtonElement).click();
    expect(TestBed.inject(LensCardService).openMode()).toBe('sigma');
    TestBed.inject(LensCardService).close();

    TestBed.inject(FilterService).setHeatmapMode('frequency');
    fixture.detectChanges();
    expect(banner.classList).not.toContain('shown');
  });

  it('hosts the lens definition card', () => {
    const fixture = TestBed.createComponent(MatrixPageComponent);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('app-lens-definition-card')).toBeTruthy();
  });
});
