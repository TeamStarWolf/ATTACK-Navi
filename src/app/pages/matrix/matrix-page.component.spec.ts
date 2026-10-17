// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { MatrixPageComponent } from './matrix-page.component';
import { DataService } from '../../services/data.service';
import { FilterService } from '../../services/filter.service';
import { LensCardService } from '../../services/lens-card.service';
import { heatmapModeDef, lensAvailability } from '../../models/heatmap-modes';
import { BehaviorSubject } from 'rxjs';
import { OwnerDataService, PREVALENCE_BANNER_TEXT } from '../../services/owner-data.service';

describe('MatrixPageComponent', () => {
  let ownerData: BehaviorSubject<boolean>;

  beforeEach(async () => {
    ownerData = new BehaviorSubject(false);
    await TestBed.configureTestingModule({
      imports: [MatrixPageComponent],
      providers: [
        provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]),
        { provide: OwnerDataService, useValue: { hasOwnerData$: ownerData.asObservable() } },
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
