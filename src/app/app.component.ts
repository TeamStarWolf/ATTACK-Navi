// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, ViewChild, ChangeDetectionStrategy, ChangeDetectorRef, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { take } from 'rxjs';

import { NavigationEnd, NavigationStart, Router, RouterOutlet } from '@angular/router';
import { DataService, AttackDomain } from './services/data.service';
import { Domain } from './models/domain';
import { DEFAULT_HEATMAP_MODE, FilterService } from './services/filter.service';
import { OwnerDataService } from './services/owner-data.service';
import { ViewpointService } from './services/viewpoint.service';
import { SidebarComponent } from './components/sidebar/sidebar.component';
import { ToolbarComponent } from './components/toolbar/toolbar.component';
import { BriefingStripComponent } from './components/briefing-strip/briefing-strip.component';
import { GapViewComponent } from './components/gap-view/gap-view.component';
import { KeyboardHelpComponent } from './components/keyboard-help/keyboard-help.component';
import { NavRailComponent } from './components/nav-rail/nav-rail.component';
import { OnboardingComponent } from './components/onboarding/onboarding.component';
import { UniversalSearchComponent } from './components/universal-search/universal-search.component';
import { PaletteWarmupComponent } from './components/palette-warmup/palette-warmup.component';
import { DrawerWarmupComponent } from './components/drawer-warmup/drawer-warmup.component';
import { UrlStateService } from './services/url-state.service';
import { MatrixControlService } from './services/matrix-control.service';
import { HotkeysService } from './services/hotkeys.service';
import { HelpOverlayService } from './services/help-overlay.service';
import { ThemeService } from './services/theme.service';
import { DrawerWidthService } from './services/drawer-width.service';

/**
 * The technique detail page (P2-18, S15): #/technique/:domain/:id. Its first
 * path segment; the page owns the evidence card, so the drawer is not rendered there.
 */
export const TECHNIQUE_PAGE_SEGMENT = 'technique';

/** True when `url` (a router URL) is the technique detail page, #/technique/:domain/:id. */
export function isTechniquePageUrl(url: string): boolean {
  const segments = url.split(/[?#]/)[0].split('/').filter(Boolean);
  return segments.length === 3 && segments[0] === TECHNIQUE_PAGE_SEGMENT;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, SidebarComponent, ToolbarComponent, BriefingStripComponent, GapViewComponent, KeyboardHelpComponent, NavRailComponent, OnboardingComponent, UniversalSearchComponent, PaletteWarmupComponent, DrawerWarmupComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent implements OnInit {
  private readonly destroyRef = inject(DestroyRef);
  @ViewChild(GapViewComponent) gapViewRef?: GapViewComponent;

  domain: Domain | null = null;
  private matrixControl = inject(MatrixControlService);
  private readonly router = inject(Router);
  private hotkeys = inject(HotkeysService);
  private viewpoint = inject(ViewpointService);
  private readonly ownerData = inject(OwnerDataService);
  protected helpOverlay = inject(HelpOverlayService);
  /** The open technique drawer takes its width from the workspace (above 768 px). */
  protected readonly drawer = inject(DrawerWidthService);
  /** True on the technique detail page: AppComponent hides the drawer there (S15). */
  protected readonly drawerSuppressed = signal(false);
  showToast = false;
  toastMessage = '';
  currentDomain: AttackDomain = 'enterprise';
  private lastWorkspace?: string;
  private pendingKeepSelection = false;
  private drawerPinned = false;

  constructor(
    private dataService: DataService,
    private filterService: FilterService,
    private cdr: ChangeDetectorRef,
    private urlStateService: UrlStateService,
    private themeService: ThemeService,
  ) {}

  ngOnInit(): void {
    this.dataService.domain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => { this.domain = d; this.cdr.markForCheck(); });
    this.dataService.currentDomain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => { this.currentDomain = d; this.cdr.markForCheck(); });
    this.dataService.loadDomain();
    this.matrixControl.gapViewRequests$
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => this.gapViewRef?.show());
    this.initDrawerRouteScope();
    // A shared link whose `tech` is not in the loaded domain says so here (E2.3).
    this.filterService.urlNotice$
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((message) => this.showToastMessage(message, 6000));
    // The URL writer needs D4 to know whether heat=frequency may be left out
    // (P2-19). The first emission is synchronous, so it is set before the writer starts.
    this.ownerData.hasOwnerData$
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((has) => this.filterService.ownerDataPresent.next(has));
    // Restore the saved viewpoint's lens before the URL writer starts, and let
    // it defer to an explicit `heat` deep link (handled inside restore()).
    this.viewpoint.restore();
    this.applyDefaultLensRule();
    this.urlStateService.init();
    this.themeService.init();
    this.hotkeys.init();
  }

  /**
   * The default-lens rule (Phase 2 design §3 P2-19, E2.4; D4, §10.4 items 3
   * and 4). Runs once, at boot, after viewpoint.restore() and before the URL
   * reader. Precedence: an explicit heat= (the reader applies it after this),
   * then a specialist viewpoint's lens, then D4's Posture, then frequency. It
   * reads OwnerDataService.defaultLens$'s synchronous first emission, so it
   * never waits for a domain (no race, R11). Owner data that first appears
   * later in the session changes the default on the next boot only: the lens
   * on screen is never switched under the user. A heat= that names no
   * registered lens (heat=bogus, an empty heat=) is not an explicit choice:
   * urlHasHeatParam reads it as absent, so this rule still runs and the
   * writer then replaces the invalid key with the lens chosen here (RP-F item 1).
   */
  private applyDefaultLensRule(): void {
    if (this.viewpoint.urlHasHeatParam()) return;
    const stored = this.viewpoint.storedDefaultLens();
    if (stored !== null && stored !== DEFAULT_HEATMAP_MODE) return;
    let lens = DEFAULT_HEATMAP_MODE;
    this.ownerData.defaultLens$.pipe(take(1)).subscribe((l) => (lens = l));
    if (lens !== DEFAULT_HEATMAP_MODE) this.filterService.setHeatmapMode(lens);
  }

  /**
   * The technique sidebar is global and its selection lives in FilterService, so
   * an open drawer used to ride over the next workspace. Close it when the
   * WORKSPACE (the first path segment) changes (E2.3) — UNLESS the drawer is
   * pinned, or the navigation carries keepTechniqueSelection (set by
   * PanelNavService for flows that select a technique FOR the destination, e.g.
   * "show this technique on the matrix"). A tab change inside one workspace and
   * url-state's replaceUrl query writes keep the drawer open.
   */
  private initDrawerRouteScope(): void {
    this.filterService.drawerPinned$
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((pinned) => (this.drawerPinned = pinned));
    this.router.events
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((e) => {
        if (e instanceof NavigationStart) {
          this.pendingKeepSelection = this.shouldKeepSelection(
            e.navigationTrigger, this.router.getCurrentNavigation()?.extras?.state);
        } else if (e instanceof NavigationEnd) {
          const url = e.urlAfterRedirects ?? e.url;
          this.clearSelectionOnRouteChange(url, this.pendingKeepSelection);
          this.pendingKeepSelection = false;
          this.drawerSuppressed.set(isTechniquePageUrl(url));
        }
      });
  }

  /**
   * Honor keepTechniqueSelection only on an IMPERATIVE navigation. On Back/Forward
   * (popstate) the router restores the history entry's saved state, which still
   * carries the flag from when PanelNavService pushed that entry — re-applying it
   * would resurrect a leftover drawer (the original bug, back through history).
   */
  private shouldKeepSelection(
    trigger: NavigationStart['navigationTrigger'],
    state: { [k: string]: unknown } | undefined,
  ): boolean {
    return trigger !== 'popstate' && state?.['keepTechniqueSelection'] === true;
  }

  /**
   * Close the technique sidebar when the workspace changes (#/detect/sigma to
   * #/intel/groups), unless the drawer is pinned or this navigation carries a
   * selection made for the destination (keep). The first navigation only records
   * the starting workspace (nothing to clear on load); a tab change in the same
   * workspace (#/detect/sigma to #/detect/validation) or a url-state query write
   * leaves the drawer open.
   */
  private clearSelectionOnRouteChange(url: string, keep: boolean): void {
    const workspace = url.split(/[?#]/)[0].split('/').find(Boolean) ?? '';
    // The technique page selects its own technique (P2-18): arriving there never clears it.
    const ownsSelection = workspace === TECHNIQUE_PAGE_SEGMENT;
    if (this.lastWorkspace !== undefined && workspace !== this.lastWorkspace && !keep && !this.drawerPinned && !ownsSelection) {
      this.filterService.selectTechnique(null);
    }
    this.lastWorkspace = workspace;
  }

  onDomainChange(domain: AttackDomain): void {
    this.filterService.clearAll();
    this.dataService.switchDomain(domain);
  }

  copyShareLink(): void {
    const url = this.urlStateService.getShareUrl();
    navigator.clipboard.writeText(url)
      .then(() => this.showToastMessage('Link copied to clipboard!'))
      .catch(() => this.showToastMessage('Unable to copy the share link from this browser'));
  }

  showCopiedToast(): void {
    this.showToastMessage('Link copied to clipboard!');
  }

  private showToastMessage(message: string, durationMs = 2500): void {
    this.showToast = true;
    this.toastMessage = message;
    this.cdr.markForCheck();
    setTimeout(() => { this.showToast = false; this.cdr.markForCheck(); }, durationMs);
  }
}
