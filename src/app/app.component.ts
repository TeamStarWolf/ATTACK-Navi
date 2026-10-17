// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, ViewChild, ChangeDetectionStrategy, ChangeDetectorRef, DestroyRef, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import { NavigationEnd, NavigationStart, Router, RouterOutlet } from '@angular/router';
import { DataService, AttackDomain } from './services/data.service';
import { Domain } from './models/domain';
import { FilterService } from './services/filter.service';
import { ViewpointService } from './services/viewpoint.service';
import { SidebarComponent } from './components/sidebar/sidebar.component';
import { ToolbarComponent } from './components/toolbar/toolbar.component';
import { GapViewComponent } from './components/gap-view/gap-view.component';
import { KeyboardHelpComponent } from './components/keyboard-help/keyboard-help.component';
import { NavRailComponent } from './components/nav-rail/nav-rail.component';
import { OnboardingComponent } from './components/onboarding/onboarding.component';
import { UniversalSearchComponent } from './components/universal-search/universal-search.component';
import { UrlStateService } from './services/url-state.service';
import { MatrixControlService } from './services/matrix-control.service';
import { HotkeysService } from './services/hotkeys.service';
import { HelpOverlayService } from './services/help-overlay.service';
import { ThemeService } from './services/theme.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, SidebarComponent, ToolbarComponent, GapViewComponent, KeyboardHelpComponent, NavRailComponent, OnboardingComponent, UniversalSearchComponent],
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
  protected helpOverlay = inject(HelpOverlayService);
  showToast = false;
  toastMessage = '';
  currentDomain: AttackDomain = 'enterprise';
  private lastRoutePath?: string;
  private pendingKeepSelection = false;

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
    // Restore the saved viewpoint's lens before the URL writer starts, and let
    // it defer to an explicit `heat` deep link (handled inside restore()).
    this.viewpoint.restore();
    this.urlStateService.init();
    this.themeService.init();
    this.hotkeys.init();
  }

  /**
   * The technique sidebar is global and its selection lives in FilterService, so
   * an open drawer used to ride over the next workspace. Close it when the route
   * PATH changes — UNLESS the navigation carries keepTechniqueSelection (set by
   * PanelNavService for flows that select a technique FOR the destination, e.g.
   * "show this technique on the matrix"). url-state writes filter edits with
   * replaceUrl on the SAME path (query only), so those keep the drawer open.
   */
  private initDrawerRouteScope(): void {
    this.router.events
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((e) => {
        if (e instanceof NavigationStart) {
          this.pendingKeepSelection = this.shouldKeepSelection(
            e.navigationTrigger, this.router.getCurrentNavigation()?.extras?.state);
        } else if (e instanceof NavigationEnd) {
          this.clearSelectionOnRouteChange(e.urlAfterRedirects ?? e.url, this.pendingKeepSelection);
          this.pendingKeepSelection = false;
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
   * Close the technique sidebar when the route path changes, unless this
   * navigation carries a selection made for the destination (keep). The first
   * navigation only records the starting path (nothing to clear on load); a
   * same-path navigation (a url-state query write) leaves the drawer open.
   */
  private clearSelectionOnRouteChange(url: string, keep: boolean): void {
    const path = url.split(/[?#]/)[0];
    if (this.lastRoutePath !== undefined && path !== this.lastRoutePath && !keep) {
      this.filterService.selectTechnique(null);
    }
    this.lastRoutePath = path;
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

  private showToastMessage(message: string): void {
    this.showToast = true;
    this.toastMessage = message;
    this.cdr.markForCheck();
    setTimeout(() => { this.showToast = false; this.cdr.markForCheck(); }, 2500);
  }
}
