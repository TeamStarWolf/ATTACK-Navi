// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, ViewChild, ChangeDetectionStrategy, ChangeDetectorRef, DestroyRef, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { DataService, AttackDomain } from './services/data.service';
import { Domain } from './models/domain';
import { FilterService } from './services/filter.service';
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
  imports: [CommonModule, RouterOutlet, SidebarComponent, ToolbarComponent, GapViewComponent, KeyboardHelpComponent, NavRailComponent, OnboardingComponent, UniversalSearchComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent implements OnInit {
  private readonly destroyRef = inject(DestroyRef);
  @ViewChild(GapViewComponent) gapViewRef?: GapViewComponent;

  domain: Domain | null = null;
  private matrixControl = inject(MatrixControlService);
  private hotkeys = inject(HotkeysService);
  protected helpOverlay = inject(HelpOverlayService);
  showToast = false;
  toastMessage = '';
  currentDomain: AttackDomain = 'enterprise';

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
    this.urlStateService.init();
    this.themeService.init();
    this.hotkeys.init();
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
