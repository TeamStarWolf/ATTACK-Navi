// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, ViewChild, ChangeDetectionStrategy, ChangeDetectorRef, HostListener, DestroyRef, inject } from '@angular/core';
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
import { UrlStateService } from './services/url-state.service';
import { PanelNavService } from './services/panel-nav.service';
import { CommandPaletteService } from './services/command-palette.service';
import { MatrixControlService } from './services/matrix-control.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, SidebarComponent, ToolbarComponent, GapViewComponent, KeyboardHelpComponent, NavRailComponent, OnboardingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent implements OnInit {
  private readonly destroyRef = inject(DestroyRef);
  @ViewChild(GapViewComponent) gapViewRef?: GapViewComponent;
  @ViewChild(KeyboardHelpComponent) keyboardHelp?: KeyboardHelpComponent;

  domain: Domain | null = null;
  isLightMode = false;
  private panelNav = inject(PanelNavService);
  private palette = inject(CommandPaletteService);
  private matrixControl = inject(MatrixControlService);
  showToast = false;
  toastMessage = '';
  currentDomain: AttackDomain = 'enterprise';

  constructor(
    private dataService: DataService,
    private filterService: FilterService,
    private cdr: ChangeDetectorRef,
    private urlStateService: UrlStateService,
  ) {}

  ngOnInit(): void {
    this.dataService.domain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => { this.domain = d; this.cdr.markForCheck(); });
    this.dataService.currentDomain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => { this.currentDomain = d; this.cdr.markForCheck(); });
    this.dataService.loadDomain();
    this.urlStateService.init();
    if (localStorage.getItem('mitre-nav-theme') === 'light') {
      this.isLightMode = true;
      document.body.classList.add('light-mode');
    }
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

  @HostListener('document:keydown', ['$event'])
  onGlobalKeydown(event: KeyboardEvent): void {
    // Skip if typing in an input field
    const target = event.target as HTMLElement;
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return;
    if (target.isContentEditable) return;

    if (event.key === 'Escape') {
      // The palette handles its own Escape; here Escape deselects the technique.
      if (this.palette.isOpen) return;
      this.filterService.selectTechnique(null);
      event.preventDefault();
      return;
    }

    if (event.ctrlKey || event.metaKey) {
      switch (event.key) {
        case 'f':
          event.preventDefault();
          this.focusTechniqueSearch();
          break;
        case 'k':
          event.preventDefault();
          this.palette.open();
          break;
        case 'e':
          event.preventDefault();
          this.matrixControl.expandAll();
          break;
      }
      return;
    }

    // Single-key shortcuts (no modifier)
    switch (event.key) {
      case 'd':
        event.preventDefault();
        this.panelNav.toggle('dashboard');
        break;
      case 't':
        event.preventDefault();
        this.panelNav.toggle('timeline');
        break;
      case 'w':
        event.preventDefault();
        this.panelNav.toggle('watchlist');
        break;
      case 'r':
        event.preventDefault();
        this.panelNav.toggle('risk-matrix');
        break;
      case 'c':
        event.preventDefault();
        this.filterService.clearAll();
        break;
      case 'm':
        event.preventDefault();
        this.panelNav.open('matrix');
        break;
    }
  }

  toggleDarkMode(): void {
    this.isLightMode = !this.isLightMode;
    if (this.isLightMode) {
      document.body.classList.add('light-mode');
    } else {
      document.body.classList.remove('light-mode');
    }
    localStorage.setItem('mitre-nav-theme', this.isLightMode ? 'light' : 'dark');
    this.cdr.markForCheck();
  }

  focusTechniqueSearch(): void {
    const input = document.querySelector<HTMLInputElement>('.technique-search .search-input');
    if (input) {
      input.focus();
      input.select();
    }
  }
}
