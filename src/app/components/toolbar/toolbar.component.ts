// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  Input,
  Output,
  EventEmitter,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';

import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';
import { Technique } from '../../models/technique';
import { FilterService } from '../../services/filter.service';
import { DataService, DataSourceMode, AttackDomain } from '../../services/data.service';
import { CommandPaletteService } from '../../services/command-palette.service';
import { ThemeService } from '../../services/theme.service';
import { SavedViewsService, SavedView } from '../../services/saved-views.service';
import { IconComponent } from '../../shared/icons/icon.component';

export const PLATFORMS = [
  'Windows', 'Linux', 'macOS', 'Azure AD', 'Office 365',
  'Google Workspace', 'SaaS', 'IaaS', 'Network', 'Containers', 'PRE',
];

export const PLATFORM_PILLS = [
  { name: 'Windows', icon: '🪟' },
  { name: 'Linux', icon: '🐧' },
  { name: 'macOS', icon: '🍎' },
  { name: 'IaaS', icon: '☁️' },
  { name: 'Containers', icon: '🐳' },
  { name: 'Network', icon: '🌐' },
  { name: 'Office 365', icon: '📧' },
  { name: 'SaaS', icon: '💼' },
  { name: 'Azure AD', icon: '🔷' },
  { name: 'Google Workspace', icon: '📁' },
];

/**
 * The global top bar. Matrix-scoped controls (technique/mitigation search,
 * platform/source/status filters, heatmap dropdown, exports menu) moved
 * into MatrixControlsComponent and the /reports Export Hub — this bar
 * carries only what applies everywhere: brand, domain + data source,
 * palette search, saved views, share, and theme.
 */
@Component({
  selector: 'app-toolbar',
  standalone: true,
  imports: [FormsModule, RouterLink, IconComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './toolbar.component.html',
  styleUrl: './toolbar.component.scss',
})
export class ToolbarComponent implements OnInit, OnDestroy {
  @Input() techniques: Technique[] = [];
  @Input() set currentDomain(value: AttackDomain) {
    this.attackDomain = value;
  }
  @Output() domainChange = new EventEmitter<AttackDomain>();
  @Output() copyShareLink = new EventEmitter<void>();

  isLightMode = false;

  attackVersion = '';
  dataSourceMode: DataSourceMode = 'live';
  attackDomain: AttackDomain = 'enterprise';
  loading = false;

  // Saved views
  views: SavedView[] = [];
  showViewsMenu = false;
  showSaveDialog = false;
  newViewName = '';
  newViewDesc = '';

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private router: Router,
    private palette: CommandPaletteService,
    private themeService: ThemeService,
    private cdr: ChangeDetectorRef,
    private savedViewsService: SavedViewsService,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.themeService.isLight$.subscribe((v) => { this.isLightMode = v; this.cdr.markForCheck(); }));
    this.subs.add(this.dataService.loading$.subscribe((l) => { this.loading = l; this.cdr.markForCheck(); }));
    this.subs.add(this.dataService.domain$.subscribe((d) => {
      this.attackVersion = d?.attackVersion ?? '';
      this.cdr.markForCheck();
    }));
    this.subs.add(this.savedViewsService.views$.subscribe(views => { this.views = views; this.cdr.markForCheck(); }));
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  openPalette(): void {
    this.palette.open();
  }

  toggleTheme(): void {
    this.themeService.toggle();
  }

  onDataSourceChange(): void {
    this.dataService.setDataSourceMode(this.dataSourceMode);
    this.dataService.loadDomain();
  }

  onDomainChange(): void {
    this.domainChange.emit(this.attackDomain);
  }

  forceRefresh(): void {
    this.dataService.forceRefresh();
  }

  saveView(): void {
    if (!this.newViewName.trim()) return;
    this.savedViewsService.saveCurrentView(this.newViewName.trim(), this.newViewDesc.trim());
    this.newViewName = '';
    this.newViewDesc = '';
    this.showSaveDialog = false;
    this.cdr.markForCheck();
  }

  restoreView(view: SavedView): void {
    this.savedViewsService.restoreView(view);
    this.showViewsMenu = false;
    // Saved views describe matrix filter state — show the result.
    void this.router.navigate(['/matrix'], { queryParamsHandling: 'preserve' });
  }

  deleteView(id: string): void {
    this.savedViewsService.deleteView(id);
    this.cdr.markForCheck();
  }

  formatViewDate(iso: string): string {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch {
      return '';
    }
  }

  /** Returns a consistent daily technique selected by date-seeded index. */
  get techniqueOfDay(): Technique | null {
    if (!this.techniques.length) return null;
    const today = new Date();
    const seed = today.getFullYear() * 10000 + (today.getMonth() + 1) * 100 + today.getDate();
    return this.techniques[seed % this.techniques.length] ?? null;
  }

  selectTechniqueOfDay(): void {
    const t = this.techniqueOfDay;
    if (t) {
      this.filterService.setTechniqueQuery(t.attackId);
      void this.router.navigate(['/matrix'], { queryParamsHandling: 'preserve' });
    }
  }
}
