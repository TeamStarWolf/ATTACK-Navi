// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  DestroyRef,
  HostListener,
  OnInit,
  ViewChild,
  inject,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { CommonModule, TitleCasePipe } from '@angular/common';
import { AttackDomain, DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';
import { Tactic } from '../../models/tactic';
import { Technique } from '../../models/technique';
import { ImplStatus, ImplementationService } from '../../services/implementation.service';
import { MatrixComponent } from '../../components/matrix/matrix.component';
import { MatrixControlsComponent } from './matrix-controls.component';
import { LegendComponent } from '../../components/legend/legend.component';
import { QuickFiltersComponent } from '../../components/quick-filters/quick-filters.component';
import { FilterChipsComponent } from '../../components/filter-chips/filter-chips.component';
import { LensDefinitionCardComponent } from '../../components/lens-definition-card/lens-definition-card.component';
import { DEFAULT_HEATMAP_MODE, FilterService, HeatmapMode } from '../../services/filter.service';
import { LensCardService } from '../../services/lens-card.service';
import { LensAvailability, heatmapModeDef, lensAvailability } from '../../models/heatmap-modes';
import { SourceBannerComponent } from '../../components/source-banner/source-banner.component';
import { OwnerDataService, PREVALENCE_BANNER_TEXT, showPrevalenceBanner } from '../../services/owner-data.service';
import { PostureService } from '../../services/posture.service';
import {
  TacticSummaryComponent,
  TacticSummaryData,
} from '../../components/tactic-summary/tactic-summary.component';

/**
 * The matrix home page: ATT&CK grid plus its context chrome (legend, quick
 * filters, filter chips), the tactic-summary popover, and the multi-select
 * bulk-action bar. Coverage stats and data-source health live on the Status
 * workspace (/status). Extracted from the pre-router AppComponent.
 * Routed with data.reuse=true — the component is detached, not destroyed, when
 * navigating to another workspace.
 */
@Component({
  selector: 'app-matrix-page',
  standalone: true,
  imports: [
    CommonModule,
    TitleCasePipe,
    MatrixComponent,
    MatrixControlsComponent,
    LegendComponent,
    QuickFiltersComponent,
    FilterChipsComponent,
    TacticSummaryComponent,
    LensDefinitionCardComponent,
    SourceBannerComponent,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './matrix-page.component.html',
  styleUrl: './matrix-page.component.scss',
})
export class MatrixPageComponent implements OnInit {
  private readonly destroyRef = inject(DestroyRef);
  private readonly dataService = inject(DataService);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly filterService = inject(FilterService);
  private readonly lensCards = inject(LensCardService);
  private readonly ownerData = inject(OwnerDataService);
  private readonly posture = inject(PostureService);

  @ViewChild(MatrixComponent) matrixRef?: MatrixComponent;
  @ViewChild(TacticSummaryComponent) tacticSummary?: TacticSummaryComponent;

  domain: Domain | null = null;
  loading = true;
  error: string | null = null;
  currentDomain: AttackDomain = 'enterprise';
  heatmapMode: HeatmapMode = DEFAULT_HEATMAP_MODE;
  /** The exact D4 predicate (OwnerDataService.hasOwnerData$, P2-05). */
  ownerDataExists = false;
  readonly prevalenceBannerText = PREVALENCE_BANNER_TEXT;

  /**
   * The one-line Prevalence banner (plan E1.5, decision D4; Phase 2 design
   * P2-05, Revision 3). It hides when D4 holds or when PostureService has
   * Covered or Proven data to show (ownerWords): once any surface can show
   * such a number, "not a view of your environment" is not true. Combined
   * here, not in OwnerDataService, because PostureService reads
   * OwnerDataService and the reverse injection would be circular. Reading the
   * ownerWords signal from the template keeps this OnPush view current.
   */
  get prevalenceBanner(): boolean {
    return showPrevalenceBanner(this.heatmapMode, this.ownerDataExists || this.posture.ownerWords());
  }

  /**
   * The active lens's availability in the domain on screen (E1.2). When it has
   * no data here the matrix shows every cell as 'n/a in this domain' (hatched)
   * and this banner says why, so a missing source never reads as all zeros.
   */
  get lensNa(): (LensAvailability & { label: string }) | null {
    const def = heatmapModeDef(this.heatmapMode);
    if (!def) return null;
    const a = lensAvailability(def, this.currentDomain);
    return a.available ? null : { ...a, label: def.label };
  }

  openLensCard(event: Event): void {
    this.lensCards.open(this.heatmapMode, event.currentTarget);
  }

  /** Legend/quick-filters/stats strip — collapsed by default, sticky choice. */
  contextStripOpen = localStorage.getItem('matrix-context-strip') === 'open';

  toggleContextStrip(): void {
    this.contextStripOpen = !this.contextStripOpen;
    try {
      localStorage.setItem('matrix-context-strip', this.contextStripOpen ? 'open' : 'closed');
    } catch { /* storage unavailable */ }
    this.cdr.markForCheck();
  }

  ngOnInit(): void {
    this.dataService.domain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => {
      this.domain = d;
      this.cdr.markForCheck();
    });
    this.dataService.loading$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((l) => {
      this.loading = l;
      this.cdr.markForCheck();
    });
    this.dataService.error$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((e) => {
      this.error = e;
      this.cdr.markForCheck();
    });
    this.dataService.currentDomain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => {
      this.currentDomain = d;
      this.cdr.markForCheck();
    });
    this.filterService.heatmapMode$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((m) => {
      this.heatmapMode = m;
      this.cdr.markForCheck();
    });
    this.ownerData.hasOwnerData$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((has) => {
      this.ownerDataExists = has;
      this.cdr.markForCheck();
    });
  }

  @HostListener('document:click')
  closePopup(): void {
    this.tacticSummary?.hide();
  }

  onTacticClick(event: { tactic: Tactic; techniques: Technique[]; event: MouseEvent }): void {
    if (!this.domain) return;
    const parentTechniques = event.techniques.filter((t) => !t.isSubtechnique);
    const data: TacticSummaryData = {
      tactic: event.tactic,
      techniques: event.techniques,
      parentTechniques,
      domain: this.domain,
    };
    this.tacticSummary?.show(data, event.event);
  }

  focusTechniqueSearch(): void {
    const input = document.querySelector<HTMLInputElement>('.technique-search .search-input');
    if (input) {
      input.focus();
      input.select();
    }
  }

  get selectedTechniqueCount(): number {
    return this.matrixRef?.selectedTechIds?.size ?? 0;
  }

  bulkAddToWatchlist(): void {
    this.matrixRef?.bulkAddToWatchlist();
    this.cdr.markForCheck();
  }

  bulkSetStatus(status: ImplStatus): void {
    this.matrixRef?.bulkSetStatus(status);
    this.cdr.markForCheck();
  }

  bulkAddTag(): void {
    const tag = prompt('Enter tag name to apply to all selected techniques:');
    if (tag && tag.trim()) {
      this.matrixRef?.bulkAddTag(tag.trim());
      this.cdr.markForCheck();
    }
  }

  clearMultiSelect(): void {
    this.matrixRef?.clearSelection();
    this.cdr.markForCheck();
  }
}
