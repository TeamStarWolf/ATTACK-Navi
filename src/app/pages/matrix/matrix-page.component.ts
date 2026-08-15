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
import { StatsBarComponent } from '../../components/stats-bar/stats-bar.component';
import { DataHealthComponent } from '../../components/data-health/data-health.component';
import {
  TacticSummaryComponent,
  TacticSummaryData,
} from '../../components/tactic-summary/tactic-summary.component';

/**
 * The matrix home page: ATT&CK grid plus its context chrome (legend, quick
 * filters, filter chips, stats, data health), the tactic-summary popover, and
 * the multi-select bulk-action bar. Extracted from the pre-router AppComponent.
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
    StatsBarComponent,
    DataHealthComponent,
    TacticSummaryComponent,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './matrix-page.component.html',
  styleUrl: './matrix-page.component.scss',
})
export class MatrixPageComponent implements OnInit {
  private readonly destroyRef = inject(DestroyRef);
  private readonly dataService = inject(DataService);
  private readonly cdr = inject(ChangeDetectorRef);

  @ViewChild(MatrixComponent) matrixRef?: MatrixComponent;
  @ViewChild(TacticSummaryComponent) tacticSummary?: TacticSummaryComponent;

  domain: Domain | null = null;
  loading = true;
  error: string | null = null;
  currentDomain: AttackDomain = 'enterprise';

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

  scrollToTactic(shortname: string): void {
    const headers = document.querySelectorAll('.tactic-header');
    for (const h of Array.from(headers)) {
      if (h.textContent?.toLowerCase().includes(shortname.toLowerCase().replace(/-/g, ' '))) {
        h.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'start' });
        break;
      }
    }
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
