import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription, combineLatest } from 'rxjs';
import { Mitigation } from '../../models/mitigation';
import { Technique } from '../../models/technique';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService, ImplStatus, IMPL_STATUS_LABELS } from '../../services/implementation.service';

interface WhatIfRow {
  mitigation: Mitigation;
  newTechniques: number;      // techniques not currently covered that this would add
  totalTechniques: number;
  exposureScore: number;      // distinct threat groups using the new techniques
  implStatus: ImplStatus | null;
  checked: boolean;
}

@Component({
  selector: 'app-whatif-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './whatif-panel.component.html',
  styleUrl: './whatif-panel.component.scss',
})
export class WhatifPanelComponent implements OnInit, OnDestroy {
  visible = false;
  searchText = '';
  rows: WhatIfRow[] = [];
  filteredRows: WhatIfRow[] = [];
  whatIfIds = new Set<string>();

  currentCoveragePct = 0;
  currentCovered = 0;
  whatIfCoveragePct = 0;
  whatIfCovered = 0;
  totalParent = 0;

  statusLabels = IMPL_STATUS_LABELS;
  filterMode: 'all' | 'not-implemented' = 'not-implemented';

  private allRows: WhatIfRow[] = [];
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      combineLatest([
        this.dataService.domain$,
        this.implService.status$,
        this.filterService.whatIfMitigationIds$,
      ]).subscribe(([domain, statusMap, whatIfIds]) => {
        this.whatIfIds = whatIfIds;
        if (!domain) return;

        const parentTechs = domain.techniques.filter((t) => !t.isSubtechnique);
        this.totalParent = parentTechs.length;

        // Current coverage: techniques with ≥1 mitigation
        const coveredNow = new Set(
          parentTechs.filter((t) => (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) > 0).map((t) => t.id),
        );
        this.currentCovered = coveredNow.size;
        this.currentCoveragePct = Math.round((this.currentCovered / this.totalParent) * 100);

        // What-if coverage: add in what-if mitigations
        const whatIfCoveredIds = new Set(coveredNow);
        for (const mitId of whatIfIds) {
          const techs = domain.techniquesByMitigation.get(mitId) ?? [];
          for (const t of techs) {
            if (!t.isSubtechnique) whatIfCoveredIds.add(t.id);
          }
        }
        this.whatIfCovered = whatIfCoveredIds.size;
        this.whatIfCoveragePct = Math.round((this.whatIfCovered / this.totalParent) * 100);

        // Build rows
        this.allRows = domain.mitigations.map((mit) => {
          const techniques = (domain.techniquesByMitigation.get(mit.id) ?? []).filter((t) => !t.isSubtechnique);
          const newTechObjs = techniques.filter((t) => !coveredNow.has(t.id));
          const groupSet = new Set<string>();
          for (const t of newTechObjs) {
            for (const g of (domain.groupsByTechnique.get(t.id) ?? [])) {
              groupSet.add(g.id);
            }
          }
          return {
            mitigation: mit,
            newTechniques: newTechObjs.length,
            totalTechniques: techniques.length,
            exposureScore: groupSet.size,
            implStatus: statusMap.get(mit.id) ?? null,
            checked: whatIfIds.has(mit.id),
          };
        });

        // Sort by new techniques desc
        this.allRows.sort((a, b) => b.newTechniques - a.newTechniques || b.totalTechniques - a.totalTechniques);
        this.applyFilter();
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.filterService.activePanel$.subscribe((panel) => {
        this.visible = panel === 'whatif';
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  onSearch(): void {
    this.applyFilter();
    this.cdr.markForCheck();
  }

  onFilterModeChange(): void {
    this.applyFilter();
    this.cdr.markForCheck();
  }

  private applyFilter(): void {
    let rows = this.allRows;
    if (this.filterMode === 'not-implemented') {
      rows = rows.filter((r) => r.implStatus !== 'implemented');
    }
    const q = this.searchText.trim().toLowerCase();
    if (q) {
      rows = rows.filter(
        (r) =>
          r.mitigation.attackId.toLowerCase().includes(q) ||
          r.mitigation.name.toLowerCase().includes(q),
      );
    }
    this.filteredRows = rows;
  }

  toggleMitigation(row: WhatIfRow): void {
    this.filterService.toggleWhatIfMitigation(row.mitigation.id);
  }

  clearAll(): void {
    this.filterService.clearWhatIf();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  get checkedCount(): number {
    return this.whatIfIds.size;
  }

  get gainedTechniques(): number {
    return this.whatIfCovered - this.currentCovered;
  }
}
