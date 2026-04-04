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
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService, ImplStatus, IMPL_STATUS_LABELS, IMPL_STATUS_COLORS } from '../../services/implementation.service';
import { CveService } from '../../services/cve.service';
import { AtomicService } from '../../services/atomic.service';
import { SigmaService } from '../../services/sigma.service';
import { EpssService } from '../../services/epss.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { NistMappingService } from '../../services/nist-mapping.service';

interface PriorityRow {
  mitigation: Mitigation;
  totalTechniques: number;
  uniqueTechniques: number;    // techniques where this is the ONLY mitigation
  exposureScore: number;       // distinct threat groups using covered techniques
  kevScore: number;            // KEV CVEs affecting covered techniques
  atomicScore: number;         // total atomic tests for covered techniques
  sigmaScore: number;          // total Sigma rules across all techniques covered by this mitigation
  unifiedScore: number;        // average unified risk score across covered techniques (0-100)
  nistScore: number;           // total NIST 800-53 controls across covered techniques
  implStatus: ImplStatus | null;
}

@Component({
  selector: 'app-priority-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './priority-panel.component.html',
  styleUrl: './priority-panel.component.scss',
})
export class PriorityPanelComponent implements OnInit, OnDestroy {
  visible = false;
  rows: PriorityRow[] = [];
  sortKey: 'unique' | 'total' | 'exposure' | 'kev' | 'atomic' | 'sigma' | 'unified' | 'nist' = 'unique';
  searchText = '';
  statusLabels = IMPL_STATUS_LABELS;
  statusColors = IMPL_STATUS_COLORS;
  readonly statusOptions: ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];

  private allRows: PriorityRow[] = [];
  private kevScores = new Map<string, number>();
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private cveService: CveService,
    private atomicService: AtomicService,
    private sigmaService: SigmaService,
    public epssService: EpssService,
    private attackCveService: AttackCveService,
    private nistMappingService: NistMappingService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Trigger KEV load if not already done
    this.cveService.loadKev();

    this.subs.add(
      combineLatest([
        this.dataService.domain$,
        this.implService.status$,
        this.cveService.kevTechScores$,
      ]).subscribe(([domain, statusMap, kevTechScores]) => {
        if (!domain) return;

        this.kevScores = kevTechScores;

        // Build unique-coverage map: techniqueId → how many mitigations cover it
        const techMitCount = new Map<string, number>();
        for (const [techId, rels] of domain.mitigationsByTechnique.entries()) {
          techMitCount.set(techId, rels.length);
        }

        this.allRows = domain.mitigations.map((mit) => {
          const techniques = domain.techniquesByMitigation.get(mit.id) ?? [];
          const unique = techniques.filter((t) => (techMitCount.get(t.id) ?? 0) === 1).length;
          const groupSet = new Set<string>();
          let kev = 0;
          let atomic = 0;
          let sigma = 0;
          let nist = 0;
          let unifiedSum = 0;
          for (const t of techniques) {
            for (const g of (domain.groupsByTechnique.get(t.id) ?? [])) {
              groupSet.add(g.id);
            }
            kev += kevTechScores.get(t.attackId) ?? 0;
            atomic += this.atomicService.getTestCount(t.attackId);

            const sigmaCount = this.sigmaService.getRuleCount(t.attackId);
            sigma += sigmaCount;

            nist += this.nistMappingService.getControlCount(t.attackId);

            const mitCount = techMitCount.get(t.id) ?? 0;
            const atomicCount = this.atomicService.getTestCount(t.attackId);
            unifiedSum += Math.min(mitCount / 4, 1) * 30
              + Math.min(sigmaCount / 5, 1) * 20
              + Math.min(atomicCount / 3, 1) * 15;
          }
          const unifiedScore = techniques.length > 0
            ? Math.round(unifiedSum / techniques.length)
            : 0;

          return {
            mitigation: mit,
            totalTechniques: techniques.length,
            uniqueTechniques: unique,
            exposureScore: groupSet.size,
            kevScore: kev,
            atomicScore: atomic,
            sigmaScore: sigma,
            nistScore: nist,
            unifiedScore,
            implStatus: statusMap.get(mit.id) ?? null,
          };
        });

        this.applyFilter();
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.filterService.activePanel$.subscribe((panel) => {
        this.visible = panel === 'priority';
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  setSortKey(key: 'unique' | 'total' | 'exposure' | 'kev' | 'atomic' | 'sigma' | 'unified' | 'nist'): void {
    this.sortKey = key;
    this.applyFilter();
    this.cdr.markForCheck();
  }

  onSearch(): void {
    this.applyFilter();
    this.cdr.markForCheck();
  }

  getUnifiedColor(score: number): string {
    if (score <= 15) return '#7f0000';
    if (score <= 30) return '#c62828';
    if (score <= 50) return '#e65100';
    if (score <= 65) return '#f9a825';
    if (score <= 80) return '#558b2f';
    return '#1b5e20';
  }

  private applyFilter(): void {
    const q = this.searchText.toLowerCase().trim();
    let filtered = q
      ? this.allRows.filter(
          (r) =>
            r.mitigation.attackId.toLowerCase().includes(q) ||
            r.mitigation.name.toLowerCase().includes(q),
        )
      : [...this.allRows];

    filtered.sort((a, b) => {
      if (this.sortKey === 'unique') {
        return b.uniqueTechniques !== a.uniqueTechniques
          ? b.uniqueTechniques - a.uniqueTechniques
          : b.totalTechniques - a.totalTechniques;
      } else if (this.sortKey === 'total') {
        return b.totalTechniques !== a.totalTechniques
          ? b.totalTechniques - a.totalTechniques
          : b.uniqueTechniques - a.uniqueTechniques;
      } else if (this.sortKey === 'kev') {
        return b.kevScore !== a.kevScore
          ? b.kevScore - a.kevScore
          : b.totalTechniques - a.totalTechniques;
      } else if (this.sortKey === 'atomic') {
        return b.atomicScore !== a.atomicScore
          ? b.atomicScore - a.atomicScore
          : b.totalTechniques - a.totalTechniques;
      } else if (this.sortKey === 'sigma') {
        return b.sigmaScore !== a.sigmaScore
          ? b.sigmaScore - a.sigmaScore
          : b.totalTechniques - a.totalTechniques;
      } else if (this.sortKey === 'unified') {
        return b.unifiedScore !== a.unifiedScore
          ? b.unifiedScore - a.unifiedScore
          : b.totalTechniques - a.totalTechniques;
      } else if (this.sortKey === 'nist') {
        return b.nistScore !== a.nistScore
          ? b.nistScore - a.nistScore
          : b.totalTechniques - a.totalTechniques;
      } else {
        return b.exposureScore !== a.exposureScore
          ? b.exposureScore - a.exposureScore
          : b.totalTechniques - a.totalTechniques;
      }
    });

    this.rows = filtered;
  }

  setStatus(row: PriorityRow, status: ImplStatus): void {
    const next = row.implStatus === status ? null : status;
    this.implService.setStatus(row.mitigation.id, next);
  }

  filterByMitigation(row: PriorityRow): void {
    this.filterService.filterByMitigation(row.mitigation);
    this.filterService.setActivePanel(null);
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }
}
