// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription, combineLatest } from 'rxjs';
import { Domain } from '../../models/domain';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService, ImplStatus, IMPL_STATUS_LABELS } from '../../services/implementation.service';
import { DocumentationService, MitigationDoc } from '../../services/documentation.service';

interface TacticReport {
  name: string;
  total: number;
  covered: number;
  pct: number;
  topGaps: string[];
}

interface RecommendedMit {
  attackId: string;
  name: string;
  coverage: number;
  uniqueCoverage: number;
}

interface DocumentedMit {
  attackId: string;
  name: string;
  status: string;
  owner: string;
  dueDate: string;
  controlRefs: string;
  evidenceUrl: string;
  notes: string;
}

@Component({
  selector: 'app-report-panel',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './report-panel.component.html',
  styleUrl: './report-panel.component.scss',
})
export class ReportPanelComponent implements OnInit, OnDestroy {
  visible = false;
  domain: Domain | null = null;
  reportDate = '';

  totalTechniques = 0;
  coveredTechniques = 0;
  coveragePct = 0;
  implementedCoveredPct = 0;
  implementedCovered = 0;
  totalMitigations = 0;
  totalGroups = 0;
  totalCampaigns = 0;

  tacticStats: TacticReport[] = [];
  topUncovered: Array<{ attackId: string; name: string; tactics: string }> = [];
  recommendedMits: RecommendedMit[] = [];
  documentedMits: DocumentedMit[] = [];
  implSummary: Record<string, number> = {};
  statusLabels = IMPL_STATUS_LABELS;
  readonly implStatusKeys: ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private docService: DocumentationService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      combineLatest([
        this.dataService.domain$,
        this.implService.status$,
        this.docService.mitDocs$,
      ]).subscribe(([domain, statusMap, mitDocs]) => {
        this.domain = domain;
        if (!domain) return;

        this.reportDate = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
        const parentTechs = domain.techniques.filter((t) => !t.isSubtechnique);
        this.totalTechniques = parentTechs.length;
        this.totalMitigations = domain.mitigations.length;
        this.totalGroups = domain.groups.length;
        this.totalCampaigns = domain.campaigns.length;

        const coveredNow = parentTechs.filter((t) => (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) > 0);
        this.coveredTechniques = coveredNow.length;
        this.coveragePct = Math.round((this.coveredTechniques / this.totalTechniques) * 100);

        // Implemented coverage: technique has at least one mitigation that is "implemented"
        const implementedIds = new Set<string>();
        for (const [mitId, status] of statusMap.entries()) {
          if (status === 'implemented') {
            const techs = domain.techniquesByMitigation.get(mitId) ?? [];
            for (const t of techs) {
              if (!t.isSubtechnique) implementedIds.add(t.id);
            }
          }
        }
        this.implementedCovered = implementedIds.size;
        this.implementedCoveredPct = Math.round((this.implementedCovered / this.totalTechniques) * 100);

        // Impl summary
        this.implSummary = this.implService.summarize();

        // Tactic stats
        this.tacticStats = domain.tacticColumns.map((col) => {
          const parents = col.techniques.filter((t) => !t.isSubtechnique);
          const covered = parents.filter((t) => (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) > 0);
          const gaps = parents
            .filter((t) => (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) === 0)
            .slice(0, 5)
            .map((t) => t.attackId);
          return {
            name: col.tactic.name,
            total: parents.length,
            covered: covered.length,
            pct: parents.length > 0 ? Math.round((covered.length / parents.length) * 100) : 0,
            topGaps: gaps,
          };
        });

        // Top uncovered techniques (by group exposure)
        const uncoveredTechs = parentTechs
          .filter((t) => (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) === 0)
          .map((t) => ({
            attackId: t.attackId,
            name: t.name,
            tactics: t.tacticShortnames.join(', '),
            groupCount: (domain.groupsByTechnique.get(t.id) ?? []).length,
          }))
          .sort((a, b) => b.groupCount - a.groupCount)
          .slice(0, 15);
        this.topUncovered = uncoveredTechs;

        // Recommended mitigations (for uncovered techniques)
        const techMitCount = new Map<string, number>();
        for (const [techId, rels] of domain.mitigationsByTechnique.entries()) {
          techMitCount.set(techId, rels.length);
        }
        const uncoveredIds = new Set(parentTechs.filter((t) => (domain.mitigationsByTechnique.get(t.id)?.length ?? 0) === 0).map((t) => t.id));

        this.recommendedMits = domain.mitigations
          .filter((m) => statusMap.get(m.id) !== 'implemented')
          .map((m) => {
            const techs = (domain.techniquesByMitigation.get(m.id) ?? []).filter((t) => !t.isSubtechnique);
            const newCoverage = techs.filter((t) => uncoveredIds.has(t.id)).length;
            const unique = techs.filter((t) => (techMitCount.get(t.id) ?? 0) === 1).length;
            return { attackId: m.attackId, name: m.name, coverage: techs.length, uniqueCoverage: unique };
          })
          .filter((r) => r.coverage > 0)
          .sort((a, b) => b.uniqueCoverage - a.uniqueCoverage || b.coverage - a.coverage)
          .slice(0, 10);

        // Documented mitigations — any with at least one field filled
        this.documentedMits = domain.mitigations
          .filter((m) => {
            const doc = mitDocs.get(m.id);
            return doc && (doc.notes || doc.owner || doc.dueDate || doc.controlRefs || doc.evidenceUrl);
          })
          .map((m) => {
            const doc = mitDocs.get(m.id)!;
            return {
              attackId: m.attackId,
              name: m.name,
              status: statusMap.has(m.id) ? IMPL_STATUS_LABELS[statusMap.get(m.id)!] : '—',
              owner: doc.owner,
              dueDate: doc.dueDate,
              controlRefs: doc.controlRefs,
              evidenceUrl: doc.evidenceUrl,
              notes: doc.notes,
            };
          })
          .sort((a, b) => a.attackId.localeCompare(b.attackId));

        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.filterService.activePanel$.subscribe((panel) => {
        this.visible = panel === 'report';
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  print(): void {
    window.print();
  }

  exportCsv(): void {
    if (!this.domain) return;
    const rows = [
      'Technique ID,Technique Name,Tactics,Platforms,Mitigations,Threat Groups,Covered',
    ];
    for (const t of this.domain.techniques.filter((t) => !t.isSubtechnique)) {
      const mitCount = this.domain.mitigationsByTechnique.get(t.id)?.length ?? 0;
      const groupCount = this.domain.groupsByTechnique.get(t.id)?.length ?? 0;
      rows.push([
        t.attackId,
        `"${t.name.replace(/"/g, '""')}"`,
        `"${t.tacticShortnames.join('; ')}"`,
        `"${t.platforms.join('; ')}"`,
        mitCount,
        groupCount,
        mitCount > 0 ? 'Yes' : 'No',
      ].join(','));
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `mitre-coverage-report-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  pctColor(pct: number): string {
    if (pct >= 80) return '#4caf50';
    if (pct >= 50) return '#ff9800';
    return '#e53935';
  }
}
