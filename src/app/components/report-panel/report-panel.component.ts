// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Signal,
  computed,
  inject,
  signal,
} from '@angular/core';

import { Subscription, combineLatest } from 'rxjs';
import { Domain } from '../../models/domain';
import { DataService } from '../../services/data.service';
import { ImplementationService, ImplStatus, IMPL_STATUS_LABELS } from '../../services/implementation.service';
import { DocumentationService, MitigationDoc } from '../../services/documentation.service';
import { ReportConfigService, ReportSection } from '../../services/report-config.service';
import { csvRow } from '../../utils/csv';
import {
  ReportSplit,
  TacticSplit,
  computeReportSplit,
  partialCardLines,
  isTechniqueMapped,
  REPORT_SPLIT_LABELS,
} from '../../models/report-split';
import { PostureService } from '../../services/posture.service';
import { PROVEN } from '../../models/posture/posture-vocabulary';
import type { PostureBucket } from '../../models/posture/posture.types';

/**
 * One tactic row of the split: Known and its Theoretical sub-line from
 * reference mapping, the posture buckets from PostureService.rollup. See
 * models/report-split.ts.
 */
interface TacticReport extends TacticSplit {
  topGaps: string[];
}

/**
 * The report-builder CSV's Implemented cell for one technique (P2-07): the
 * same per-technique answer the posture card counts. 'Yes' for covered,
 * proven and stale, 'Partial' for partial, 'No' otherwise.
 */
export const CSV_IMPLEMENTED_CELL: Readonly<Record<PostureBucket, 'Yes' | 'Partial' | 'No'>> = {
  covered: 'Yes', proven: 'Yes', stale: 'Yes', partial: 'Partial', known: 'No', none: 'No',
};

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
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './report-panel.component.html',
  styleUrl: './report-panel.component.scss',
})
export class ReportPanelComponent implements OnInit, OnDestroy {
  domain: Domain | null = null;
  reportDate = '';

  readonly labels = REPORT_SPLIT_LABELS;
  readonly provenLabel = PROVEN;

  private readonly posture = inject(PostureService);
  /** Covered and Proven words render only when the owner has recorded data (§2.4). */
  readonly ownerWords: Signal<boolean> = this.posture.ownerWords;
  private readonly domainSig = signal<Domain | null>(null);
  private readonly implementedMitigations = signal(0);
  /**
   * The split, recomputed from PostureService.rollup whenever the posture
   * states change: the same numbers as the posture card, the Validation
   * summary, the stats-bar and the HTML and PDF reports.
   */
  /** The partial card's per-cause lines (RP-F decision 36). */
  readonly partialLines = computed(() => {
    const s = this.split();
    return s ? partialCardLines(s) : [];
  });

  readonly split: Signal<ReportSplit | null> = computed(() => {
    const domain = this.domainSig();
    return domain ? computeReportSplit(domain, this.posture.rollup(), this.implementedMitigations()) : null;
  });
  /** Tactic rows of the split, with the first five unmapped techniques. */
  readonly tacticStats: Signal<TacticReport[]> = computed(() =>
    (this.split()?.byTactic ?? []).map(ts => ({ ...ts, topGaps: ts.unmappedIds.slice(0, 5) })));

  totalMitigations = 0;
  totalGroups = 0;
  totalCampaigns = 0;

  topUncovered: Array<{ attackId: string; name: string; tactics: string }> = [];
  recommendedMits: RecommendedMit[] = [];
  documentedMits: DocumentedMit[] = [];
  implSummary: Record<string, number> = {};
  statusLabels = IMPL_STATUS_LABELS;
  readonly implStatusKeys: ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];

  // Report Builder config (section visibility + order) — drives this on-screen
  // preview AND the exported HTML report.
  allSections: ReportSection[] = [];
  configOpen = false;

  private subs = new Subscription();

  constructor(
    private dataService: DataService,
    private implService: ImplementationService,
    private docService: DocumentationService,
    private reportConfig: ReportConfigService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Keep the drawer + preview in sync with the saved report config.
    this.subs.add(
      this.reportConfig.config$.subscribe(config => {
        this.allSections = [...config.sections].sort((a, b) => a.order - b.order);
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      combineLatest([
        this.dataService.domain$,
        this.implService.status$,
        this.docService.mitDocs$,
      ]).subscribe(([domain, statusMap, mitDocs]) => {
        this.domain = domain;
        if (!domain) {
          this.domainSig.set(null);
          return;
        }

        this.reportDate = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
        const parentTechs = domain.techniques.filter((t) => !t.isSubtechnique);
        this.totalMitigations = domain.mitigations.length;
        this.totalGroups = domain.groups.length;
        this.totalCampaigns = domain.campaigns.length;

        // Impl summary (mitigations by status). The split (one shared
        // computation for the panel, the HTML export and the PDF report) takes
        // the implemented mitigation count from it.
        this.implSummary = this.implService.summarize();
        this.implementedMitigations.set(this.implSummary['implemented'] ?? 0);
        this.domainSig.set(domain);

        // Techniques with no mitigation mapped, by adversary use
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
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  // ─── Report Builder config ──────────────────────────────────────────────
  toggleConfig(): void {
    this.configOpen = !this.configOpen;
    this.cdr.markForCheck();
  }

  toggleSection(id: string): void {
    this.reportConfig.toggleSection(id);
    this.cdr.markForCheck();
  }

  moveSection(id: string, direction: 'up' | 'down'): void {
    this.reportConfig.moveSection(id, direction);
    this.cdr.markForCheck();
  }

  resetSections(): void {
    this.reportConfig.resetDefaults();
    this.cdr.markForCheck();
  }

  isSectionVisible(id: string): boolean {
    const section = this.allSections.find(s => s.id === id);
    // Unknown ids default to visible (forward-compatible with new sections).
    return section ? section.visible : true;
  }

  sectionOrder(id: string): number {
    const section = this.allSections.find(s => s.id === id);
    return section ? section.order : 0;
  }

  orderedSections(): ReportSection[] {
    return this.allSections.filter(s => s.visible);
  }

  print(): void {
    window.print();
  }

  exportCsv(): void {
    if (!this.domain) return;
    // Theoretical (reference mapping) and Implemented (self-attested) are
    // separate columns: a mapped mitigation is never reported as implemented.
    // The Implemented cell is the technique's posture bucket (P2-07), so a broad
    // mitigation reads 'Partial' until the technique is confirmed.
    const rows = [
      `Technique ID,Technique Name,Tactics,Platforms,Mitigations Mapped,Threat Groups,${REPORT_SPLIT_LABELS.theoretical},${REPORT_SPLIT_LABELS.implemented}`,
    ];
    for (const t of this.domain.techniques.filter((t) => !t.isSubtechnique)) {
      const mitCount = this.domain.mitigationsByTechnique.get(t.id)?.length ?? 0;
      const groupCount = this.domain.groupsByTechnique.get(t.id)?.length ?? 0;
      rows.push(csvRow([
        t.attackId,
        t.name,
        t.tacticShortnames.join('; '),
        t.platforms.join('; '),
        mitCount,
        groupCount,
        isTechniqueMapped(t) ? 'Yes' : 'No',
        CSV_IMPLEMENTED_CELL[this.posture.stateFor(t).bucket],
      ]));
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `mitre-coverage-report-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

}
