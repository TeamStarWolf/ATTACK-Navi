import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription, combineLatest, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService, AttackDomain } from '../../services/data.service';
import { ImplementationService, ImplStatus } from '../../services/implementation.service';
import { CveService } from '../../services/cve.service';
import { EpssService, EpssScore } from '../../services/epss.service';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';
import { ThreatGroup } from '../../models/group';

interface TacticAssessment {
  tacticName: string;
  tacticShortname: string;
  techniques: TechniqueAssessment[];
  expanded: boolean;
}

interface TechniqueAssessment {
  id: string;
  attackId: string;
  name: string;
  status: ImplStatus | null;
  actorCount: number;
  kevCount: number;
  epssMax: number;
}

interface SectorCategory {
  label: string;
  keywords: string[];
}

const SECTOR_CATEGORIES: SectorCategory[] = [
  { label: 'Financial', keywords: ['financial', 'banking', 'payment', 'fin'] },
  { label: 'Government', keywords: ['government', 'military', 'defense', 'intelligence', 'political', 'embassy'] },
  { label: 'Healthcare', keywords: ['health', 'hospital', 'medical', 'pharma'] },
  { label: 'Technology', keywords: ['technology', 'software', 'tech', 'telecom', 'it '] },
  { label: 'Energy', keywords: ['energy', 'oil', 'gas', 'nuclear', 'power', 'utility'] },
  { label: 'Education', keywords: ['education', 'university', 'academic', 'research'] },
];

@Component({
  selector: 'app-assessment-wizard',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './assessment-wizard.component.html',
  styleUrl: './assessment-wizard.component.scss',
})
export class AssessmentWizardComponent implements OnInit, OnDestroy {
  visible = false;
  currentStep = 1;
  readonly totalSteps = 5;

  // Step 1 — Domain
  selectedDomain: AttackDomain | null = null;
  readonly domainOptions: { value: AttackDomain; label: string; desc: string }[] = [
    { value: 'enterprise', label: 'Enterprise', desc: 'Windows, macOS, Linux, Cloud, Network — the most comprehensive ATT&CK matrix covering corporate IT environments.' },
    { value: 'ics', label: 'ICS', desc: 'Industrial Control Systems — covers SCADA, PLCs, and operational technology environments.' },
    { value: 'mobile', label: 'Mobile', desc: 'Android and iOS — techniques targeting mobile devices and applications.' },
  ];

  // Step 2 — Threat profile
  domain: Domain | null = null;
  allGroups: ThreatGroup[] = [];
  filteredGroups: ThreatGroup[] = [];
  selectedGroupIds = new Set<string>();
  groupSearchQuery = '';
  activeSectorFilter: string | null = null;
  skipGroupSelection = false;
  readonly sectorCategories = SECTOR_CATEGORIES;

  // Step 3 — Rate implementation
  tacticAssessments: TacticAssessment[] = [];
  assessmentProgress = 0;
  totalTechniques = 0;
  ratedTechniques = 0;

  // Step 4 — Results
  coverageCount = 0;
  totalAssessed = 0;
  coveragePercent = 0;
  riskScore = 0;
  tacticBreakdown: { name: string; covered: number; total: number; percent: number }[] = [];
  priorityGaps: TechniqueAssessment[] = [];

  // Step 5 — Export
  exportMessage = '';

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private cveService: CveService,
    private epssService: EpssService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'assessment';
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

  // ─── Navigation ──────────────────────────────────────────────────────────

  nextStep(): void {
    if (this.currentStep === 1 && this.selectedDomain) {
      this.loadDomainData();
    }
    if (this.currentStep === 2) {
      this.buildAssessment();
    }
    if (this.currentStep === 3) {
      this.computeResults();
    }
    if (this.currentStep < this.totalSteps) {
      this.currentStep++;
      this.cdr.markForCheck();
    }
  }

  prevStep(): void {
    if (this.currentStep > 1) {
      this.currentStep--;
      this.cdr.markForCheck();
    }
  }

  goToStep(step: number): void {
    if (step >= 1 && step <= this.totalSteps && step <= this.getMaxReachableStep()) {
      if (step === 3 && this.currentStep < 3) this.buildAssessment();
      if (step === 4 && this.currentStep < 4) this.computeResults();
      this.currentStep = step;
      this.cdr.markForCheck();
    }
  }

  getMaxReachableStep(): number {
    if (!this.selectedDomain) return 1;
    if (this.tacticAssessments.length === 0) return 2;
    return this.totalSteps;
  }

  canGoNext(): boolean {
    switch (this.currentStep) {
      case 1: return !!this.selectedDomain;
      case 2: return this.skipGroupSelection || this.selectedGroupIds.size > 0;
      case 3: return true;
      case 4: return true;
      default: return false;
    }
  }

  // ─── Step 1: Domain ───────────────────────────────────────────────────────

  selectDomain(d: AttackDomain): void {
    this.selectedDomain = d;
    this.cdr.markForCheck();
  }

  private loadDomainData(): void {
    if (!this.selectedDomain) return;
    // Switch domain if needed and load data
    this.dataService.switchDomain(this.selectedDomain);
    this.subs.add(
      this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
        this.domain = domain;
        this.allGroups = [...domain.groups].sort((a, b) => a.name.localeCompare(b.name));
        this.filteredGroups = this.allGroups;
        this.cdr.markForCheck();
      }),
    );
  }

  // ─── Step 2: Threat profile ────────────────────────────────────────────────

  filterGroups(): void {
    const q = this.groupSearchQuery.toLowerCase().trim();
    let groups = this.allGroups;

    if (this.activeSectorFilter) {
      const category = SECTOR_CATEGORIES.find(c => c.label === this.activeSectorFilter);
      if (category) {
        groups = groups.filter(g => {
          const desc = g.description.toLowerCase();
          return category.keywords.some(kw => desc.includes(kw));
        });
      }
    }

    if (q) {
      groups = groups.filter(g =>
        g.name.toLowerCase().includes(q) ||
        g.attackId.toLowerCase().includes(q) ||
        g.aliases.some(a => a.toLowerCase().includes(q)),
      );
    }

    this.filteredGroups = groups;
    this.cdr.markForCheck();
  }

  toggleSectorFilter(label: string): void {
    this.activeSectorFilter = this.activeSectorFilter === label ? null : label;
    this.filterGroups();
  }

  toggleGroup(groupId: string): void {
    if (this.selectedGroupIds.has(groupId)) {
      this.selectedGroupIds.delete(groupId);
    } else {
      this.selectedGroupIds.add(groupId);
    }
    this.skipGroupSelection = false;
    this.cdr.markForCheck();
  }

  selectAllVisible(): void {
    for (const g of this.filteredGroups) {
      this.selectedGroupIds.add(g.id);
    }
    this.skipGroupSelection = false;
    this.cdr.markForCheck();
  }

  clearGroups(): void {
    this.selectedGroupIds.clear();
    this.cdr.markForCheck();
  }

  setSkipGroups(): void {
    this.skipGroupSelection = true;
    this.selectedGroupIds.clear();
    this.cdr.markForCheck();
  }

  // ─── Step 3: Rate implementation ──────────────────────────────────────────

  private buildAssessment(): void {
    if (!this.domain) return;

    // Determine which techniques to include
    let techniqueIds: Set<string>;
    if (this.skipGroupSelection) {
      techniqueIds = new Set(this.domain.techniques.filter(t => !t.isSubtechnique).map(t => t.id));
    } else {
      techniqueIds = new Set<string>();
      for (const gid of this.selectedGroupIds) {
        const techs = this.domain.techniquesByGroup.get(gid) ?? [];
        for (const t of techs) {
          if (!t.isSubtechnique) techniqueIds.add(t.id);
        }
      }
    }

    // Build KEV technique set from kevTechScores$ snapshot
    const kevTechIds = new Set<string>();
    this.cveService.kevTechScores$.pipe(take(1)).subscribe(scores => {
      for (const [techId] of scores) {
        kevTechIds.add(techId);
      }
    });

    // Group techniques by tactic
    const tacticMap = new Map<string, TechniqueAssessment[]>();
    const tacticOrder: string[] = [];
    for (const col of this.domain.tacticColumns) {
      const shortname = col.tactic.shortname;
      tacticOrder.push(shortname);
      const assessments: TechniqueAssessment[] = [];
      for (const tech of col.techniques) {
        if (!techniqueIds.has(tech.id)) continue;
        if (tech.isSubtechnique) continue;
        const actorCount = (this.domain.groupsByTechnique.get(tech.id) ?? []).length;
        const kevCount = kevTechIds.has(tech.id) ? 1 : 0;
        assessments.push({
          id: tech.id,
          attackId: tech.attackId,
          name: tech.name,
          status: this.implService.getStatus(tech.id) as ImplStatus | null,
          actorCount,
          kevCount,
          epssMax: 0,
        });
      }
      if (assessments.length > 0) {
        tacticMap.set(shortname, assessments);
      }
    }

    this.tacticAssessments = tacticOrder
      .filter(s => tacticMap.has(s))
      .map(s => ({
        tacticName: s.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
        tacticShortname: s,
        techniques: tacticMap.get(s)!,
        expanded: false,
      }));

    this.totalTechniques = this.tacticAssessments.reduce((sum, ta) => sum + ta.techniques.length, 0);
    this.updateProgress();
    this.cdr.markForCheck();
  }

  setTechniqueStatus(tech: TechniqueAssessment, status: ImplStatus): void {
    tech.status = status;
    this.implService.setStatus(tech.id, status);
    this.updateProgress();
    this.cdr.markForCheck();
  }

  markAllNotStarted(): void {
    for (const ta of this.tacticAssessments) {
      for (const tech of ta.techniques) {
        if (!tech.status) {
          tech.status = 'not-started';
          this.implService.setStatus(tech.id, 'not-started');
        }
      }
    }
    this.updateProgress();
    this.cdr.markForCheck();
  }

  getRatedCount(ta: TacticAssessment): number {
    return ta.techniques.filter(t => !!t.status).length;
  }

  toggleTactic(ta: TacticAssessment): void {
    ta.expanded = !ta.expanded;
    this.cdr.markForCheck();
  }

  expandAllTactics(): void {
    for (const ta of this.tacticAssessments) ta.expanded = true;
    this.cdr.markForCheck();
  }

  collapseAllTactics(): void {
    for (const ta of this.tacticAssessments) ta.expanded = false;
    this.cdr.markForCheck();
  }

  private updateProgress(): void {
    this.ratedTechniques = this.tacticAssessments.reduce(
      (sum, ta) => sum + ta.techniques.filter(t => !!t.status).length, 0,
    );
    this.assessmentProgress = this.totalTechniques > 0
      ? Math.round((this.ratedTechniques / this.totalTechniques) * 100)
      : 0;
  }

  // ─── Step 4: Results ──────────────────────────────────────────────────────

  private computeResults(): void {
    this.totalAssessed = this.totalTechniques;
    this.coverageCount = 0;

    for (const ta of this.tacticAssessments) {
      for (const tech of ta.techniques) {
        if (tech.status === 'implemented' || tech.status === 'in-progress') {
          this.coverageCount++;
        }
      }
    }

    this.coveragePercent = this.totalAssessed > 0
      ? Math.round((this.coverageCount / this.totalAssessed) * 100)
      : 0;

    // Tactic breakdown
    this.tacticBreakdown = this.tacticAssessments.map(ta => {
      const total = ta.techniques.length;
      const covered = ta.techniques.filter(t => t.status === 'implemented' || t.status === 'in-progress').length;
      return {
        name: ta.tacticName,
        covered,
        total,
        percent: total > 0 ? Math.round((covered / total) * 100) : 0,
      };
    });

    // Risk score: 0 (fully covered) to 100 (zero coverage, high KEV/actor exposure)
    const uncoveredFraction = 1 - (this.coverageCount / Math.max(this.totalAssessed, 1));
    const avgActorExposure = this.tacticAssessments.reduce((sum, ta) =>
      sum + ta.techniques.reduce((s2, t) => s2 + (t.status !== 'implemented' ? t.actorCount : 0), 0),
      0,
    ) / Math.max(this.totalAssessed, 1);
    const kevExposure = this.tacticAssessments.reduce((sum, ta) =>
      sum + ta.techniques.filter(t => t.kevCount > 0 && t.status !== 'implemented').length,
      0,
    );
    this.riskScore = Math.min(100, Math.round(
      uncoveredFraction * 50 +
      Math.min(avgActorExposure, 10) * 3 +
      Math.min(kevExposure, 10) * 2,
    ));

    // Priority gaps: uncovered, sorted by KEV + actor count
    const gaps: TechniqueAssessment[] = [];
    for (const ta of this.tacticAssessments) {
      for (const tech of ta.techniques) {
        if (tech.status !== 'implemented' && tech.status !== 'in-progress') {
          gaps.push(tech);
        }
      }
    }
    gaps.sort((a, b) => (b.kevCount * 100 + b.actorCount + b.epssMax * 50)
      - (a.kevCount * 100 + a.actorCount + a.epssMax * 50));
    this.priorityGaps = gaps.slice(0, 10);
    this.cdr.markForCheck();
  }

  getRiskClass(): string {
    if (this.riskScore >= 70) return 'risk-high';
    if (this.riskScore >= 40) return 'risk-medium';
    return 'risk-low';
  }

  // ─── Step 5: Export & Next Steps ──────────────────────────────────────────

  exportCsv(): void {
    const rows: string[] = ['Technique ID,Technique Name,Status,Actor Count,KEV'];
    for (const ta of this.tacticAssessments) {
      for (const tech of ta.techniques) {
        rows.push([
          tech.attackId,
          `"${tech.name.replace(/"/g, '""')}"`,
          tech.status ?? 'unrated',
          tech.actorCount,
          tech.kevCount,
        ].join(','));
      }
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'assessment-export.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    this.exportMessage = 'CSV exported!';
    this.cdr.markForCheck();
    setTimeout(() => { this.exportMessage = ''; this.cdr.markForCheck(); }, 2500);
  }

  applyToMatrix(): void {
    // Statuses already saved via implService during step 3 — just navigate to matrix
    this.filterService.setActivePanel(null);
  }

  openPanel(panel: string): void {
    this.filterService.setActivePanel(panel as any);
  }

  getStatusLabel(status: ImplStatus | null): string {
    switch (status) {
      case 'implemented': return 'Implemented';
      case 'in-progress': return 'In Progress';
      case 'planned': return 'Planned';
      case 'not-started': return 'Not Started';
      default: return 'Unrated';
    }
  }

  getStatusClass(status: ImplStatus | null): string {
    switch (status) {
      case 'implemented': return 'status-implemented';
      case 'in-progress': return 'status-in-progress';
      case 'planned': return 'status-planned';
      case 'not-started': return 'status-not-started';
      default: return 'status-unrated';
    }
  }
}
