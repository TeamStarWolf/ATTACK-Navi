// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription, combineLatest, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { DataService, AttackDomain } from '../../services/data.service';
import { SettingsService } from '../../services/settings.service';
import { ImplementationService, ImplStatus } from '../../services/implementation.service';
import { CveService } from '../../services/cve.service';
import { EpssService, EpssScore } from '../../services/epss.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { ThreatProfilePickerComponent } from '../threat-profile-picker/threat-profile-picker.component';
import { Domain } from '../../models/domain';
import { csvRow } from '../../utils/csv';

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

// The sector aid table now lives only in ThreatProfilePickerComponent (P2-10); the wizard
// uses the picker, so it no longer defines or exports the table.

@Component({
  selector: 'app-assessment-wizard',
  standalone: true,
  imports: [CommonModule, FormsModule, ThreatProfilePickerComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './assessment-wizard.component.html',
  styleUrl: './assessment-wizard.component.scss',
})
export class AssessmentWizardComponent implements OnDestroy {
  currentStep = 1;
  readonly totalSteps = 5;

  // Step 1 — Domain
  selectedDomain: AttackDomain | null = null;
  readonly domainOptions: { value: AttackDomain; label: string; desc: string }[] = [
    { value: 'enterprise', label: 'Enterprise', desc: 'Windows, macOS, Linux, Cloud, Network — the most comprehensive ATT&CK matrix covering corporate IT environments.' },
    { value: 'ics', label: 'ICS', desc: 'Industrial Control Systems — covers SCADA, PLCs, and operational technology environments.' },
    { value: 'mobile', label: 'Mobile', desc: 'Android and iOS — techniques targeting mobile devices and applications.' },
    { value: 'f3', label: 'F3 Fraud Framework', desc: 'CTID\'s Fight Financial Fraud framework — fraud techniques plus the ATT&CK techniques fraud actors reuse. CTID publishes no mitigation mappings yet, so coverage scoring relies on your own statuses.' },
  ];

  // Step 2 — Threat profile. The shared picker edits ThreatProfileService; the
  // resulting profile scopes step 3 and supplies the denominator.
  domain: Domain | null = null;

  // Step 3 — Rate implementation
  tacticAssessments: TacticAssessment[] = [];
  assessmentProgress = 0;
  ratedTechniques = 0;

  /**
   * The assessment denominator: the profile's parent techniques, rolled up so a
   * parent reached only through a sub-technique is included (R4 §3). Reactive, so
   * it tracks the shared profile in one change-detection pass.
   */
  get totalTechniques(): number {
    return this.threatProfile.current.parentTechniqueIds.size;
  }

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
    private panelNav: PanelNavService,
    private dataService: DataService,
    private implService: ImplementationService,
    private cveService: CveService,
    private epssService: EpssService,
    private cdr: ChangeDetectorRef,
    private settingsService: SettingsService,
    private threatProfile: ThreatProfileService,
  ) {}

  ngOnDestroy(): void {
    this.subs.unsubscribe();
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
      case 2: return true;   // the shared picker always holds a profile (default Top 20)
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
        this.cdr.markForCheck();
      }),
    );
  }

  // ─── Step 2: Threat profile ────────────────────────────────────────────────
  // The shared <app-threat-profile-picker mode="profile"> edits ThreatProfileService.
  // "Skip" sets the profile to every technique.

  setSkipGroups(): void {
    this.threatProfile.setSource({ kind: 'all' });
    this.cdr.markForCheck();
  }

  // ─── Step 3: Rate implementation ──────────────────────────────────────────

  private buildAssessment(): void {
    if (!this.domain) return;

    // The techniques to rate are the shared profile's parent techniques, rolled up
    // so a parent reached only through a sub-technique is included ({kind:'all'} is
    // every parent). R4 §3; matches the totalTechniques getter.
    const techniqueIds = new Set(this.threatProfile.current.parentTechniqueIds);

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
        expanded: this.settingsService.current.expandSectionsByDefault,
      }));

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
    // Count UNIQUE technique ids: a multi-tactic technique appears in tacticAssessments
    // once per tactic, but totalTechniques is the unique parent count (parentTechniqueIds).
    const rated = new Set<string>();
    for (const ta of this.tacticAssessments) {
      for (const t of ta.techniques) if (t.status) rated.add(t.id);
    }
    this.ratedTechniques = rated.size;
    this.assessmentProgress = this.totalTechniques > 0
      ? Math.round((this.ratedTechniques / this.totalTechniques) * 100)
      : 0;
  }

  // ─── Step 4: Results ──────────────────────────────────────────────────────

  private computeResults(): void {
    this.totalAssessed = this.totalTechniques;

    // Unique covered technique ids, so coverageCount <= totalAssessed (a multi-tactic
    // technique is counted once); keeps coveragePercent <= 100 and uncoveredFraction >= 0.
    const covered = new Set<string>();
    for (const ta of this.tacticAssessments) {
      for (const tech of ta.techniques) {
        if (tech.status === 'implemented' || tech.status === 'in-progress') covered.add(tech.id);
      }
    }
    this.coverageCount = covered.size;

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
        rows.push(csvRow([
          tech.attackId,
          tech.name,
          tech.status ?? 'unrated',
          tech.actorCount,
          tech.kevCount,
        ]));
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
    this.panelNav.open('matrix');
  }

  openPanel(panel: string): void {
    this.panelNav.open(panel);
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
