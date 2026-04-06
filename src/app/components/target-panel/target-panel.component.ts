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
import { FormsModule } from '@angular/forms';
import { Subscription, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { Mitigation } from '../../models/mitigation';

interface PlanMitigation {
  mitigation: Mitigation;
  newTechniques: string[];
  cumulativeCoverage: number;
}

@Component({
  selector: 'app-target-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './target-panel.component.html',
  styleUrl: './target-panel.component.scss',
})
export class TargetPanelComponent implements OnInit, OnDestroy {
  visible = false;
  targetPct = 80;
  currentPct = 0;
  gapPct = 0;
  plan: PlanMitigation[] = [];
  computing = false;
  planGenerated = false;

  private cachedDomain: any = null;
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'target';
        if (this.visible) {
          this.loadDomainAndCompute();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  private loadDomainAndCompute(): void {
    if (this.cachedDomain) {
      this.computeCurrentCoverage();
      return;
    }
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      this.cachedDomain = domain;
      this.computeCurrentCoverage();
    });
  }

  computeCurrentCoverage(): void {
    const domain = this.cachedDomain;
    if (!domain) return;
    const parentTechs = domain.techniques.filter((t: any) => !t.isSubtechnique);
    const total = parentTechs.length || 1;
    const covered = parentTechs.filter((t: any) => t.mitigationCount > 0).length;
    this.currentPct = Math.round((covered / total) * 100);
    this.gapPct = Math.max(0, this.targetPct - this.currentPct);
    this.cdr.markForCheck();
  }

  onTargetChange(): void {
    this.gapPct = Math.max(0, this.targetPct - this.currentPct);
    this.planGenerated = false;
    this.plan = [];
    this.cdr.markForCheck();
  }

  get targetReachable(): boolean {
    if (!this.cachedDomain) return true;
    const domain = this.cachedDomain;
    const parentTechs = domain.techniques.filter((t: any) => !t.isSubtechnique);
    const total = parentTechs.length || 1;
    // Max reachable = all parent techs that have at least one mitigation
    const maxCoverable = parentTechs.filter((t: any) => t.mitigationCount > 0).length;
    const maxPct = Math.round((maxCoverable / total) * 100);
    return this.targetPct <= maxPct;
  }

  get additionalTechniquesNeeded(): number {
    if (!this.cachedDomain) return 0;
    const domain = this.cachedDomain;
    const parentTechs = domain.techniques.filter((t: any) => !t.isSubtechnique);
    const total = parentTechs.length || 1;
    const currentCovered = parentTechs.filter((t: any) => t.mitigationCount > 0).length;
    const targetCount = Math.ceil((this.targetPct / 100) * total);
    return Math.max(0, targetCount - currentCovered);
  }

  get totalAdditionalCovered(): number {
    if (!this.plan.length) return 0;
    return this.plan.reduce((sum, p) => sum + p.newTechniques.length, 0);
  }

  generatePlan(): void {
    this.computing = true;
    this.cdr.markForCheck();

    setTimeout(() => {
      const domain = this.cachedDomain;
      if (!domain) { this.computing = false; return; }

      const parentTechs = domain.techniques.filter((t: any) => !t.isSubtechnique);
      const total = parentTechs.length || 1;

      // Techniques currently uncovered (no mitigation at all)
      const uncoveredTechs = new Set<string>(
        parentTechs.filter((t: any) => t.mitigationCount === 0).map((t: any) => t.id),
      );
      let currentCovered = total - uncoveredTechs.size;

      // Build mitigation → parent technique set map (keyed by mitigation STIX id)
      const mitTechMap = new Map<string, Set<string>>();
      for (const [mitId, techs] of (domain.techniquesByMitigation as Map<string, any[]>)) {
        const parentTechIds = new Set<string>(
          (techs as any[]).filter(t => !t.isSubtechnique).map(t => t.id),
        );
        if (parentTechIds.size > 0) mitTechMap.set(mitId, parentTechIds);
      }

      const targetCount = Math.ceil((this.targetPct / 100) * total);
      const plan: PlanMitigation[] = [];
      const usedMits = new Set<string>();
      const stillUncovered = new Set<string>(uncoveredTechs);

      while (currentCovered < targetCount && usedMits.size < domain.mitigations.length) {
        let bestMit: Mitigation | null = null;
        let bestNewTechs: string[] = [];

        for (const [mitId, techs] of mitTechMap) {
          if (usedMits.has(mitId)) continue;
          const newTechs = [...techs].filter(id => stillUncovered.has(id));
          if (newTechs.length > bestNewTechs.length) {
            bestNewTechs = newTechs;
            bestMit = domain.mitigations.find((m: Mitigation) => m.id === mitId) ?? null;
          }
        }

        if (!bestMit || bestNewTechs.length === 0) break;

        usedMits.add(bestMit.id);
        for (const id of bestNewTechs) stillUncovered.delete(id);
        currentCovered += bestNewTechs.length;

        plan.push({
          mitigation: bestMit,
          newTechniques: bestNewTechs,
          cumulativeCoverage: Math.round((currentCovered / total) * 100),
        });
      }

      this.plan = plan;
      this.planGenerated = true;
      this.computing = false;
      this.cdr.markForCheck();
    }, 200);
  }

  get progressSteps(): number[] {
    const steps = [this.currentPct];
    for (const p of this.plan) steps.push(p.cumulativeCoverage);
    return steps;
  }

  attackUrl(mitId: string): string {
    return `https://attack.mitre.org/mitigations/${mitId}/`;
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }
}
