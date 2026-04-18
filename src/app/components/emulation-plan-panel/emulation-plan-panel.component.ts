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
import {
  EmulationPlanService,
  EmulationPlan,
  EmulationStep,
} from '../../services/emulation-plan.service';
import { LibraryService } from '../../services/library.service';
import { ViewModeService } from '../../services/view-mode.service';
import { ThreatGroup } from '../../models/group';
import { Domain } from '../../models/domain';

interface PhaseGroup {
  phase: string;
  steps: EmulationStep[];
}

@Component({
  selector: 'app-emulation-plan-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './emulation-plan-panel.component.html',
  styleUrls: ['./emulation-plan-panel.component.scss'],
})
export class EmulationPlanPanelComponent implements OnInit, OnDestroy {
  visible = false;

  // Data
  domain: Domain | null = null;
  groups: ThreatGroup[] = [];

  // UI state
  groupSearch = '';
  selectedGroup: ThreatGroup | null = null;
  plan: EmulationPlan | null = null;
  phaseGroups: PhaseGroup[] = [];
  expandedSteps = new Set<number>();
  generating = false;
  savedPlans: EmulationPlan[] = [];

  // Common-actor quick picks
  readonly quickPicks: string[] = ['APT28', 'APT29', 'APT41', 'FIN7', 'Lazarus Group', 'Sandworm Team'];

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private emulationService: EmulationPlanService,
    private libraryService: LibraryService,
    private viewModeService: ViewModeService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'emulation';
        if (this.visible) {
          this.ensureGroupsLoaded();
          this.savedPlans = this.emulationService.getSavedPlans();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  // ─── Setup ────────────────────────────────────────────────────────────────

  private ensureGroupsLoaded(): void {
    if (this.groups.length > 0) return;
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      this.domain = domain;
      this.groups = [...domain.groups].sort((a, b) => a.name.localeCompare(b.name));
      this.cdr.markForCheck();
    });
  }

  // ─── Group selection ──────────────────────────────────────────────────────

  get filteredGroups(): ThreatGroup[] {
    const q = this.groupSearch.trim().toLowerCase();
    if (!q) return this.groups.slice(0, 50);
    return this.groups
      .filter(g =>
        g.name.toLowerCase().includes(q) ||
        g.attackId.toLowerCase().includes(q) ||
        g.aliases.some(a => a.toLowerCase().includes(q)),
      )
      .slice(0, 50);
  }

  pickQuickGroup(name: string): void {
    const found = this.groups.find(g =>
      g.name.toLowerCase() === name.toLowerCase() ||
      g.aliases.some(a => a.toLowerCase() === name.toLowerCase()),
    );
    if (found) this.selectGroup(found);
  }

  selectGroup(group: ThreatGroup): void {
    this.selectedGroup = group;
    this.groupSearch = '';
    this.cdr.markForCheck();
  }

  clearGroup(): void {
    this.selectedGroup = null;
    this.plan = null;
    this.phaseGroups = [];
    this.expandedSteps.clear();
    this.cdr.markForCheck();
  }

  // ─── Plan generation ──────────────────────────────────────────────────────

  generatePlan(): void {
    if (!this.selectedGroup || !this.domain) return;
    this.generating = true;
    this.cdr.markForCheck();

    // Defer to next tick so the spinner renders
    setTimeout(() => {
      this.plan = this.emulationService.generatePlan(this.selectedGroup!.attackId, this.domain!);
      this.phaseGroups = this.groupByPhase(this.plan.steps);
      this.expandedSteps.clear();
      this.generating = false;
      this.cdr.markForCheck();
    }, 0);
  }

  private groupByPhase(steps: EmulationStep[]): PhaseGroup[] {
    const map = new Map<string, EmulationStep[]>();
    for (const s of steps) {
      if (!map.has(s.phase)) map.set(s.phase, []);
      map.get(s.phase)!.push(s);
    }
    return Array.from(map, ([phase, steps]) => ({ phase, steps }));
  }

  // ─── Step interaction ─────────────────────────────────────────────────────

  toggleStep(order: number): void {
    if (this.expandedSteps.has(order)) {
      this.expandedSteps.delete(order);
    } else {
      this.expandedSteps.add(order);
    }
    this.cdr.markForCheck();
  }

  isExpanded(order: number): boolean {
    return this.expandedSteps.has(order);
  }

  copyCommand(cmd: string): void {
    navigator.clipboard?.writeText(cmd).catch(() => {});
  }

  /** Library tools relevant to a step's tactic. */
  libraryCountForStep(step: EmulationStep): number {
    // step.phase is the display name; map back to slug
    const slug = step.phase.toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    return this.libraryService.getAssetsForTactic(slug).length;
  }

  jumpToLibrary(): void {
    this.viewModeService.set('library');
    this.close();
  }

  // ─── Saving / loading ─────────────────────────────────────────────────────

  saveCurrentPlan(): void {
    if (!this.plan) return;
    this.emulationService.savePlan(this.plan);
    this.savedPlans = this.emulationService.getSavedPlans();
    this.cdr.markForCheck();
  }

  loadPlan(p: EmulationPlan): void {
    this.plan = p;
    this.phaseGroups = this.groupByPhase(p.steps);
    this.selectedGroup = this.groups.find(g => g.attackId === p.actorId) ?? null;
    this.expandedSteps.clear();
    this.cdr.markForCheck();
  }

  deleteSavedPlan(id: string): void {
    this.emulationService.deletePlan(id);
    this.savedPlans = this.emulationService.getSavedPlans();
    this.cdr.markForCheck();
  }

  // ─── Exports ──────────────────────────────────────────────────────────────

  exportMarkdown(): void {
    if (!this.plan) return;
    const md = this.emulationService.exportMarkdown(this.plan);
    const filename = `emulation-${this.plan.actorId}-${new Date().toISOString().split('T')[0]}.md`;
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    a.click();
    URL.revokeObjectURL(url);
  }

  exportCaldera(): void {
    if (this.plan) this.emulationService.exportCalderaProfile(this.plan);
  }

  exportScythe(): void {
    if (this.plan) this.emulationService.exportScytheCampaign(this.plan);
  }

  exportJson(): void {
    if (this.plan) this.emulationService.exportJson(this.plan);
  }

  // ─── Lifecycle ────────────────────────────────────────────────────────────

  close(): void {
    this.filterService.setActivePanel(null);
  }
}
