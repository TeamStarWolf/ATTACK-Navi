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
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import {
  EmulationPlanService,
  EmulationPlan,
  EmulationStep,
} from '../../services/emulation-plan.service';
import { LibraryService } from '../../services/library.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { PickerQuickPick, ThreatProfilePickerComponent } from '../threat-profile-picker/threat-profile-picker.component';
import { ThreatGroup } from '../../models/group';
import { Domain } from '../../models/domain';

interface PhaseGroup {
  phase: string;
  steps: EmulationStep[];
}

@Component({
  selector: 'app-emulation-plan-panel',
  standalone: true,
  imports: [CommonModule, ThreatProfilePickerComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './emulation-plan-panel.component.html',
  styleUrls: ['./emulation-plan-panel.component.scss'],
})
export class EmulationPlanPanelComponent implements OnInit, OnDestroy {

  // Data
  domain: Domain | null = null;
  groups: ThreatGroup[] = [];

  // UI state
  selectedGroup: ThreatGroup | null = null;
  plan: EmulationPlan | null = null;
  planError: string | null = null;
  phaseGroups: PhaseGroup[] = [];
  expandedSteps = new Set<number>();
  generating = false;
  savedPlans: EmulationPlan[] = [];

  // Common-actor quick picks, by ATT&CK id. They are the shared picker's quick-select
  // presets (RP-F item 3): the picker resolves them to the loaded domain's STIX groups
  // and selects through its own selectGroup, so the panel has no second selection path.
  readonly quickPicks: readonly PickerQuickPick[] = [
    { label: 'APT28', attackId: 'G0007' },
    { label: 'APT29', attackId: 'G0016' },
    { label: 'APT41', attackId: 'G0096' },
    { label: 'FIN7', attackId: 'G0046' },
    { label: 'Lazarus Group', attackId: 'G0032' },
    { label: 'Sandworm Team', attackId: 'G0034' },
  ];
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private emulationService: EmulationPlanService,
    private libraryService: LibraryService,
    private panelNav: PanelNavService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Follow domain$ for life (like the embedded picker): a domain switch must re-resolve
    // the group list and the quick picks so a later pick lands on the current domain.
    this.subs.add(this.dataService.domain$.subscribe(domain => {
      this.domain = domain;
      this.groups = domain ? [...domain.groups].sort((a, b) => a.name.localeCompare(b.name)) : [];
      // Keep the selection valid for the loaded domain: re-resolve by id, and if the group
      // is gone, clear it and any plan so generatePlan can never run against a stale group
      // (generatePlan now throws for an actor the domain lacks).
      if (this.selectedGroup) {
        const stillHere = this.groups.find(g => g.id === this.selectedGroup!.id) ?? null;
        this.selectedGroup = stillHere;
        if (!stillHere) { this.plan = null; this.phaseGroups = []; this.expandedSteps.clear(); this.planError = null; }
      }
      this.cdr.markForCheck();
    }));
    this.savedPlans = this.emulationService.getSavedPlans();
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  // ─── Setup ────────────────────────────────────────────────────────────────

  // ─── Group selection ──────────────────────────────────────────────────────

  /**
   * The shared picker (single mode) emits a STIX intrusion-set id, from a list item or
   * a Common pick; resolve it to the group. This is the panel's only way to choose a group.
   */
  onGroupPicked(stixId: string): void {
    const group = this.groups.find(g => g.id === stixId);
    if (!group) return;
    this.selectedGroup = group;
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
    this.planError = null;
    this.cdr.markForCheck();

    // Defer to next tick so the spinner renders.
    setTimeout(() => {
      try {
        // generatePlan resolves the actor by STIX id or ATT&CK id and throws if the loaded
        // domain has neither. The picker gives us a STIX id, so the normal path never throws;
        // the try/catch guards the stale-group edge so the button can't hang on "Generating…".
        this.plan = this.emulationService.generatePlan(this.selectedGroup!.id, this.domain!);
        this.phaseGroups = this.groupByPhase(this.plan.steps);
        this.expandedSteps.clear();
      } catch (e) {
        this.plan = null;
        this.phaseGroups = [];
        this.planError = e instanceof Error ? e.message : 'Could not generate the plan.';
      } finally {
        this.generating = false;
        this.cdr.markForCheck();
      }
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
    this.panelNav.open('library');
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

}
