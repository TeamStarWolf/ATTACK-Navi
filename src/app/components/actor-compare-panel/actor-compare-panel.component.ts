// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';

import { Subscription } from 'rxjs';
import { DataService } from '../../services/data.service';
import { ThreatGroup } from '../../models/group';
import { Technique } from '../../models/technique';
import { Domain } from '../../models/domain';
import { ThreatProfilePickerComponent } from '../threat-profile-picker/threat-profile-picker.component';

export interface TechniqueRow {
  attackId: string;
  name: string;
  tactics: string[];
  mitigationCount: number;
}

@Component({
  selector: 'app-actor-compare-panel',
  standalone: true,
  imports: [ThreatProfilePickerComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './actor-compare-panel.component.html',
  styleUrl: './actor-compare-panel.component.scss',
})
export class ActorComparePanelComponent implements OnInit, OnDestroy {

  groups: ThreatGroup[] = [];
  actorA: ThreatGroup | null = null;
  actorB: ThreatGroup | null = null;
  activeTab: 'overlap' | 'unique-a' | 'unique-b' | 'matrix' = 'overlap';

  techniquesByGroup = new Map<string, Set<string>>();
  techniqueObjectsByAttackId = new Map<string, Technique>();

  private domain: Domain | null = null;
  private subs = new Subscription();

  constructor(
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.loadData();
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  // Follow domain$ for life: the embedded pickers track the domain, so when it
  // switches we rebuild the group index and drop any selection the new domain
  // lacks, rather than comparing against a stale map.
  private loadData(): void {
    this.subs.add(this.dataService.domain$.subscribe(domain => {
      this.domain = domain;
      if (!domain) { this.groups = []; this.actorA = null; this.actorB = null; this.cdr.markForCheck(); return; }
      this.groups = [...domain.groups].sort((a, b) => a.name.localeCompare(b.name));
      this.techniqueObjectsByAttackId.clear();
      this.buildTechniqueObjectIndex(domain);
      this.buildTechniqueMap(domain);
      // Re-resolve a kept selection from the NEW domain's groups (never keep the stale
      // object); a selection the new domain lacks is dropped.
      const reResolve = (a: ThreatGroup | null) => a ? (domain.groups.find(g => g.id === a.id) ?? null) : null;
      this.actorA = reResolve(this.actorA);
      this.actorB = reResolve(this.actorB);
      this.cdr.markForCheck();
    }));
  }

  private buildTechniqueObjectIndex(domain: Domain): void {
    for (const tech of domain.techniques) {
      if (!tech.isSubtechnique) {
        this.techniqueObjectsByAttackId.set(tech.attackId, tech);
      }
    }
  }

  buildTechniqueMap(domain: Domain): void {
    this.techniquesByGroup.clear();
    for (const tech of domain.techniques.filter(t => !t.isSubtechnique)) {
      const groups = this.dataService.getGroupsForTechnique(tech.id);
      for (const g of groups) {
        if (!this.techniquesByGroup.has(g.id)) {
          this.techniquesByGroup.set(g.id, new Set());
        }
        this.techniquesByGroup.get(g.id)!.add(tech.attackId);
      }
    }
  }

  private getTechSetA(): Set<string> {
    if (!this.actorA) return new Set();
    return this.techniquesByGroup.get(this.actorA.id) ?? new Set();
  }

  private getTechSetB(): Set<string> {
    if (!this.actorB) return new Set();
    return this.techniquesByGroup.get(this.actorB.id) ?? new Set();
  }

  get overlapIds(): string[] {
    const a = this.getTechSetA();
    const b = this.getTechSetB();
    return [...a].filter(id => b.has(id)).sort();
  }

  get uniqueToAIds(): string[] {
    const a = this.getTechSetA();
    const b = this.getTechSetB();
    return [...a].filter(id => !b.has(id)).sort();
  }

  get uniqueToBIds(): string[] {
    const a = this.getTechSetA();
    const b = this.getTechSetB();
    return [...b].filter(id => !a.has(id)).sort();
  }

  get unionSize(): number {
    const a = this.getTechSetA();
    const b = this.getTechSetB();
    const union = new Set([...a, ...b]);
    return union.size;
  }

  get overlapPct(): number {
    const union = this.unionSize;
    if (!union) return 0;
    return Math.round((this.overlapIds.length / union) * 100);
  }

  /** Both pickers resolved to the same group — a self-comparison, which the panel refuses. */
  get sameGroup(): boolean {
    return !!(this.actorA && this.actorB && this.actorA.id === this.actorB.id);
  }

  get techCountA(): number {
    return this.getTechSetA().size;
  }

  get techCountB(): number {
    return this.getTechSetB().size;
  }

  toRows(attackIds: string[]): TechniqueRow[] {
    return attackIds.map(id => {
      const tech = this.techniqueObjectsByAttackId.get(id);
      if (!tech) return { attackId: id, name: '', tactics: [], mitigationCount: 0 };
      return {
        attackId: tech.attackId,
        name: tech.name,
        tactics: tech.tacticShortnames,
        mitigationCount: tech.mitigationCount,
      };
    });
  }

  get overlapRows(): TechniqueRow[] {
    return this.toRows(this.overlapIds).sort((a, b) => b.mitigationCount - a.mitigationCount);
  }

  get uniqueToARows(): TechniqueRow[] {
    return this.toRows(this.uniqueToAIds);
  }

  get uniqueToBRows(): TechniqueRow[] {
    return this.toRows(this.uniqueToBIds);
  }

  get tacticColumns(): Array<{ tactic: string; overlap: string[]; uniqueA: string[]; uniqueB: string[] }> {
    if (!this.domain) return [];
    const overlapSet = new Set(this.overlapIds);
    const uniqueASet = new Set(this.uniqueToAIds);
    const uniqueBSet = new Set(this.uniqueToBIds);

    return this.domain.tacticColumns.map(col => {
      const overlap: string[] = [];
      const uniqueA: string[] = [];
      const uniqueB: string[] = [];
      for (const tech of col.techniques) {
        if (overlapSet.has(tech.attackId)) overlap.push(tech.attackId);
        else if (uniqueASet.has(tech.attackId)) uniqueA.push(tech.attackId);
        else if (uniqueBSet.has(tech.attackId)) uniqueB.push(tech.attackId);
      }
      return { tactic: col.tactic.name, overlap, uniqueA, uniqueB };
    }).filter(col => col.overlap.length > 0 || col.uniqueA.length > 0 || col.uniqueB.length > 0);
  }

  /** The shared picker (single mode) emits a STIX intrusion-set id; resolve it to the group. */
  onPickA(stixId: string): void {
    this.actorA = this.groups.find(g => g.id === stixId) ?? null;
    this.activeTab = 'overlap';
    this.cdr.markForCheck();
  }

  onPickB(stixId: string): void {
    this.actorB = this.groups.find(g => g.id === stixId) ?? null;
    this.activeTab = 'overlap';
    this.cdr.markForCheck();
  }

  clearActorA(): void {
    this.actorA = null;
    this.cdr.markForCheck();
  }

  clearActorB(): void {
    this.actorB = null;
    this.cdr.markForCheck();
  }

  setTab(tab: 'overlap' | 'unique-a' | 'unique-b' | 'matrix'): void {
    this.activeTab = tab;
  }

  attackUrl(attackId: string): string {
    return `https://attack.mitre.org/techniques/${attackId.replace('.', '/')}/`;
  }

  groupUrl(group: ThreatGroup): string {
    return group.url || `https://attack.mitre.org/groups/${group.attackId}/`;
  }
}
