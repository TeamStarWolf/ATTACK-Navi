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
import { ThreatGroup } from '../../models/group';
import { Technique } from '../../models/technique';
import { Domain } from '../../models/domain';

export interface TechniqueRow {
  attackId: string;
  name: string;
  tactics: string[];
  mitigationCount: number;
}

@Component({
  selector: 'app-actor-compare-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './actor-compare-panel.component.html',
  styleUrl: './actor-compare-panel.component.scss',
})
export class ActorComparePanelComponent implements OnInit, OnDestroy {
  visible = false;

  groups: ThreatGroup[] = [];
  actorA: ThreatGroup | null = null;
  actorB: ThreatGroup | null = null;
  searchA = '';
  searchB = '';
  showDropdownA = false;
  showDropdownB = false;
  activeTab: 'overlap' | 'unique-a' | 'unique-b' | 'matrix' = 'overlap';

  techniquesByGroup = new Map<string, Set<string>>();
  techniqueObjectsByAttackId = new Map<string, Technique>();

  private domain: Domain | null = null;
  private mapBuilt = false;
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'actor-compare';
        if (this.visible && !this.mapBuilt) {
          this.loadData();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  private loadData(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      this.domain = domain;
      this.groups = [...domain.groups].sort((a, b) => a.name.localeCompare(b.name));
      this.buildTechniqueObjectIndex(domain);
      this.buildTechniqueMap(domain);
      this.mapBuilt = true;
      this.cdr.markForCheck();
    });
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

  get filteredGroupsA(): ThreatGroup[] {
    const q = this.searchA.trim().toLowerCase();
    return this.groups.filter(g => {
      if (this.actorB && g.id === this.actorB.id) return false;
      if (!q) return true;
      return g.name.toLowerCase().includes(q) || g.attackId.toLowerCase().includes(q);
    });
  }

  get filteredGroupsB(): ThreatGroup[] {
    const q = this.searchB.trim().toLowerCase();
    return this.groups.filter(g => {
      if (this.actorA && g.id === this.actorA.id) return false;
      if (!q) return true;
      return g.name.toLowerCase().includes(q) || g.attackId.toLowerCase().includes(q);
    });
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

  selectActorA(group: ThreatGroup): void {
    this.actorA = group;
    this.searchA = '';
    this.showDropdownA = false;
    this.activeTab = 'overlap';
    this.cdr.markForCheck();
  }

  selectActorB(group: ThreatGroup): void {
    this.actorB = group;
    this.searchB = '';
    this.showDropdownB = false;
    this.activeTab = 'overlap';
    this.cdr.markForCheck();
  }

  clearActorA(): void {
    this.actorA = null;
    this.searchA = '';
    this.cdr.markForCheck();
  }

  clearActorB(): void {
    this.actorB = null;
    this.searchB = '';
    this.cdr.markForCheck();
  }

  setTab(tab: 'overlap' | 'unique-a' | 'unique-b' | 'matrix'): void {
    this.activeTab = tab;
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  attackUrl(attackId: string): string {
    return `https://attack.mitre.org/techniques/${attackId.replace('.', '/')}/`;
  }

  groupUrl(group: ThreatGroup): string {
    return group.url || `https://attack.mitre.org/groups/${group.attackId}/`;
  }

  onSearchAFocus(): void {
    this.showDropdownA = true;
  }

  onSearchBFocus(): void {
    this.showDropdownB = true;
  }

  onSearchABlur(): void {
    setTimeout(() => { this.showDropdownA = false; this.cdr.markForCheck(); }, 150);
  }

  onSearchBBlur(): void {
    setTimeout(() => { this.showDropdownB = false; this.cdr.markForCheck(); }, 150);
  }
}
