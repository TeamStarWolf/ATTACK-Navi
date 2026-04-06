// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';
import { ThreatGroup } from '../../models/group';
import { Technique } from '../../models/technique';

interface CompTechnique {
  tech: Technique;
  side: 'a-only' | 'both' | 'b-only';
}

@Component({
  selector: 'app-comparison-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './comparison-panel.component.html',
  styleUrl: './comparison-panel.component.scss',
})
export class ComparisonPanelComponent implements OnInit, OnDestroy {
  open = false;
  domain: Domain | null = null;
  groups: ThreatGroup[] = [];
  selectedIdA = '';
  selectedIdB = '';
  aOnly: Technique[] = [];
  both: Technique[] = [];
  bOnly: Technique[] = [];
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.filterService.activePanel$.subscribe(p => {
      this.open = p === 'comparison';
      this.cdr.markForCheck();
    }));
    this.subs.add(this.dataService.domain$.subscribe(d => {
      this.domain = d;
      // Collect all unique groups from domain
      if (d) {
        const groupMap = new Map<string, ThreatGroup>();
        for (const [, gs] of d.groupsByTechnique) {
          for (const g of gs) groupMap.set(g.id, g);
        }
        this.groups = [...groupMap.values()].sort((a, b) => a.name.localeCompare(b.name));
      }
      this.compute();
      this.cdr.markForCheck();
    }));
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  close(): void { this.filterService.setActivePanel(null); }

  compute(): void {
    if (!this.domain || !this.selectedIdA || !this.selectedIdB || this.selectedIdA === this.selectedIdB) {
      this.aOnly = []; this.both = []; this.bOnly = [];
      return;
    }
    // Get technique STIX ids used by each group using techniquesByGroup map
    // techniquesByGroup maps group.id (STIX id) to Technique[]
    // But selectedIdA/B are attackId (G-prefix). Need to find the STIX id.
    const groupA = this.groups.find(g => g.attackId === this.selectedIdA);
    const groupB = this.groups.find(g => g.attackId === this.selectedIdB);
    if (!groupA || !groupB) { this.aOnly = []; this.both = []; this.bOnly = []; return; }

    const techsA = new Set((this.domain.techniquesByGroup.get(groupA.id) ?? []).map(t => t.id));
    const techsB = new Set((this.domain.techniquesByGroup.get(groupB.id) ?? []).map(t => t.id));

    const allIds = new Set([...techsA, ...techsB]);
    const aOnly: Technique[] = [], both: Technique[] = [], bOnly: Technique[] = [];

    for (const id of allIds) {
      const tech = this.domain.techniques.find(t => t.id === id);
      if (!tech || tech.parentId) continue; // skip sub-techniques for clarity
      if (techsA.has(id) && techsB.has(id)) both.push(tech);
      else if (techsA.has(id)) aOnly.push(tech);
      else bOnly.push(tech);
    }

    this.aOnly = aOnly.sort((a, b) => a.attackId.localeCompare(b.attackId));
    this.both = both.sort((a, b) => a.attackId.localeCompare(b.attackId));
    this.bOnly = bOnly.sort((a, b) => a.attackId.localeCompare(b.attackId));
    this.cdr.markForCheck();
  }

  get overlapPct(): number {
    const total = this.aOnly.length + this.both.length + this.bOnly.length;
    return total > 0 ? Math.round((this.both.length / total) * 100) : 0;
  }

  selectTechnique(tech: Technique): void {
    this.filterService.selectTechnique(tech);
  }

  filterByGroup(attackId: string): void {
    if (!this.domain) return;
    const g = this.groups.find(g => g.attackId === attackId);
    if (g) {
      this.filterService.toggleThreatGroup(g.id);
      this.filterService.setActivePanel('threats');
    }
  }
}
