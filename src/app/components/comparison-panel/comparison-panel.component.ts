// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';

import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';
import { ThreatGroup } from '../../models/group';
import { Technique } from '../../models/technique';
import { ThreatProfilePickerComponent } from '../threat-profile-picker/threat-profile-picker.component';

@Component({
  selector: 'app-comparison-panel',
  standalone: true,
  imports: [ThreatProfilePickerComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './comparison-panel.component.html',
  styleUrl: './comparison-panel.component.scss',
})
export class ComparisonPanelComponent implements OnInit, OnDestroy {
  domain: Domain | null = null;
  groups: ThreatGroup[] = [];
  groupA: ThreatGroup | null = null;
  groupB: ThreatGroup | null = null;
  aOnly: Technique[] = [];
  both: Technique[] = [];
  bOnly: Technique[] = [];
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private panelNav: PanelNavService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.dataService.domain$.subscribe(d => {
      this.domain = d;
      if (d) {
        const groupMap = new Map<string, ThreatGroup>();
        for (const [, gs] of d.groupsByTechnique) {
          for (const g of gs) groupMap.set(g.id, g);
        }
        this.groups = [...groupMap.values()].sort((a, b) => a.name.localeCompare(b.name));
        // Drop a selection the new domain lacks, so compare never runs stale.
        const stillHere = (g: ThreatGroup | null) => g && groupMap.has(g.id) ? g : null;
        this.groupA = stillHere(this.groupA);
        this.groupB = stillHere(this.groupB);
      } else {
        this.groups = []; this.groupA = null; this.groupB = null;
      }
      this.compute();
      this.cdr.markForCheck();
    }));
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  /** The shared picker (single mode) emits a STIX intrusion-set id. */
  onPickA(stixId: string): void {
    this.groupA = this.groups.find(g => g.id === stixId) ?? null;
    this.compute();
    this.cdr.markForCheck();
  }

  onPickB(stixId: string): void {
    this.groupB = this.groups.find(g => g.id === stixId) ?? null;
    this.compute();
    this.cdr.markForCheck();
  }

  clearA(): void { this.groupA = null; this.compute(); this.cdr.markForCheck(); }
  clearB(): void { this.groupB = null; this.compute(); this.cdr.markForCheck(); }

  compute(): void {
    if (!this.domain || !this.groupA || !this.groupB || this.groupA.id === this.groupB.id) {
      this.aOnly = []; this.both = []; this.bOnly = [];
      return;
    }
    // techniquesByGroup is keyed by group STIX id; the pickers give us STIX ids.
    const techsA = new Set((this.domain.techniquesByGroup.get(this.groupA.id) ?? []).map(t => t.id));
    const techsB = new Set((this.domain.techniquesByGroup.get(this.groupB.id) ?? []).map(t => t.id));

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
  }

  get overlapPct(): number {
    const total = this.aOnly.length + this.both.length + this.bOnly.length;
    return total > 0 ? Math.round((this.both.length / total) * 100) : 0;
  }

  selectTechnique(tech: Technique): void {
    this.filterService.selectTechnique(tech);
  }

  filterByGroup(group: ThreatGroup | null): void {
    if (!group) return;
    this.filterService.toggleThreatGroup(group.id);
    this.panelNav.open('threats');
  }
}
