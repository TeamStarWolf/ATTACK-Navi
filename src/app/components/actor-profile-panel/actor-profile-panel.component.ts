import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { ThreatGroup } from '../../models/group';
import { AttackSoftware } from '../../models/software';
import { Campaign } from '../../models/campaign';
import { Technique } from '../../models/technique';
import { Domain } from '../../models/domain';

interface GroupProfile {
  group: ThreatGroup;
  techniques: Technique[];
  software: AttackSoftware[];
  campaigns: Campaign[];
  coveredCount: number;
  uncoveredCount: number;
  coveragePct: number;
  tacticBreakdown: { tactic: string; count: number }[];
  topUncovered: Technique[];
}

@Component({
  selector: 'app-actor-profile-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './actor-profile-panel.component.html',
  styleUrl: './actor-profile-panel.component.scss',
})
export class ActorProfilePanelComponent implements OnInit, OnDestroy {
  open = false;
  domain: Domain | null = null;
  allGroups: ThreatGroup[] = [];
  filteredGroups: ThreatGroup[] = [];
  selectedProfile: GroupProfile | null = null;
  searchText = '';
  implStatusMap = new Map<string, string>();
  viewTab: 'overview' | 'techniques' | 'software' | 'campaigns' = 'overview';
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.filterService.activePanel$.subscribe(panel => {
      this.open = (panel as string) === 'actor';
      if (this.open && this.domain) this.loadGroups();
      this.cdr.markForCheck();
    }));
    this.subs.add(this.dataService.domain$.subscribe(domain => {
      this.domain = domain;
      if (this.open && domain) this.loadGroups();
      this.cdr.markForCheck();
    }));
    this.subs.add(this.implService.status$.subscribe(map => {
      this.implStatusMap = map as Map<string, string>;
      this.cdr.markForCheck();
    }));
  }

  private loadGroups(): void {
    if (!this.domain) return;
    this.allGroups = [...this.domain.groups].sort((a, b) => a.name.localeCompare(b.name));
    this.filterGroups();
  }

  filterGroups(): void {
    const q = this.searchText.toLowerCase();
    this.filteredGroups = q
      ? this.allGroups.filter(g => g.name.toLowerCase().includes(q) || g.attackId.toLowerCase().includes(q) || (g.aliases ?? []).some(a => a.toLowerCase().includes(q)))
      : this.allGroups;
    this.cdr.markForCheck();
  }

  selectGroup(group: ThreatGroup): void {
    const techniques = this.dataService.getTechniquesForGroup(group.id);
    const software = this.dataService.getSoftwareForGroup(group.id);
    const campaigns = this.dataService.getCampaignsForGroup(group.id);

    const coveredIds = new Set<string>();
    for (const [mitId, status] of this.implStatusMap.entries()) {
      if (status === 'implemented') {
        const techsForMit = this.dataService.getTechniquesForMitigation(mitId);
        for (const t of techsForMit) coveredIds.add(t.id);
      }
    }

    const coveredCount = techniques.filter(t => coveredIds.has(t.id)).length;
    const uncoveredCount = techniques.length - coveredCount;
    const coveragePct = techniques.length > 0 ? Math.round((coveredCount / techniques.length) * 100) : 0;

    const tacticMap = new Map<string, number>();
    for (const t of techniques) {
      for (const tac of t.tacticShortnames) {
        tacticMap.set(tac, (tacticMap.get(tac) ?? 0) + 1);
      }
    }
    const tacticBreakdown = [...tacticMap.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([tactic, count]) => ({ tactic, count }));

    const topUncovered = techniques
      .filter(t => !coveredIds.has(t.id))
      .sort((a, b) => (b.mitigationCount ?? 0) - (a.mitigationCount ?? 0))
      .slice(0, 10);

    this.selectedProfile = { group, techniques, software, campaigns, coveredCount, uncoveredCount, coveragePct, tacticBreakdown, topUncovered };
    this.viewTab = 'overview';
    this.cdr.markForCheck();
  }

  backToList(): void { this.selectedProfile = null; this.cdr.markForCheck(); }

  filterByGroup(group: ThreatGroup): void {
    this.filterService.toggleThreatGroup(group.id);
    this.filterService.setActivePanel(null);
  }

  selectTechnique(tech: Technique): void {
    this.filterService.selectTechnique(tech);
    this.filterService.setActivePanel(null);
  }

  close(): void { this.filterService.setActivePanel(null); }

  getTechCoverage(techId: string): boolean {
    for (const [mitId, status] of this.implStatusMap.entries()) {
      if (status === 'implemented') {
        const techs = this.dataService.getTechniquesForMitigation(mitId);
        if (techs.some(t => t.id === techId)) return true;
      }
    }
    return false;
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }
}
