import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription, combineLatest } from 'rxjs';
import { ThreatGroup } from '../../models/group';
import { Campaign } from '../../models/campaign';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { CveService } from '../../services/cve.service';

interface GroupRow {
  group: ThreatGroup;
  techniqueCount: number;
  coveredCount: number;
}

interface CampaignRow {
  campaign: Campaign;
  techniqueCount: number;
  coveredCount: number;
  attributedGroupNames: string[];
}

interface GapRow {
  attackId: string;
  name: string;
  tactic: string;
  groupNames: string[];   // which selected groups use this technique
  kevCount: number;
}

@Component({
  selector: 'app-threat-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './threat-panel.component.html',
  styleUrl: './threat-panel.component.scss',
})
export class ThreatPanelComponent implements OnInit, OnDestroy {
  visible = false;
  activeTab: 'groups' | 'campaigns' = 'groups';
  searchText = '';

  // Groups
  filteredGroupRows: GroupRow[] = [];
  activeGroupIds = new Set<string>();
  private allGroupRows: GroupRow[] = [];

  // Campaigns
  filteredCampaignRows: CampaignRow[] = [];
  activeCampaignIds = new Set<string>();
  private allCampaignRows: CampaignRow[] = [];

  // Gap analysis
  gapRows: GapRow[] = [];
  showGapSection = false;

  private domain: import('../../models/domain').Domain | null = null;
  private kevScores = new Map<string, number>();
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private cveService: CveService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      combineLatest([
        this.dataService.domain$,
        this.filterService.activeThreatGroupIds$,
        this.filterService.activeCampaignIds$,
      ]).subscribe(([domain, activeGroupIds, activeCampaignIds]) => {
        this.activeGroupIds = activeGroupIds;
        this.activeCampaignIds = activeCampaignIds;
        this.domain = domain;

        if (domain) {
          const coveredTechIds = new Set([...domain.mitigationsByTechnique.keys()]);

          this.allGroupRows = domain.groups.map((group) => {
            const techniques = domain.techniquesByGroup.get(group.id) ?? [];
            const covered = techniques.filter((t) => coveredTechIds.has(t.id)).length;
            return { group, techniqueCount: techniques.length, coveredCount: covered };
          });

          this.allCampaignRows = domain.campaigns.map((campaign) => {
            const techniques = domain.techniquesByCampaign.get(campaign.id) ?? [];
            const covered = techniques.filter((t) => coveredTechIds.has(t.id)).length;
            const attributedGroupNames = campaign.attributedGroupIds
              .map((gid) => domain.groups.find((g) => g.id === gid)?.name ?? '')
              .filter(Boolean);
            return { campaign, techniqueCount: techniques.length, coveredCount: covered, attributedGroupNames };
          });

          this.applySearch();
          this.computeGaps();
        }
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.cveService.kevTechScores$.subscribe(scores => {
        this.kevScores = scores;
        this.computeGaps();
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.filterService.activePanel$.subscribe((panel) => {
        this.visible = panel === 'threats';
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  setTab(tab: 'groups' | 'campaigns'): void {
    this.activeTab = tab;
    this.searchText = '';
    this.showGapSection = false;
    this.applySearch();
    this.computeGaps();
    this.cdr.markForCheck();
  }

  onSearch(): void {
    this.applySearch();
    this.cdr.markForCheck();
  }

  private applySearch(): void {
    const q = this.searchText.trim().toLowerCase();
    if (!q) {
      this.filteredGroupRows = this.allGroupRows;
      this.filteredCampaignRows = this.allCampaignRows;
      return;
    }
    this.filteredGroupRows = this.allGroupRows.filter(
      (r) =>
        r.group.name.toLowerCase().includes(q) ||
        r.group.attackId.toLowerCase().includes(q) ||
        r.group.aliases.some((a) => a.toLowerCase().includes(q)),
    );
    this.filteredCampaignRows = this.allCampaignRows.filter(
      (r) =>
        r.campaign.name.toLowerCase().includes(q) ||
        r.campaign.attackId.toLowerCase().includes(q) ||
        r.attributedGroupNames.some((n) => n.toLowerCase().includes(q)),
    );
  }

  toggleGroup(row: GroupRow): void {
    this.filterService.toggleThreatGroup(row.group.id);
  }

  private computeGaps(): void {
    if (!this.domain) {
      this.gapRows = [];
      return;
    }
    const coveredTechIds = new Set([...this.domain.mitigationsByTechnique.keys()]);
    const gapMap = new Map<string, GapRow>();

    if (this.activeTab === 'groups') {
      if (this.activeGroupIds.size === 0) { this.gapRows = []; return; }
      for (const groupId of this.activeGroupIds) {
        const group = this.domain.groups.find(g => g.id === groupId);
        if (!group) continue;
        const techniques = this.domain.techniquesByGroup.get(groupId) ?? [];
        for (const tech of techniques) {
          if (coveredTechIds.has(tech.id)) continue;
          if (!gapMap.has(tech.id)) {
            gapMap.set(tech.id, {
              attackId: tech.attackId,
              name: tech.name,
              tactic: tech.tacticShortnames[0] ?? '',
              groupNames: [],
              kevCount: this.kevScores.get(tech.attackId) ?? 0,
            });
          }
          gapMap.get(tech.id)!.groupNames.push(group.name);
        }
      }
    } else {
      if (this.activeCampaignIds.size === 0) { this.gapRows = []; return; }
      for (const campaignId of this.activeCampaignIds) {
        const campaign = this.domain.campaigns.find(c => c.id === campaignId);
        if (!campaign) continue;
        const techniques = this.domain.techniquesByCampaign.get(campaignId) ?? [];
        for (const tech of techniques) {
          if (coveredTechIds.has(tech.id)) continue;
          if (!gapMap.has(tech.id)) {
            gapMap.set(tech.id, {
              attackId: tech.attackId,
              name: tech.name,
              tactic: tech.tacticShortnames[0] ?? '',
              groupNames: [],
              kevCount: this.kevScores.get(tech.attackId) ?? 0,
            });
          }
          gapMap.get(tech.id)!.groupNames.push(campaign.name);
        }
      }
    }

    this.gapRows = [...gapMap.values()]
      .sort((a, b) => (b.kevCount - a.kevCount) || (b.groupNames.length - a.groupNames.length))
      .slice(0, 15);
  }

  toggleCampaign(row: CampaignRow): void {
    this.filterService.toggleCampaign(row.campaign.id);
  }

  clearAll(): void {
    if (this.activeTab === 'groups') {
      this.filterService.clearThreatGroups();
    } else {
      this.filterService.clearCampaigns();
    }
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  get selectedGroupCount(): number { return this.activeGroupIds.size; }
  get selectedCampaignCount(): number { return this.activeCampaignIds.size; }

  get activeSelectionCount(): number {
    return this.activeTab === 'groups' ? this.selectedGroupCount : this.selectedCampaignCount;
  }

  coveragePct(techniqueCount: number, coveredCount: number): number {
    if (!techniqueCount) return 0;
    return Math.round((coveredCount / techniqueCount) * 100);
  }

  formatDate(iso: string): string {
    if (!iso) return '';
    try {
      return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short' });
    } catch {
      return iso.slice(0, 7);
    }
  }
}
