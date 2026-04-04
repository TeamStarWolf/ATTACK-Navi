import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  HostListener,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';
import { Campaign } from '../../models/campaign';
import { ThreatGroup } from '../../models/group';

interface CampaignBar {
  campaign: Campaign;
  groupName: string;
  groupColor: string;
  startYear: number;
  endYear: number;
  startPct: number;   // % from left
  widthPct: number;   // % width
  isActive: boolean;  // in activeCampaignIds
  techniqueCount: number;
}

interface GroupFilter {
  id: string;
  name: string;
  color: string;
  count: number;
  selected: boolean;
}

const GROUP_COLORS = [
  '#58a6ff', '#f78166', '#3fb950', '#d2a8ff', '#ffa657',
  '#79c0ff', '#ff7b72', '#56d364', '#bc8cff', '#ffc680',
  '#a5d6ff', '#ffb3ae', '#7ee787', '#d0a9f5', '#ffd8a8',
];

@Component({
  selector: 'app-campaign-timeline-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './campaign-timeline-panel.component.html',
  styleUrl: './campaign-timeline-panel.component.scss',
})
export class CampaignTimelinePanelComponent implements OnInit, OnDestroy {
  open = false;
  domain: Domain | null = null;

  searchText = '';
  viewYear = 'all';
  selectedGroupIds = new Set<string>();

  allBars: CampaignBar[] = [];
  filteredBars: CampaignBar[] = [];
  datedBars: CampaignBar[] = [];
  undatedBars: CampaignBar[] = [];

  groupFilters: GroupFilter[] = [];
  activeCampaignIds = new Set<string>();

  timelineStart = 2006;
  timelineEnd = 2026;
  yearTicks: number[] = [];

  // Stats
  totalCampaigns = 0;
  activeCampaignCount = 0;
  mostActivePeriod = '';

  hoveredCampaign: Campaign | null = null;
  tooltipX = 0;
  tooltipY = 0;

  private groupColorMap = new Map<string, string>();
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.open = p === 'campaign-timeline';
        if (this.open && this.domain) this.build();
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.dataService.domain$.subscribe(d => {
        this.domain = d;
        if (this.open && d) this.build();
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.filterService.activeCampaignIds$.subscribe(ids => {
        this.activeCampaignIds = ids;
        this.updateActiveState();
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  close(): void { this.filterService.setActivePanel(null); }

  private build(): void {
    if (!this.domain) return;
    const domain = this.domain;

    // Build group color map
    const allGroups = new Map<string, ThreatGroup>();
    for (const [, gs] of domain.groupsByTechnique) {
      for (const g of gs) allGroups.set(g.id, g);
    }
    let colorIdx = 0;
    for (const g of allGroups.values()) {
      if (!this.groupColorMap.has(g.id)) {
        this.groupColorMap.set(g.id, GROUP_COLORS[colorIdx % GROUP_COLORS.length]);
        colorIdx++;
      }
    }

    // Determine timeline bounds
    let minYear = 9999, maxYear = 0;
    for (const c of domain.campaigns) {
      if (c.firstSeen) {
        const y = new Date(c.firstSeen).getFullYear();
        if (y < minYear) minYear = y;
      }
      if (c.lastSeen) {
        const y = new Date(c.lastSeen).getFullYear();
        if (y > maxYear) maxYear = y;
      }
    }
    this.timelineStart = Math.min(minYear === 9999 ? 2008 : minYear, 2008);
    this.timelineEnd = Math.max(maxYear === 0 ? 2026 : maxYear + 1, new Date().getFullYear() + 1);
    const range = this.timelineEnd - this.timelineStart;

    // Build year ticks
    this.yearTicks = [];
    for (let y = this.timelineStart; y <= this.timelineEnd; y++) {
      this.yearTicks.push(y);
    }

    // Build bars
    const groupCounts = new Map<string, number>();
    this.allBars = domain.campaigns.map(c => {
      const groupId = c.attributedGroupIds[0] ?? '';
      const group = allGroups.get(groupId);
      const groupName = group?.name ?? 'Unknown';
      const color = this.groupColorMap.get(groupId) ?? '#8b949e';

      // Track group counts for filters
      groupCounts.set(groupId, (groupCounts.get(groupId) ?? 0) + 1);

      const techCount = (domain.techniquesByCampaign.get(c.id) ?? []).length;

      let startYear = 0, endYear = 0;
      if (c.firstSeen) startYear = new Date(c.firstSeen).getFullYear();
      if (c.lastSeen) endYear = new Date(c.lastSeen).getFullYear() + 1;
      else if (startYear) endYear = Math.max(startYear + 1, new Date().getFullYear() + 1);

      const startPct = startYear ? ((startYear - this.timelineStart) / range) * 100 : 0;
      const endPct = endYear ? ((endYear - this.timelineStart) / range) * 100 : 100;

      return {
        campaign: c,
        groupName,
        groupColor: color,
        startYear,
        endYear,
        startPct: Math.max(0, startPct),
        widthPct: Math.max(1, Math.min(endPct, 100) - Math.max(0, startPct)),
        isActive: this.activeCampaignIds.has(c.id),
        techniqueCount: techCount,
      };
    });

    // Sort by first seen date
    this.allBars.sort((a, b) => {
      if (!a.startYear && !b.startYear) return a.campaign.name.localeCompare(b.campaign.name);
      if (!a.startYear) return 1;
      if (!b.startYear) return -1;
      return a.startYear - b.startYear;
    });

    // Build group filter list
    const gfMap = new Map<string, GroupFilter>();
    for (const c of domain.campaigns) {
      const gid = c.attributedGroupIds[0] ?? '';
      const group = allGroups.get(gid);
      if (!gfMap.has(gid)) {
        gfMap.set(gid, {
          id: gid,
          name: group?.name ?? 'Unknown',
          color: this.groupColorMap.get(gid) ?? '#8b949e',
          count: 0,
          selected: true,
        });
      }
      gfMap.get(gid)!.count++;
    }
    this.groupFilters = [...gfMap.values()].sort((a, b) => b.count - a.count).slice(0, 20);

    this.totalCampaigns = domain.campaigns.length;

    // Find most active period (year with most campaigns active)
    const yearActivity = new Map<number, number>();
    for (const bar of this.allBars) {
      if (bar.startYear && bar.endYear) {
        for (let y = bar.startYear; y < bar.endYear; y++) {
          yearActivity.set(y, (yearActivity.get(y) ?? 0) + 1);
        }
      }
    }
    let maxActivity = 0, peakYear = 0;
    for (const [y, count] of yearActivity) {
      if (count > maxActivity) { maxActivity = count; peakYear = y; }
    }
    this.mostActivePeriod = peakYear ? `${peakYear} (${maxActivity} campaigns)` : 'N/A';

    this.applyFilters();
  }

  private applyFilters(): void {
    const q = this.searchText.toLowerCase().trim();
    const selectedGroups = this.groupFilters.filter(g => g.selected).map(g => g.id);
    const selectedGroupSet = new Set(selectedGroups);

    let bars = this.allBars.filter(b => {
      const matchSearch = !q || b.campaign.name.toLowerCase().includes(q) ||
        b.groupName.toLowerCase().includes(q) ||
        b.campaign.aliases.some(a => a.toLowerCase().includes(q));
      const groupId = b.campaign.attributedGroupIds[0] ?? '';
      const matchGroup = selectedGroupSet.size === 0 || selectedGroupSet.has(groupId);
      return matchSearch && matchGroup;
    });

    this.datedBars = bars.filter(b => b.startYear > 0);
    this.undatedBars = bars.filter(b => b.startYear === 0);
    this.filteredBars = bars;
    this.activeCampaignCount = [...this.activeCampaignIds].filter(id =>
      bars.some(b => b.campaign.id === id),
    ).length;
    this.cdr.markForCheck();
  }

  private updateActiveState(): void {
    for (const bar of this.allBars) {
      bar.isActive = this.activeCampaignIds.has(bar.campaign.id);
    }
    this.cdr.markForCheck();
  }

  onSearch(): void { this.applyFilters(); }

  toggleGroupFilter(gf: GroupFilter): void {
    gf.selected = !gf.selected;
    this.applyFilters();
  }

  selectAllGroups(): void {
    this.groupFilters.forEach(g => g.selected = true);
    this.applyFilters();
  }

  clearGroupFilters(): void {
    this.groupFilters.forEach(g => g.selected = false);
    this.applyFilters();
  }

  toggleCampaign(bar: CampaignBar): void {
    this.filterService.toggleCampaign(bar.campaign.id);
    if (!bar.isActive) {
      this.filterService.setHeatmapMode('campaign');
    }
  }

  selectAll(): void {
    for (const bar of this.filteredBars) {
      if (!bar.isActive) this.filterService.toggleCampaign(bar.campaign.id);
    }
    this.filterService.setHeatmapMode('campaign');
  }

  clearAll(): void {
    this.filterService.clearCampaigns();
  }

  onBarHover(event: MouseEvent, bar: CampaignBar): void {
    this.hoveredCampaign = bar.campaign;
    this.tooltipX = event.offsetX + 12;
    this.tooltipY = event.offsetY - 10;
    this.cdr.markForCheck();
  }

  onBarLeave(): void {
    this.hoveredCampaign = null;
    this.cdr.markForCheck();
  }

  getYearPct(year: number): number {
    const range = this.timelineEnd - this.timelineStart;
    return ((year - this.timelineStart) / range) * 100;
  }

  getTechniqueCount(c: Campaign): number {
    return (this.domain?.techniquesByCampaign.get(c.id) ?? []).length;
  }

  get selectedGroupCount(): number {
    return this.groupFilters.filter(g => g.selected).length;
  }

  trackByBar(_: number, bar: CampaignBar): string { return bar.campaign.id; }
  trackByYear(_: number, y: number): number { return y; }
  trackByGroup(_: number, g: GroupFilter): string { return g.id; }

  @HostListener('document:keydown.escape')
  onEsc(): void { if (this.open) this.close(); }
}
