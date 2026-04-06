// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService, ImplStatus, IMPL_STATUS_LABELS, IMPL_STATUS_COLORS } from '../../services/implementation.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { Mitigation } from '../../models/mitigation';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';

interface AutoRoadmapPhase {
  quarter: 'Q1' | 'Q2' | 'Q3' | 'Q4';
  label: string;
  color: string;
  mitigations: RoadmapMitigation[];
  techniquesGained: number;
  cvesCovered: number;
}

interface RoadmapMitigation {
  mitigation: Mitigation;
  priorityScore: number;
  techniquesCount: number;
  cveCount: number;
  currentStatus: ImplStatus | null;
}

interface RoadmapItem {
  mitigation: Mitigation;
  techniquesCovered: number;     // unique techniques this mitigation covers
  uncoveredTechniques: number;   // techniques NOT yet fully mitigated
  avgGroupCount: number;         // avg threat groups using covered techniques
  impactScore: number;           // uncoveredTechniques * avgGroupCount
  currentStatus: ImplStatus | null;
  effort: 'Low' | 'Medium' | 'High';
  priorityScore: number;         // impactScore / effortWeight
  tacticsCovered: string[];
}

const EFFORT_MAP: Record<string, RoadmapItem['effort']> = {
  'M1017': 'Low',  // User Training
  'M1018': 'Low',  // User Account Management
  'M1047': 'Low',  // Audit
  'M1049': 'Medium', // Antivirus/Antimalware
  'M1026': 'Low',  // Privileged Account Management
  'M1032': 'Low',  // Multi-factor Authentication
  'M1030': 'Medium', // Network Segmentation
  'M1031': 'Medium', // Network Intrusion Prevention
  'M1035': 'Low',  // Limit Access to Resource Over Network
  'M1036': 'Medium', // Account Use Policies
  'M1037': 'Medium', // Filter Network Traffic
  'M1038': 'Medium', // Execution Prevention
  'M1042': 'Medium', // Disable or Remove Feature or Program
  'M1043': 'High', // Credential Access Protection
  'M1045': 'High', // Code Signing
  'M1050': 'High', // Exploit Protection
  'M1051': 'Medium', // Update Software
  'M1052': 'Low',  // User Account Control
  'M1054': 'Medium', // Software Configuration
};

const EFFORT_WEIGHT: Record<RoadmapItem['effort'], number> = { 'Low': 1, 'Medium': 2, 'High': 4 };

@Component({
  selector: 'app-roadmap-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './roadmap-panel.component.html',
  styleUrl: './roadmap-panel.component.scss',
})
export class RoadmapPanelComponent implements OnInit, OnDestroy {
  open = false;
  domain: Domain | null = null;
  roadmap: RoadmapItem[] = [];
  sortBy: 'priority' | 'impact' | 'coverage' | 'status' = 'priority';
  filterStatus: 'all' | 'unstarted' | 'inprogress' = 'unstarted';
  statusLabels: Record<string, string> = IMPL_STATUS_LABELS;
  statusColors: Record<string, string> = IMPL_STATUS_COLORS;
  implStatusMap = new Map<string, ImplStatus>();
  private subs = new Subscription();

  autoRoadmap: AutoRoadmapPhase[] | null = null;
  generatingRoadmap = false;
  showAutoRoadmap = false;

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private attackCveService: AttackCveService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.filterService.activePanel$.subscribe(panel => {
      this.open = (panel as string) === 'roadmap';
      if (this.open && this.domain) this.buildRoadmap();
      this.cdr.markForCheck();
    }));
    this.subs.add(this.dataService.domain$.subscribe(domain => {
      this.domain = domain;
      if (this.open) this.buildRoadmap();
      this.cdr.markForCheck();
    }));
    this.subs.add(this.implService.status$.subscribe(map => {
      this.implStatusMap = map;
      if (this.open) this.buildRoadmap();
      this.cdr.markForCheck();
    }));
  }

  close(): void { this.filterService.setActivePanel(null); }

  private buildRoadmap(): void {
    if (!this.domain) return;

    const groupsByTech = new Map<string, number>();
    for (const t of this.domain.techniques) {
      groupsByTech.set(t.id, this.dataService.getGroupsForTechnique(t.id).length);
    }

    const items: RoadmapItem[] = this.domain.mitigations.map(mit => {
      const techniques: Technique[] = this.dataService.getTechniquesForMitigation(mit.id);
      const uncovered = techniques.filter(t => {
        const allMits = this.dataService.getMitigationsForTechnique(t.id);
        return !allMits.some(r => this.implStatusMap.get(r.mitigation.id) === 'implemented');
      });
      const avgGroups = techniques.length > 0
        ? techniques.reduce((sum, t) => sum + (groupsByTech.get(t.id) ?? 0), 0) / techniques.length
        : 0;
      const impact = uncovered.length * Math.max(avgGroups, 1);
      const effort = EFFORT_MAP[mit.attackId] ?? 'Medium';
      const priority = impact / EFFORT_WEIGHT[effort];
      const tactics = [...new Set(techniques.flatMap(t => t.tacticShortnames))];
      return {
        mitigation: mit,
        techniquesCovered: techniques.length,
        uncoveredTechniques: uncovered.length,
        avgGroupCount: Math.round(avgGroups * 10) / 10,
        impactScore: Math.round(impact),
        currentStatus: this.implStatusMap.get(mit.id) ?? null,
        effort,
        priorityScore: Math.round(priority * 10) / 10,
        tacticsCovered: tactics.slice(0, 3),
      };
    });

    this.roadmap = items;
    this.cdr.markForCheck();
  }

  get sortedRoadmap(): RoadmapItem[] {
    let items = [...this.roadmap];
    if (this.filterStatus === 'unstarted') items = items.filter(i => !i.currentStatus || i.currentStatus === 'not-started');
    if (this.filterStatus === 'inprogress') items = items.filter(i => i.currentStatus === 'in-progress' || i.currentStatus === 'planned');
    switch (this.sortBy) {
      case 'impact':    return items.sort((a, b) => b.impactScore - a.impactScore).slice(0, 40);
      case 'coverage':  return items.sort((a, b) => b.techniquesCovered - a.techniquesCovered).slice(0, 40);
      case 'status':    return items.sort((a, b) => (a.currentStatus ?? 'zzz').localeCompare(b.currentStatus ?? 'zzz')).slice(0, 40);
      default:          return items.sort((a, b) => b.priorityScore - a.priorityScore).slice(0, 40);
    }
  }

  setStatus(mitId: string, status: ImplStatus): void {
    const current = this.implStatusMap.get(mitId);
    this.implService.setStatus(mitId, current === status ? null : status);
  }

  exportCsv(): void {
    const rows = [
      ['Rank', 'ID', 'Mitigation', 'Techniques Covered', 'Uncovered', 'Avg Groups', 'Impact Score', 'Effort', 'Priority Score', 'Status', 'Tactics'],
      ...this.sortedRoadmap.map((item, i) => [
        i + 1,
        item.mitigation.attackId,
        item.mitigation.name,
        item.techniquesCovered,
        item.uncoveredTechniques,
        item.avgGroupCount,
        item.impactScore,
        item.effort,
        item.priorityScore,
        item.currentStatus ?? 'not-started',
        item.tacticsCovered.join('; '),
      ])
    ];
    const csv = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `remediation_roadmap_${new Date().toISOString().split('T')[0]}.csv`;
    a.click(); URL.revokeObjectURL(url);
  }

  get totalAutoRoadmapCves(): number {
    if (!this.autoRoadmap) return 0;
    return this.autoRoadmap.reduce((sum, phase) => sum + phase.cvesCovered, 0);
  }

  get autoRoadmapPriorityCount(): number {
    if (!this.autoRoadmap || this.autoRoadmap.length < 2) return 0;
    return this.autoRoadmap[0].mitigations.length + this.autoRoadmap[1].mitigations.length;
  }

  generateAutoRoadmap(): void {
    if (!this.domain) return;
    this.generatingRoadmap = true;
    this.cdr.markForCheck();

    setTimeout(() => {
      const domain = this.domain!;
      const statusMap = this.implService.getStatusMap();

      const scored: RoadmapMitigation[] = domain.mitigations.map(mit => {
        const techniques: Technique[] = domain.techniquesByMitigation.get(mit.id) ?? [];
        const cveCount = techniques.filter(t =>
          this.attackCveService.getCvesForTechnique(t.attackId).length > 0
        ).length;
        const groupCount = techniques.reduce((sum, t) =>
          sum + (domain.groupsByTechnique.get(t.id)?.length ?? 0), 0
        );
        const score = (techniques.length * 3) + (cveCount * 5) + (groupCount * 2);
        const status = statusMap.get(mit.id) ?? null;

        return {
          mitigation: mit,
          priorityScore: score,
          techniquesCount: techniques.length,
          cveCount,
          currentStatus: status,
        };
      });

      const pending = scored
        .filter(m => m.currentStatus !== 'implemented')
        .sort((a, b) => b.priorityScore - a.priorityScore);

      const quarterSize = Math.ceil(pending.length / 4);
      const quarters = ['Q1', 'Q2', 'Q3', 'Q4'] as const;
      const labels = ['Critical - Implement Now', 'High Priority', 'Medium Priority', 'Long Term'];
      const colors = ['#f87171', '#fb923c', '#fbbf24', '#4ade80'];

      this.autoRoadmap = quarters.map((q, i) => {
        const slice = pending.slice(i * quarterSize, (i + 1) * quarterSize);
        const techIds = new Set(slice.flatMap(m =>
          (domain.techniquesByMitigation.get(m.mitigation.id) ?? []).map(t => t.id)
        ));
        return {
          quarter: q,
          label: labels[i],
          color: colors[i],
          mitigations: slice,
          techniquesGained: techIds.size,
          cvesCovered: slice.reduce((s, m) => s + m.cveCount, 0),
        };
      });

      this.generatingRoadmap = false;
      this.showAutoRoadmap = true;
      this.cdr.markForCheck();
    }, 500);
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }
}
