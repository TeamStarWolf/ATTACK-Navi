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
import { Subscription, combineLatest, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { MispService, MispGalaxyCluster } from '../../services/misp.service';
import { OpenCtiService, OpenCtiIndicator } from '../../services/opencti.service';
import { Domain } from '../../models/domain';

export interface IntelRow {
  attackId: string;
  name: string;
  mispCluster: boolean;
  groupCount: number;
  intelScore: number;
}

interface IndicatorRow {
  source: 'MISP' | 'OpenCTI';
  type: string;
  value: string;
  confidence: number;
  lastUpdated: string;
}

interface ActorRow {
  name: string;
  aliases: string[];
  techniqueCount: number;
  source: 'ATT&CK' | 'OpenCTI';
  groupId: string;
}

interface MispEventRow {
  info: string;
  date: string;
  org: string;
  attributeCount: number;
  threatLevel: string;
}

@Component({
  selector: 'app-threat-intelligence-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './threat-intelligence-panel.component.html',
  styleUrl: './threat-intelligence-panel.component.scss',
})
export class ThreatIntelligencePanelComponent implements OnInit, OnDestroy {
  visible = false;
  activeTab: 'overview' | 'indicators' | 'actors' | 'misp' = 'overview';

  // Overview
  galaxyClustersLoaded = 0;
  openCtiConnected = false;
  totalGroups = 0;
  totalWithIntel = 0;
  topIntelRows: IntelRow[] = [];

  // Indicators
  indicatorSearch = '';
  indicatorRows: IndicatorRow[] = [];
  indicatorLoading = false;

  // Actors
  actorSearch = '';
  actorRows: ActorRow[] = [];
  allActorRows: ActorRow[] = [];

  // MISP Events
  mispConnected = false;
  mispSearch = '';
  mispEventRows: MispEventRow[] = [];
  mispEventTemplate = '';

  private domain: Domain | null = null;
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private mispService: MispService,
    private openCtiService: OpenCtiService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'intelligence';
        if (this.visible && this.topIntelRows.length === 0) {
          this.buildOverview();
        }
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.openCtiService.connected$.subscribe(c => {
        this.openCtiConnected = c;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.mispService.total$.subscribe(total => {
        this.galaxyClustersLoaded = total;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.dataService.domain$.subscribe(d => {
        this.domain = d;
        if (d) {
          this.totalGroups = d.groups.length;
          this.buildActors();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  setTab(tab: 'overview' | 'indicators' | 'actors' | 'misp'): void {
    this.activeTab = tab;
    this.cdr.markForCheck();
  }

  // ─── Overview ─────────────────────────────────────────────────────────────

  buildOverview(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      const rows: IntelRow[] = [];
      for (const tech of domain.techniques) {
        if (tech.isSubtechnique) continue;
        const hasMisp = this.mispService.hasMisp(tech.attackId);
        const groupCount = (domain.groupsByTechnique.get(tech.id) ?? []).length;
        const score = (hasMisp ? 1 : 0) + groupCount;
        rows.push({
          attackId: tech.attackId,
          name: tech.name,
          mispCluster: hasMisp,
          groupCount,
          intelScore: score,
        });
      }
      this.totalWithIntel = rows.filter(r => r.intelScore > 0).length;
      this.topIntelRows = rows
        .sort((a, b) => b.intelScore - a.intelScore)
        .slice(0, 20);
      this.cdr.markForCheck();
    });
  }

  // ─── Indicators ───────────────────────────────────────────────────────────

  searchIndicators(): void {
    const q = this.indicatorSearch.trim();
    if (!q) {
      this.indicatorRows = [];
      return;
    }

    this.indicatorLoading = true;
    this.indicatorRows = [];
    this.cdr.markForCheck();

    // MISP clusters matching query
    const mispResults = this.mispService.search(q);
    const rows: IndicatorRow[] = mispResults.map(c => ({
      source: 'MISP' as const,
      type: 'Galaxy Cluster',
      value: c.value,
      confidence: 100,
      lastUpdated: '',
    }));

    // OpenCTI indicators
    const attackId = q.match(/^T\d{4}/i) ? q.toUpperCase() : '';
    if (attackId && this.openCtiConnected) {
      this.openCtiService.getIndicatorsForTechnique(attackId).subscribe(indicators => {
        for (const ind of indicators) {
          rows.push({
            source: 'OpenCTI',
            type: ind.patternType,
            value: ind.pattern.length > 80 ? ind.pattern.slice(0, 77) + '...' : ind.pattern,
            confidence: ind.confidence,
            lastUpdated: ind.validFrom ? this.formatDate(ind.validFrom) : '',
          });
        }
        this.indicatorRows = rows;
        this.indicatorLoading = false;
        this.cdr.markForCheck();
      });
    } else {
      this.indicatorRows = rows;
      this.indicatorLoading = false;
      this.cdr.markForCheck();
    }
  }

  copyValue(value: string): void {
    navigator.clipboard.writeText(value);
  }

  exportIndicatorCsv(): void {
    if (this.indicatorRows.length === 0) return;
    const header = 'Source,Type,Value,Confidence,Last Updated';
    const lines = this.indicatorRows.map(r =>
      `${r.source},"${r.type}","${r.value.replace(/"/g, '""')}",${r.confidence},"${r.lastUpdated}"`
    );
    const csv = [header, ...lines].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'threat-intel-indicators.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // ─── Actors ───────────────────────────────────────────────────────────────

  private buildActors(): void {
    if (!this.domain) return;
    this.allActorRows = this.domain.groups.map(g => ({
      name: g.name,
      aliases: g.aliases ?? [],
      techniqueCount: (this.domain!.techniquesByGroup.get(g.id) ?? []).length,
      source: 'ATT&CK' as const,
      groupId: g.id,
    }));
    this.actorRows = this.allActorRows;
  }

  filterActors(): void {
    const q = this.actorSearch.trim().toLowerCase();
    if (!q) {
      this.actorRows = this.allActorRows;
    } else {
      this.actorRows = this.allActorRows.filter(r =>
        r.name.toLowerCase().includes(q) ||
        r.aliases.some(a => a.toLowerCase().includes(q))
      );
    }
    this.cdr.markForCheck();
  }

  filterMatrixByGroup(row: ActorRow): void {
    this.filterService.toggleThreatGroup(row.groupId);
  }

  // ─── MISP Events ─────────────────────────────────────────────────────────

  generateMispEvent(): void {
    const q = this.mispSearch.trim();
    if (!q) return;
    const attackId = q.match(/^T\d{4}/i) ? q.toUpperCase() : '';
    if (!attackId) return;
    this.mispEventTemplate = this.mispService.generateEventTemplate(attackId, attackId);
    this.cdr.markForCheck();
  }

  copyEventTemplate(): void {
    if (this.mispEventTemplate) {
      navigator.clipboard.writeText(this.mispEventTemplate);
    }
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  formatDate(iso: string): string {
    if (!iso) return '';
    try {
      return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch {
      return iso.slice(0, 10);
    }
  }

  scoreBracket(score: number): 'none' | 'low' | 'medium' | 'high' {
    if (score === 0) return 'none';
    if (score <= 2) return 'low';
    if (score <= 5) return 'medium';
    return 'high';
  }
}
