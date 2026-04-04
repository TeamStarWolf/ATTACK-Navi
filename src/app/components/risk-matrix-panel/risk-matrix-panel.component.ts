import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule, DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { Technique } from '../../models/technique';

export interface RiskPoint {
  technique: Technique;
  threatScore: number;    // 0-100 based on group count
  gapScore: number;       // 0-100 (100 = completely uncovered)
  riskScore: number;      // threatScore * gapScore / 100
  groupCount: number;
  quadrant: 'critical' | 'monitor' | 'low-priority' | 'well-protected';
}

@Component({
  selector: 'app-risk-matrix-panel',
  standalone: true,
  imports: [CommonModule, FormsModule, DecimalPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './risk-matrix-panel.component.html',
  styleUrl: './risk-matrix-panel.component.scss',
})
export class RiskMatrixPanelComponent implements OnInit, OnDestroy {
  visible = false;
  points: RiskPoint[] = [];
  maxGroupCount = 0;
  maxMitigationCount = 0;
  activeTab: 'matrix' | 'list' = 'matrix';
  filterQuadrant: string | null = null;
  hoveredPoint: RiskPoint | null = null;
  tooltipPos = { x: 0, y: 0 };
  searchText = '';
  showAll = false;

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'risk-matrix';
        if (this.visible && this.points.length === 0) {
          this.buildPoints();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  buildPoints(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      // Compute maxGroupCount and maxMitigationCount from parent techniques
      let maxGroupCount = 0;
      let maxMitigationCount = 0;

      for (const tech of domain.techniques) {
        if (tech.isSubtechnique) continue;
        const groupCount = (domain.groupsByTechnique.get(tech.id) ?? []).length;
        if (groupCount > maxGroupCount) maxGroupCount = groupCount;
        if (tech.mitigationCount > maxMitigationCount) maxMitigationCount = tech.mitigationCount;
      }

      this.maxGroupCount = maxGroupCount || 1;
      this.maxMitigationCount = maxMitigationCount || 1;

      const points: RiskPoint[] = [];
      for (const tech of domain.techniques) {
        if (tech.isSubtechnique) continue;

        const groupCount = (domain.groupsByTechnique.get(tech.id) ?? []).length;
        const threatScore = Math.min(100, (groupCount / this.maxGroupCount) * 100);
        const gapScore = Math.max(0, 100 - (tech.mitigationCount / this.maxMitigationCount) * 100);
        const riskScore = (threatScore * gapScore) / 100;

        let quadrant: RiskPoint['quadrant'];
        if (threatScore >= 50 && gapScore >= 50) {
          quadrant = 'critical';
        } else if (threatScore >= 50 && gapScore < 50) {
          quadrant = 'monitor';
        } else if (threatScore < 50 && gapScore >= 50) {
          quadrant = 'low-priority';
        } else {
          quadrant = 'well-protected';
        }

        points.push({ technique: tech, threatScore, gapScore, riskScore, groupCount, quadrant });
      }

      this.points = points;
      this.cdr.markForCheck();
    });
  }

  get filteredPoints(): RiskPoint[] {
    let pts = this.points;
    if (this.filterQuadrant) {
      pts = pts.filter(p => p.quadrant === this.filterQuadrant);
    }
    const q = this.searchText.trim().toLowerCase();
    if (q) {
      pts = pts.filter(p =>
        p.technique.name.toLowerCase().includes(q) ||
        p.technique.attackId.toLowerCase().includes(q),
      );
    }
    return pts;
  }

  get sortedListPoints(): RiskPoint[] {
    const pts = [...this.filteredPoints].sort((a, b) => b.riskScore - a.riskScore);
    if (this.showAll) return pts;
    return pts.slice(0, 50);
  }

  get totalListCount(): number {
    return this.filteredPoints.length;
  }

  get criticalCount(): number {
    return this.points.filter(p => p.quadrant === 'critical').length;
  }

  get monitorCount(): number {
    return this.points.filter(p => p.quadrant === 'monitor').length;
  }

  get lowPriorityCount(): number {
    return this.points.filter(p => p.quadrant === 'low-priority').length;
  }

  get wellProtectedCount(): number {
    return this.points.filter(p => p.quadrant === 'well-protected').length;
  }

  onPointHover(point: RiskPoint, event: MouseEvent): void {
    this.hoveredPoint = point;
    this.tooltipPos = { x: event.clientX + 12, y: event.clientY - 8 };
    this.cdr.markForCheck();
  }

  onPointLeave(): void {
    this.hoveredPoint = null;
    this.cdr.markForCheck();
  }

  selectTechnique(point: RiskPoint): void {
    this.filterService.selectTechnique(point.technique);
  }

  setFilterQuadrant(q: string | null): void {
    this.filterQuadrant = q;
    this.showAll = false;
    this.cdr.markForCheck();
  }

  setTab(tab: 'matrix' | 'list'): void {
    this.activeTab = tab;
    this.searchText = '';
    this.showAll = false;
    this.cdr.markForCheck();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  quadrantLabel(q: RiskPoint['quadrant']): string {
    switch (q) {
      case 'critical':      return 'Critical';
      case 'monitor':       return 'Monitor';
      case 'low-priority':  return 'Address Later';
      case 'well-protected': return 'Well Protected';
    }
  }
}
