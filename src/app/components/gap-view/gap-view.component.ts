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
import { Subscription } from 'rxjs';
import { Technique } from '../../models/technique';
import { Domain } from '../../models/domain';
import { DataService } from '../../services/data.service';
import { FilterService } from '../../services/filter.service';

interface GapGroup {
  tacticName: string;
  techniques: Technique[];
}

@Component({
  selector: 'app-gap-view',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .gap-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.55);
      z-index: 150;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .gap-panel {
      background: #fff;
      border-radius: 8px;
      width: 720px;
      max-width: 92vw;
      max-height: 82vh;
      display: flex;
      flex-direction: column;
      box-shadow: 0 8px 32px rgba(0,0,0,0.35);
    }

    .gap-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      padding: 14px 20px;
      background: #263238;
      border-radius: 8px 8px 0 0;
      flex-shrink: 0;
      gap: 12px;
    }

    .gap-title { margin: 0; font-size: 16px; font-weight: 700; color: #eceff1; }
    .gap-subtitle { margin: 4px 0 0; font-size: 12px; color: #90a4ae; }

    .gap-header-actions {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-shrink: 0;
      margin-top: 2px;
    }

    .gap-action-btn {
      background: rgba(255,255,255,0.08);
      border: 1px solid rgba(255,255,255,0.18);
      border-radius: 5px;
      color: #b0bec5;
      font-size: 11px;
      font-weight: 600;
      padding: 4px 10px;
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.15s;
      &:hover { background: rgba(255,255,255,0.15); color: #eceff1; }
      &.active { background: rgba(255,167,38,0.15); border-color: rgba(255,167,38,0.4); color: #ffa726; }
      &.export { background: rgba(0,200,83,0.1); border-color: rgba(0,200,83,0.3); color: #00c853;
        &:hover { background: rgba(0,200,83,0.2); }
      }
    }

    .close-btn {
      background: none;
      border: none;
      color: #90a4ae;
      font-size: 18px;
      cursor: pointer;
      padding: 2px 6px;
      border-radius: 4px;
      &:hover { color: #eceff1; background: rgba(255,255,255,0.1); }
    }

    .gap-body { flex: 1; overflow-y: auto; padding: 16px 20px; }

    .gap-empty {
      text-align: center;
      padding: 40px;
      color: #78909c;
      font-size: 14px;
    }

    .gap-group { margin-bottom: 20px; }

    .gap-tactic {
      font-size: 12px;
      font-weight: 700;
      color: #263238;
      background: #eceff1;
      padding: 5px 10px;
      border-radius: 4px;
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .gap-count {
      background: #d32f2f;
      color: #fff;
      border-radius: 10px;
      padding: 1px 7px;
      font-size: 10px;
      font-weight: 700;
    }

    .gap-techniques { display: flex; flex-wrap: wrap; gap: 5px; }

    .gap-technique {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border: 1px solid #e0e0e0;
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
      background: #fafafa;
      transition: background 0.12s, border-color 0.12s;

      &:hover { background: #ffebee; border-color: #ef9a9a; }

      .gap-id { font-weight: 700; color: #d32f2f; }
      .gap-name { color: #37474f; }
    }

    .gap-footer {
      padding: 10px 20px;
      border-top: 1px solid #e0e0e0;
      font-size: 11px;
      color: #90a4ae;
      flex-shrink: 0;
      text-align: center;
    }
  `],
  template: `
    @if (visible) {
      <div class="gap-overlay" (click)="hide()">
        <div class="gap-panel" (click)="$event.stopPropagation()">
          <header class="gap-header">
            <div>
              <h2 class="gap-title">Mitigation Gaps</h2>
              <p class="gap-subtitle">{{ totalCount }} technique{{ totalCount !== 1 ? 's' : '' }} with no mapped mitigations</p>
            </div>
            <div class="gap-header-actions">
              <button class="gap-action-btn" [class.active]="sortByCount" (click)="toggleSort()"
                [title]="sortByCount ? 'Sort by tactic order' : 'Sort by gap count (most gaps first)'">
                {{ sortByCount ? '↕ By count' : '↕ By tactic' }}
              </button>
              <button class="gap-action-btn export" (click)="exportCsv()" title="Export gaps as CSV">⬇ Export</button>
            </div>
            <button class="close-btn" (click)="hide()">✕</button>
          </header>

          <div class="gap-body">
            @if (groups.length === 0) {
              <div class="gap-empty">All techniques have at least one mitigation — great coverage!</div>
            } @else {
              @for (group of groups; track group.tacticName) {
                <div class="gap-group">
                  <div class="gap-tactic">
                    {{ group.tacticName }}
                    <span class="gap-count">{{ group.techniques.length }}</span>
                  </div>
                  <div class="gap-techniques">
                    @for (t of group.techniques; track t.id) {
                      <div class="gap-technique" (click)="selectTechnique(t)" [title]="t.name">
                        <span class="gap-id">{{ t.attackId }}</span>
                        <span class="gap-name">{{ t.name }}</span>
                      </div>
                    }
                  </div>
                </div>
              }
            }
          </div>

          <div class="gap-footer">
            Click any technique to view it in the sidebar · Press Esc to close
          </div>
        </div>
      </div>
    }
  `,
})
export class GapViewComponent implements OnInit, OnDestroy {
  visible = false;
  groups: GapGroup[] = [];
  totalCount = 0;
  sortByCount = false;

  private domain: Domain | null = null;
  private subs = new Subscription();

  constructor(
    private dataService: DataService,
    private filterService: FilterService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.dataService.domain$.subscribe((domain) => {
        this.domain = domain;
        if (!domain) return;
        this.buildGroups(domain);
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  private buildGroups(domain: Domain): void {
    const groupMap = new Map<string, Technique[]>();
    for (const col of domain.tacticColumns) {
      const uncovered = col.techniques.filter((t) => !t.isSubtechnique && t.mitigationCount === 0);
      if (uncovered.length > 0) groupMap.set(col.tactic.name, uncovered);
    }
    let entries = [...groupMap.entries()].map(([tacticName, techniques]) => ({ tacticName, techniques }));
    if (this.sortByCount) entries.sort((a, b) => b.techniques.length - a.techniques.length);
    this.groups = entries;
    this.totalCount = this.groups.reduce((sum, g) => sum + g.techniques.length, 0);
  }

  toggleSort(): void {
    this.sortByCount = !this.sortByCount;
    if (this.domain) this.buildGroups(this.domain);
    this.cdr.markForCheck();
  }

  exportCsv(): void {
    if (!this.domain) return;
    const rows = ['Technique ID,Technique Name,Tactics,Platforms,Threat Groups'];
    for (const group of this.groups) {
      for (const t of group.techniques) {
        const groupCount = this.domain.groupsByTechnique.get(t.id)?.length ?? 0;
        rows.push([
          t.attackId,
          `"${t.name.replace(/"/g, '""')}"`,
          `"${t.tacticShortnames.join('; ')}"`,
          `"${t.platforms.join('; ')}"`,
          groupCount,
        ].join(','));
      }
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'mitigation-gaps.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  show(): void { this.visible = true; this.cdr.markForCheck(); }
  hide(): void { this.visible = false; this.cdr.markForCheck(); }

  selectTechnique(t: Technique): void {
    this.filterService.selectTechnique(t);
    this.hide();
  }
}
