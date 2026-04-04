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
import { MitreDataComponent } from '../../models/datasource';

export interface DataSourceRow {
  sourceName: string;
  components: MitreDataComponent[];
  techniqueCount: number;
  techIds: string[];
  expanded: boolean;
}

export interface FlatComponent {
  component: MitreDataComponent;
  sourceName: string;
  techniqueCount: number;
}

@Component({
  selector: 'app-datasource-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './datasource-panel.component.html',
  styleUrl: './datasource-panel.component.scss',
})
export class DatasourcePanelComponent implements OnInit, OnDestroy {
  visible = false;
  activeTab: 'sources' | 'components' = 'sources';
  searchText = '';
  rows: DataSourceRow[] = [];
  flatComponents: FlatComponent[] = [];
  sortBy: 'name' | 'techniques' = 'techniques';

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'datasources';
        if (this.visible && this.rows.length === 0) {
          this.buildRows();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  buildRows(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      // Group data components by sourceName and count techniques
      const sourceMap = new Map<string, { components: MitreDataComponent[]; techIds: Set<string> }>();

      for (const dc of domain.dataComponents) {
        if (!sourceMap.has(dc.dataSourceName)) {
          sourceMap.set(dc.dataSourceName, { components: [], techIds: new Set() });
        }
        const entry = sourceMap.get(dc.dataSourceName)!;
        entry.components.push(dc);
        const techs = domain.techniquesByDataComponent.get(dc.id) ?? [];
        for (const t of techs) {
          entry.techIds.add(t.id);
        }
      }

      this.rows = [...sourceMap.entries()].map(([sourceName, { components, techIds }]) => ({
        sourceName,
        components,
        techniqueCount: techIds.size,
        techIds: [...techIds],
        expanded: false,
      }));

      // Build flat component list with per-component technique counts
      const flat: FlatComponent[] = [];
      for (const row of this.rows) {
        for (const c of row.components) {
          const techCount = (domain.techniquesByDataComponent.get(c.id) ?? []).length;
          flat.push({ component: c, sourceName: row.sourceName, techniqueCount: techCount });
        }
      }
      this.flatComponents = flat;

      this.cdr.markForCheck();
    });
  }

  get filteredRows(): DataSourceRow[] {
    let rows = this.rows;
    const q = this.searchText.trim().toLowerCase();
    if (q) {
      rows = rows.filter(r =>
        r.sourceName.toLowerCase().includes(q) ||
        r.components.some(c => c.name.toLowerCase().includes(q)),
      );
    }
    if (this.sortBy === 'name') {
      return [...rows].sort((a, b) => a.sourceName.localeCompare(b.sourceName));
    }
    return [...rows].sort((a, b) => b.techniqueCount - a.techniqueCount);
  }

  get allComponents(): FlatComponent[] {
    const q = this.searchText.trim().toLowerCase();
    let filtered = q
      ? this.flatComponents.filter(r =>
          r.component.name.toLowerCase().includes(q) ||
          r.sourceName.toLowerCase().includes(q),
        )
      : this.flatComponents;

    if (this.sortBy === 'name') {
      return [...filtered].sort((a, b) => a.component.name.localeCompare(b.component.name));
    }
    return [...filtered].sort((a, b) => b.techniqueCount - a.techniqueCount);
  }

  get coverageSummary(): { sourceCount: number; techniqueCount: number; componentCount: number } {
    const allTechIds = new Set<string>();
    let componentCount = 0;
    for (const row of this.rows) {
      for (const id of row.techIds) allTechIds.add(id);
      componentCount += row.components.length;
    }
    return { sourceCount: this.rows.length, techniqueCount: allTechIds.size, componentCount };
  }

  filterBySource(sourceName: string): void {
    this.filterService.setDataSourceFilter(sourceName);
    this.close();
  }

  toggleRow(row: DataSourceRow): void {
    row.expanded = !row.expanded;
    this.cdr.markForCheck();
  }

  setTab(tab: 'sources' | 'components'): void {
    this.activeTab = tab;
    this.searchText = '';
    this.cdr.markForCheck();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }
}
