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
import { WatchlistService, WatchlistEntry } from '../../services/watchlist.service';
import { DataService } from '../../services/data.service';

@Component({
  selector: 'app-watchlist-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './watchlist-panel.component.html',
  styleUrl: './watchlist-panel.component.scss',
})
export class WatchlistPanelComponent implements OnInit, OnDestroy {
  visible = false;
  entries: WatchlistEntry[] = [];
  filterPriority: 'all' | 'high' | 'medium' | 'low' = 'all';
  sortBy: 'added' | 'priority' | 'name' = 'priority';
  searchText = '';
  editingNoteId: string | null = null;
  editingNoteText = '';

  private subs = new Subscription();

  readonly priorityOrder: Record<string, number> = { high: 0, medium: 1, low: 2 };

  constructor(
    private filterService: FilterService,
    private watchlistService: WatchlistService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'watchlist';
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.watchlistService.entries$.subscribe(entries => {
        this.entries = entries;
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  get filteredEntries(): WatchlistEntry[] {
    let result = this.entries;

    if (this.filterPriority !== 'all') {
      result = result.filter(e => e.priority === this.filterPriority);
    }

    const q = this.searchText.trim().toLowerCase();
    if (q) {
      result = result.filter(e =>
        e.techniqueId.toLowerCase().includes(q) ||
        e.name.toLowerCase().includes(q) ||
        e.note.toLowerCase().includes(q),
      );
    }

    return this.sortEntries(result);
  }

  private sortEntries(entries: WatchlistEntry[]): WatchlistEntry[] {
    const sorted = [...entries];
    switch (this.sortBy) {
      case 'name':
        return sorted.sort((a, b) => a.name.localeCompare(b.name));
      case 'added':
        return sorted.sort((a, b) => b.addedAt.localeCompare(a.addedAt));
      case 'priority':
      default:
        return sorted.sort((a, b) =>
          (this.priorityOrder[a.priority] ?? 1) - (this.priorityOrder[b.priority] ?? 1) ||
          a.name.localeCompare(b.name),
        );
    }
  }

  openTechnique(entry: WatchlistEntry): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      const tech = domain.techniques.find(t => t.attackId === entry.techniqueId);
      if (tech) {
        this.filterService.selectTechnique(tech);
        this.close();
      }
    });
  }

  removeEntry(techniqueId: string): void {
    this.watchlistService.remove(techniqueId);
    this.cdr.markForCheck();
  }

  priorityColor(p: WatchlistEntry['priority']): string {
    switch (p) {
      case 'high':   return '#f87171';
      case 'medium': return '#fbbf24';
      case 'low':    return '#4ade80';
    }
  }

  setPriority(techniqueId: string, priority: WatchlistEntry['priority']): void {
    this.watchlistService.updatePriority(techniqueId, priority);
  }

  startEditNote(entry: WatchlistEntry): void {
    this.editingNoteId = entry.techniqueId;
    this.editingNoteText = entry.note;
    this.cdr.markForCheck();
  }

  saveNote(techniqueId: string): void {
    this.watchlistService.updateNote(techniqueId, this.editingNoteText);
    this.editingNoteId = null;
    this.editingNoteText = '';
    this.cdr.markForCheck();
  }

  cancelNote(): void {
    this.editingNoteId = null;
    this.editingNoteText = '';
    this.cdr.markForCheck();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  formatDate(iso: string): string {
    try {
      return new Date(iso).toISOString().slice(0, 10);
    } catch {
      return iso;
    }
  }

  exportCsv(): void {
    const rows = ['ATT&CK ID,Name,Priority,Added,Note'];
    for (const e of this.entries) {
      rows.push([
        e.techniqueId,
        `"${e.name.replace(/"/g, '""')}"`,
        e.priority,
        this.formatDate(e.addedAt),
        `"${e.note.replace(/"/g, '""')}"`,
      ].join(','));
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'watchlist.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }
}
