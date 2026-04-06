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
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { TaggingService } from '../../services/tagging.service';
import { DataService } from '../../services/data.service';

export interface TagStat {
  tag: string;
  count: number;
  color: string;
  techniqueIds: string[];
}

interface TaggedTechnique {
  id: string;
  attackId: string;
  name: string;
}

@Component({
  selector: 'app-tags-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './tags-panel.component.html',
  styleUrl: './tags-panel.component.scss',
})
export class TagsPanelComponent implements OnInit, OnDestroy {
  visible = false;
  tagStats: TagStat[] = [];
  searchText = '';
  selectedTag: string | null = null;
  taggedTechniques: TaggedTechnique[] = [];
  renamingTag: string | null = null;
  renameValue = '';

  private subs = new Subscription();
  private techniqueMap = new Map<string, TaggedTechnique>();

  constructor(
    private filterService: FilterService,
    private taggingService: TaggingService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'tags';
        if (this.visible) {
          this.buildStats();
        }
        this.cdr.markForCheck();
      }),
    );

    // Rebuild stats when tags change
    this.subs.add(
      this.taggingService.tags$.subscribe(() => {
        if (this.visible) {
          this.buildStats();
          if (this.selectedTag) {
            this.selectTag(this.selectedTag);
          }
        }
        this.cdr.markForCheck();
      }),
    );

    // Build technique lookup from domain
    this.subs.add(
      this.dataService.domain$.subscribe(domain => {
        this.techniqueMap.clear();
        if (domain) {
          for (const t of domain.techniques) {
            this.techniqueMap.set(t.id, { id: t.id, attackId: t.attackId, name: t.name });
          }
        }
        if (this.visible) {
          this.buildStats();
          if (this.selectedTag) {
            this.selectTag(this.selectedTag);
          }
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  buildStats(): void {
    const usedTags = this.taggingService.getAllUsedTags();
    this.tagStats = usedTags.map(tag => {
      const techniqueIds = this.taggingService.getTechniquesWithTag(tag);
      return {
        tag,
        count: techniqueIds.length,
        color: this.tagColor(tag),
        techniqueIds,
      };
    });
    this.cdr.markForCheck();
  }

  selectTag(tag: string): void {
    this.selectedTag = tag;
    this.renamingTag = null;
    const ids = this.taggingService.getTechniquesWithTag(tag);
    this.taggedTechniques = ids
      .map(id => this.techniqueMap.get(id))
      .filter((t): t is TaggedTechnique => !!t)
      .sort((a, b) => a.attackId.localeCompare(b.attackId));
    this.cdr.markForCheck();
  }

  clearSelection(): void {
    this.selectedTag = null;
    this.taggedTechniques = [];
    this.renamingTag = null;
    this.renameValue = '';
    this.cdr.markForCheck();
  }

  filterByTag(tag: string): void {
    // Use technique search to filter to techniques with this tag
    const ids = this.taggingService.getTechniquesWithTag(tag);
    if (ids.length === 0) return;
    // Build a query from IDs for the search
    const firstId = this.techniqueMap.get(ids[0]);
    if (firstId) {
      this.filterService.setTechniqueQuery(firstId.attackId);
    }
    this.close();
  }

  startRename(tag: string): void {
    this.renamingTag = tag;
    this.renameValue = tag;
    this.cdr.markForCheck();
  }

  confirmRename(): void {
    const oldTag = this.renamingTag;
    const newTag = this.renameValue.trim().toLowerCase();
    if (!oldTag || !newTag || newTag === oldTag) {
      this.renamingTag = null;
      this.cdr.markForCheck();
      return;
    }
    // Rename: add new tag and remove old tag for all techniques that had it
    const ids = this.taggingService.getTechniquesWithTag(oldTag);
    for (const id of ids) {
      this.taggingService.removeTag(id, oldTag);
      this.taggingService.addTag(id, newTag);
    }
    // Update selected tag
    if (this.selectedTag === oldTag) {
      this.selectedTag = newTag;
    }
    this.renamingTag = null;
    this.buildStats();
    if (this.selectedTag) {
      this.selectTag(this.selectedTag);
    }
    this.cdr.markForCheck();
  }

  cancelRename(): void {
    this.renamingTag = null;
    this.renameValue = '';
    this.cdr.markForCheck();
  }

  deleteTag(tag: string): void {
    const ids = this.taggingService.getTechniquesWithTag(tag);
    for (const id of ids) {
      this.taggingService.removeTag(id, tag);
    }
    if (this.selectedTag === tag) {
      this.selectedTag = null;
      this.taggedTechniques = [];
    }
    this.buildStats();
    this.cdr.markForCheck();
  }

  removeTagFromTechnique(techniqueId: string): void {
    if (!this.selectedTag) return;
    this.taggingService.removeTag(techniqueId, this.selectedTag);
    this.taggedTechniques = this.taggedTechniques.filter(t => t.id !== techniqueId);
    this.cdr.markForCheck();
  }

  exportTagsCsv(): void {
    const rows: string[] = ['Tag,Technique ID,Technique Name'];
    for (const stat of this.tagStats) {
      for (const id of stat.techniqueIds) {
        const tech = this.techniqueMap.get(id);
        const attackId = tech?.attackId ?? id;
        const name = tech?.name ?? '';
        rows.push(`"${stat.tag}","${attackId}","${name.replace(/"/g, '""')}"`);
      }
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'technique-tags.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  get filteredStats(): TagStat[] {
    const q = this.searchText.trim().toLowerCase();
    if (!q) return this.tagStats;
    return this.tagStats.filter(s => s.tag.toLowerCase().includes(q));
  }

  get totalUsages(): number {
    return this.tagStats.reduce((sum, s) => sum + s.count, 0);
  }

  getTagColor(tag: string | null): string {
    if (!tag) return '#ffffff';
    return this.tagColor(tag);
  }

  private tagColor(tag: string): string {
    const colors = ['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#06b6d4', '#f97316', '#84cc16'];
    let hash = 0;
    for (const c of tag) hash = ((hash << 5) - hash) + c.charCodeAt(0);
    return colors[Math.abs(hash) % colors.length];
  }
}
