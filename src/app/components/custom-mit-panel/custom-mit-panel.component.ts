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
import { CustomMitigationService, CustomMitigation } from '../../services/custom-mitigation.service';
import { DataService } from '../../services/data.service';
import { ImplStatus, IMPL_STATUS_LABELS, IMPL_STATUS_COLORS } from '../../services/implementation.service';
import { Technique } from '../../models/technique';

const DEFAULT_CATEGORIES = ['EDR', 'SIEM', 'Network', 'Email', 'IAM', 'Endpoint', 'Identity', 'Cloud', 'Custom'];

@Component({
  selector: 'app-custom-mit-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './custom-mit-panel.component.html',
  styleUrl: './custom-mit-panel.component.scss',
})
export class CustomMitPanelComponent implements OnInit, OnDestroy {
  visible = false;
  mitigations: CustomMitigation[] = [];
  activeTab: 'list' | 'create' | 'edit' = 'list';
  form: Partial<CustomMitigation> | null = null;
  searchText = '';
  filterCategory = 'all';
  techniqueSearch = '';
  techniqueSuggestions: Technique[] = [];
  selectedTechniqueIds: string[] = [];

  readonly statusOptions: ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];
  readonly statusLabels = IMPL_STATUS_LABELS;
  readonly statusColors = IMPL_STATUS_COLORS;
  readonly defaultCategories = DEFAULT_CATEGORIES;

  private subs = new Subscription();
  private allTechniques: Technique[] = [];

  constructor(
    private filterService: FilterService,
    private customMitigationService: CustomMitigationService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(panel => {
        this.visible = panel === 'custom-mit';
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.customMitigationService.mitigations$.subscribe(mits => {
        this.mitigations = mits;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.dataService.domain$.subscribe(domain => {
        this.allTechniques = domain?.techniques ?? [];
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  startCreate(): void {
    this.form = {
      name: '',
      description: '',
      category: 'Custom',
      techniqueIds: [],
      implStatus: null,
    };
    this.selectedTechniqueIds = [];
    this.techniqueSearch = '';
    this.techniqueSuggestions = [];
    this.activeTab = 'create';
    this.cdr.markForCheck();
  }

  startEdit(mit: CustomMitigation): void {
    this.form = { ...mit };
    this.selectedTechniqueIds = [...mit.techniqueIds];
    this.techniqueSearch = '';
    this.techniqueSuggestions = [];
    this.activeTab = 'edit';
    this.cdr.markForCheck();
  }

  saveForm(): void {
    if (!this.form || !this.form.name?.trim()) return;
    if (this.activeTab === 'create') {
      this.customMitigationService.create({
        name: this.form.name.trim(),
        description: this.form.description ?? '',
        category: this.form.category ?? 'Custom',
        techniqueIds: [...this.selectedTechniqueIds],
        implStatus: this.form.implStatus ?? null,
      });
    } else if (this.activeTab === 'edit' && this.form.id) {
      this.customMitigationService.update(this.form.id, {
        name: this.form.name.trim(),
        description: this.form.description ?? '',
        category: this.form.category ?? 'Custom',
        techniqueIds: [...this.selectedTechniqueIds],
        implStatus: this.form.implStatus ?? null,
      });
    }
    this.cancelForm();
  }

  cancelForm(): void {
    this.form = null;
    this.selectedTechniqueIds = [];
    this.techniqueSearch = '';
    this.techniqueSuggestions = [];
    this.activeTab = 'list';
    this.cdr.markForCheck();
  }

  deleteMitigation(id: string): void {
    if (confirm('Delete this custom mitigation? This cannot be undone.')) {
      this.customMitigationService.delete(id);
    }
  }

  searchTechniques(query: string): void {
    this.techniqueSearch = query;
    if (!query.trim()) {
      this.techniqueSuggestions = [];
      this.cdr.markForCheck();
      return;
    }
    const q = query.trim().toLowerCase();
    this.techniqueSuggestions = this.allTechniques
      .filter(t =>
        (t.attackId.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)) &&
        !this.selectedTechniqueIds.includes(t.attackId)
      )
      .slice(0, 10);
    this.cdr.markForCheck();
  }

  addTechnique(tech: Technique): void {
    if (!this.selectedTechniqueIds.includes(tech.attackId)) {
      this.selectedTechniqueIds = [...this.selectedTechniqueIds, tech.attackId];
    }
    this.techniqueSearch = '';
    this.techniqueSuggestions = [];
    this.cdr.markForCheck();
  }

  removeTechnique(attackId: string): void {
    this.selectedTechniqueIds = this.selectedTechniqueIds.filter(id => id !== attackId);
    this.cdr.markForCheck();
  }

  get filteredMitigations(): CustomMitigation[] {
    let result = this.mitigations;
    if (this.filterCategory !== 'all') {
      result = result.filter(m => m.category === this.filterCategory);
    }
    if (this.searchText.trim()) {
      const q = this.searchText.trim().toLowerCase();
      result = result.filter(m =>
        m.name.toLowerCase().includes(q) ||
        m.description.toLowerCase().includes(q) ||
        m.id.toLowerCase().includes(q) ||
        m.category.toLowerCase().includes(q)
      );
    }
    return result;
  }

  get categories(): string[] {
    const fromData = this.mitigations.map(m => m.category);
    const all = [...new Set([...DEFAULT_CATEGORIES, ...fromData])];
    return all;
  }

  get uniqueTechniqueCount(): number {
    const ids = new Set<string>();
    for (const m of this.mitigations) {
      for (const id of m.techniqueIds) ids.add(id);
    }
    return ids.size;
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  categorySlug(category: string): string {
    return category.toLowerCase().replace(/ /g, '-');
  }

  statusLabel(status: ImplStatus | null): string {
    if (!status) return '';
    return this.statusLabels[status] ?? status;
  }
}
