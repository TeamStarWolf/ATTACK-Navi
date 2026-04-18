// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  OnInit,
  OnDestroy,
  inject,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import {
  LibraryService, LibraryAsset, LibraryData, AssetType,
  ATTACK_TACTIC_ORDER, tacticLabel,
} from '../../services/library.service';

type LibraryTab = 'explore' | 'coverage' | 'vendors' | 'lookup';

const TYPE_LABELS: Record<AssetType, string> = {
  tool: 'Tools',
  channel: 'Channels',
  'x-account': 'X Accounts',
  book: 'Books',
  'field-note': 'Field Notes',
};

const PAGE_SIZE = 50;

const SUGGESTIONS = [
  'BloodHound', 'Kerberos', 'ransomware', 'phishing', 'EDR', 'Sigma', 'YARA',
  'Active Directory', 'OAuth', 'container', 'kubernetes', 'SBOM',
  'memory', 'DLL injection', 'supply chain',
];

@Component({
  selector: 'app-library-workbench',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './library-workbench.component.html',
  styleUrls: ['./library-workbench.component.scss'],
})
export class LibraryWorkbenchComponent implements OnInit, OnDestroy {
  private libraryService = inject(LibraryService);
  private cdr = inject(ChangeDetectorRef);
  private subs = new Subscription();

  data: LibraryData | null = null;
  loading = true;

  // UI state
  currentTab: LibraryTab = 'explore';
  query = '';
  typeFilter: AssetType | 'all' = 'all';
  categoryFilter = '';
  tacticFilter = '';   // ATT&CK tactic slug or '' for any
  page = 0;
  tacticOrder = ATTACK_TACTIC_ORDER;
  tacticLabel = tacticLabel;

  // Vendors tab
  vendorQuery = '';
  selectedVendor = '';

  // Lookup tab
  lookupQuery = '';

  // Cached derived
  filteredAssets: LibraryAsset[] = [];
  availableCategories: string[] = [];
  filteredVendors: Array<[string, number]> = [];
  vendorAssets: LibraryAsset[] = [];
  lookupGroups: Array<{ type: string; assets: LibraryAsset[] }> = [];
  coverageRows: Array<{ category: string; total: number; byType: Record<string, number> }> = [];
  maxBarTotal = 1;
  totalAssets = 0;
  typeLabels = TYPE_LABELS;
  suggestions = SUGGESTIONS;

  ngOnInit(): void {
    this.subs.add(
      this.libraryService.library$.subscribe(data => {
        this.data = data;
        this.loading = false;
        this.totalAssets = data.assets.length;
        this.recomputeAll();
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  // ----- view-state helpers -----

  setTab(tab: LibraryTab): void {
    this.currentTab = tab;
    this.cdr.markForCheck();
  }

  setTypeFilter(t: AssetType | 'all'): void {
    this.typeFilter = t;
    this.categoryFilter = '';
    this.page = 0;
    this.recomputeExplore();
    this.cdr.markForCheck();
  }

  setTacticFilter(slug: string): void {
    this.tacticFilter = this.tacticFilter === slug ? '' : slug;
    this.page = 0;
    this.recomputeExplore();
    this.cdr.markForCheck();
  }

  onSearchInput(value: string): void {
    this.query = value;
    this.page = 0;
    this.recomputeExplore();
    this.cdr.markForCheck();
  }

  onCategoryChange(value: string): void {
    this.categoryFilter = value;
    this.page = 0;
    this.recomputeExplore();
    this.cdr.markForCheck();
  }

  prevPage(): void {
    if (this.page > 0) {
      this.page--;
      this.cdr.markForCheck();
    }
  }
  nextPage(): void {
    if (this.page < this.totalPages - 1) {
      this.page++;
      this.cdr.markForCheck();
    }
  }

  onVendorSearchInput(value: string): void {
    this.vendorQuery = value;
    this.recomputeVendors();
    this.cdr.markForCheck();
  }

  selectVendor(name: string): void {
    this.selectedVendor = name;
    this.vendorAssets = this.data?.assets.filter(a => a.vendor === name) ?? [];
    this.cdr.markForCheck();
  }

  onLookupInput(value: string): void {
    this.lookupQuery = value;
    this.recomputeLookup();
    this.cdr.markForCheck();
  }

  pickSuggestion(s: string): void {
    this.lookupQuery = s;
    this.recomputeLookup();
    this.cdr.markForCheck();
  }

  // ----- derived state -----

  get visibleAssets(): LibraryAsset[] {
    const start = this.page * PAGE_SIZE;
    return this.filteredAssets.slice(start, start + PAGE_SIZE);
  }

  get totalPages(): number {
    return Math.max(1, Math.ceil(this.filteredAssets.length / PAGE_SIZE));
  }

  get assetTypes(): AssetType[] {
    return Object.keys(this.data?.counts ?? {}) as AssetType[];
  }

  get vendorList(): Array<[string, number]> {
    return this.filteredVendors;
  }

  // ----- recompute -----

  private recomputeAll(): void {
    this.recomputeExplore();
    this.recomputeVendors();
    this.recomputeLookup();
    this.recomputeCoverage();
  }

  private recomputeExplore(): void {
    if (!this.data) {
      this.filteredAssets = [];
      this.availableCategories = [];
      return;
    }
    const q = this.query.trim().toLowerCase();
    const cats = new Set<string>();
    this.filteredAssets = this.data.assets.filter(a => {
      if (this.typeFilter !== 'all' && a.type !== this.typeFilter) return false;
      if (this.typeFilter === 'all' || a.type === this.typeFilter) {
        if (a.category) cats.add(a.category);
      }
      if (this.categoryFilter && a.category !== this.categoryFilter) return false;
      if (this.tacticFilter && !(a.attack_tactics ?? []).includes(this.tacticFilter)) return false;
      if (!q) return true;
      return (
        a.title.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        a.vendor.toLowerCase().includes(q) ||
        a.handle.toLowerCase().includes(q) ||
        a.category.toLowerCase().includes(q) ||
        a.subcategory.toLowerCase().includes(q)
      );
    });
    this.availableCategories = [...cats].sort();
  }

  /** Tactic stats for the Coverage tab. */
  get tacticStats(): Array<{ slug: string; label: string; count: number }> {
    const counts = this.data?.tactic_counts ?? {};
    return ATTACK_TACTIC_ORDER.map(slug => ({
      slug,
      label: tacticLabel(slug),
      count: counts[slug] ?? 0,
    }));
  }

  get maxTacticCount(): number {
    return Math.max(1, ...Object.values(this.data?.tactic_counts ?? { x: 1 }));
  }

  private recomputeVendors(): void {
    if (!this.data) return;
    const q = this.vendorQuery.trim().toLowerCase();
    this.filteredVendors = Object.entries(this.data.vendors)
      .filter(([n]) => !q || n.toLowerCase().includes(q))
      .sort((a, b) => b[1] - a[1])
      .slice(0, 200);
  }

  private recomputeLookup(): void {
    if (!this.data) {
      this.lookupGroups = [];
      return;
    }
    const q = this.lookupQuery.trim().toLowerCase();
    if (!q) {
      this.lookupGroups = [];
      return;
    }
    const matches = this.data.assets.filter(a =>
      a.title.toLowerCase().includes(q) ||
      a.description.toLowerCase().includes(q) ||
      a.category.toLowerCase().includes(q) ||
      a.subcategory.toLowerCase().includes(q),
    );
    const byType: Record<string, LibraryAsset[]> = {};
    for (const a of matches) {
      (byType[a.type] ??= []).push(a);
    }
    this.lookupGroups = Object.entries(byType).map(([type, assets]) => ({ type, assets }));
  }

  private recomputeCoverage(): void {
    if (!this.data) return;
    const allCategories = new Set<string>();
    for (const list of Object.values(this.data.categories)) {
      list?.forEach(c => allCategories.add(c));
    }
    const cats = [...allCategories].filter(Boolean).sort();
    const types = Object.keys(this.data.counts) as AssetType[];

    const rows: Array<{ category: string; total: number; byType: Record<string, number> }> = [];
    for (const cat of cats) {
      const byType: Record<string, number> = {};
      let total = 0;
      for (const t of types) {
        const n = this.data.assets.filter(a => a.type === t && a.category === cat).length;
        if (n > 0) {
          byType[t] = n;
          total += n;
        }
      }
      if (total > 0) rows.push({ category: cat, total, byType });
    }
    rows.sort((a, b) => b.total - a.total);
    this.coverageRows = rows;
    this.maxBarTotal = Math.max(1, ...rows.map(r => r.total));
  }

  // ----- helpers used by template -----

  countOf(t: AssetType): number {
    return this.data?.counts[t] ?? 0;
  }

  labelOf(key: unknown): string {
    return TYPE_LABELS[key as AssetType] ?? String(key ?? '');
  }

  vendorTotal(): number {
    return Object.keys(this.data?.vendors ?? {}).length;
  }

  segFlex(n: number): string {
    return `${n}`;
  }

  segPercent(n: number, total: number): number {
    return total > 0 ? (n / total) * 100 : 0;
  }
}
