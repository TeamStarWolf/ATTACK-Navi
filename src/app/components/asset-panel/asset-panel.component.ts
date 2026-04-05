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
import { AssetInventoryService, Asset, AssetExposure } from '../../services/asset-inventory.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { CveService } from '../../services/cve.service';
import { DataService } from '../../services/data.service';

interface TechniqueExposureRow {
  attackId: string;
  name: string;
  assetCount: number;
  topCve: string;
  epss: number | null;
}

@Component({
  selector: 'app-asset-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './asset-panel.component.html',
  styleUrl: './asset-panel.component.scss',
})
export class AssetPanelComponent implements OnInit, OnDestroy {
  visible = false;
  activeTab: 'inventory' | 'exposure' = 'inventory';

  // Inventory state
  assets: Asset[] = [];
  assetCount = 0;
  dragOver = false;

  // Add form
  showAddForm = false;
  newHostname = '';
  newOs = '';
  newSoftware = '';
  newTags = '';
  newCriticality: Asset['criticality'] = 'medium';

  // Edit state
  editingId: string | null = null;
  editHostname = '';
  editOs = '';
  editSoftware = '';
  editTags = '';
  editCriticality: Asset['criticality'] = 'medium';

  // Exposure state
  exposureDetails: AssetExposure[] = [];
  techniqueRows: TechniqueExposureRow[] = [];
  totalExposedCves = 0;
  criticalAssetsExposed = 0;
  kevExposedCount = 0;
  exposureMap = new Map<string, number>();

  // Confirm clear
  confirmingClear = false;

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private assetService: AssetInventoryService,
    private attackCveService: AttackCveService,
    private cveService: CveService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(panel => {
        this.visible = panel === 'assets';
        if (this.visible) {
          this.refreshExposure();
        }
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.assetService.assets$.subscribe(assets => {
        this.assets = assets;
        this.assetCount = assets.length;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.assetService.exposureMap$.subscribe(map => {
        this.exposureMap = map;
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

  switchTab(tab: 'inventory' | 'exposure'): void {
    this.activeTab = tab;
    if (tab === 'exposure') {
      this.refreshExposure();
    }
    this.cdr.markForCheck();
  }

  // ── File upload ─────────────────────────────────────────

  onDragOver(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.dragOver = true;
  }

  onDragLeave(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.dragOver = false;
  }

  onDrop(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.dragOver = false;

    const files = event.dataTransfer?.files;
    if (files && files.length > 0) {
      this.readCsvFile(files[0]);
    }
  }

  onFileSelect(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.readCsvFile(input.files[0]);
      input.value = '';
    }
  }

  private readCsvFile(file: File): void {
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      this.assetService.importCsv(text);
      this.refreshExposure();
      this.cdr.markForCheck();
    };
    reader.readAsText(file);
  }

  // ── CRUD ────────────────────────────────────────────────

  toggleAddForm(): void {
    this.showAddForm = !this.showAddForm;
    this.cdr.markForCheck();
  }

  addAsset(): void {
    if (!this.newHostname.trim()) return;

    this.assetService.addAsset({
      hostname: this.newHostname.trim(),
      os: this.newOs.trim(),
      software: this.newSoftware.split(',').map(s => s.trim()).filter(Boolean),
      tags: this.newTags.split(',').map(s => s.trim()).filter(Boolean),
      criticality: this.newCriticality,
    });

    this.newHostname = '';
    this.newOs = '';
    this.newSoftware = '';
    this.newTags = '';
    this.newCriticality = 'medium';
    this.showAddForm = false;
    this.refreshExposure();
    this.cdr.markForCheck();
  }

  startEdit(asset: Asset): void {
    this.editingId = asset.id;
    this.editHostname = asset.hostname;
    this.editOs = asset.os;
    this.editSoftware = asset.software.join(', ');
    this.editTags = asset.tags.join(', ');
    this.editCriticality = asset.criticality;
    this.cdr.markForCheck();
  }

  saveEdit(): void {
    if (!this.editingId) return;
    // Remove and re-add with updated info
    this.assetService.removeAsset(this.editingId);
    this.assetService.addAsset({
      hostname: this.editHostname.trim(),
      os: this.editOs.trim(),
      software: this.editSoftware.split(',').map(s => s.trim()).filter(Boolean),
      tags: this.editTags.split(',').map(s => s.trim()).filter(Boolean),
      criticality: this.editCriticality,
    });
    this.editingId = null;
    this.refreshExposure();
    this.cdr.markForCheck();
  }

  cancelEdit(): void {
    this.editingId = null;
    this.cdr.markForCheck();
  }

  removeAsset(id: string): void {
    this.assetService.removeAsset(id);
    this.refreshExposure();
    this.cdr.markForCheck();
  }

  clearAll(): void {
    if (!this.confirmingClear) {
      this.confirmingClear = true;
      this.cdr.markForCheck();
      return;
    }
    this.assetService.clearAll();
    this.confirmingClear = false;
    this.exposureDetails = [];
    this.techniqueRows = [];
    this.totalExposedCves = 0;
    this.criticalAssetsExposed = 0;
    this.kevExposedCount = 0;
    this.cdr.markForCheck();
  }

  cancelClear(): void {
    this.confirmingClear = false;
    this.cdr.markForCheck();
  }

  // ── Export ──────────────────────────────────────────────

  exportCsv(): void {
    const csv = this.assetService.exportCsv();
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'asset-inventory.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  // ── Exposure ───────────────────────────────────────────

  enableHeatmap(): void {
    this.filterService.setHeatmapMode('my-exposure');
  }

  private refreshExposure(): void {
    const assets = this.assetService.getAll();
    if (assets.length === 0) {
      this.exposureDetails = [];
      this.techniqueRows = [];
      this.totalExposedCves = 0;
      this.criticalAssetsExposed = 0;
      this.kevExposedCount = 0;
      return;
    }

    this.exposureDetails = this.assetService.getExposureDetails(assets);
    this.totalExposedCves = new Set(this.exposureDetails.map(e => e.cveId)).size;
    this.kevExposedCount = this.exposureDetails.filter(e => e.isKev).length;

    // Count critical assets that have at least 1 exposure
    const exposedAssetIds = new Set(this.exposureDetails.map(e => e.asset.id));
    this.criticalAssetsExposed = assets.filter(
      a => a.criticality === 'critical' && exposedAssetIds.has(a.id),
    ).length;

    // Build per-technique rows
    const techMap = new Map<string, { assetIds: Set<string>; cves: Set<string>; topCve: string }>();
    for (const exp of this.exposureDetails) {
      for (const attackId of exp.attackIds) {
        if (!techMap.has(attackId)) {
          techMap.set(attackId, { assetIds: new Set(), cves: new Set(), topCve: exp.cveId });
        }
        const entry = techMap.get(attackId)!;
        entry.assetIds.add(exp.asset.id);
        entry.cves.add(exp.cveId);
      }
    }

    // Resolve technique names from domain
    this.dataService.domain$.subscribe(domain => {
      if (!domain) return;
      const rows: TechniqueExposureRow[] = [];
      for (const [attackId, entry] of techMap) {
        const tech = domain.techniques.find(t => t.attackId === attackId);
        rows.push({
          attackId,
          name: tech?.name ?? attackId,
          assetCount: entry.assetIds.size,
          topCve: entry.topCve,
          epss: null,
        });
      }
      rows.sort((a, b) => b.assetCount - a.assetCount);
      this.techniqueRows = rows;
      this.cdr.markForCheck();
    });
  }

  // ── Helpers ────────────────────────────────────────────

  criticalityColor(crit: string): string {
    switch (crit) {
      case 'critical': return '#f44336';
      case 'high': return '#ff9800';
      case 'medium': return '#ffc107';
      case 'low': return '#4caf50';
      default: return '#90a4ae';
    }
  }

  trackAsset(_: number, a: Asset): string {
    return a.id;
  }

  trackRow(_: number, r: TechniqueExposureRow): string {
    return r.attackId;
  }
}
