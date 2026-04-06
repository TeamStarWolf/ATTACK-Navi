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
import { CustomTechniqueService, CustomTechnique } from '../../services/custom-technique.service';
import { CustomGroupService } from '../../services/custom-group.service';
import { CustomMitigationService } from '../../services/custom-mitigation.service';
import { AnnotationService } from '../../services/annotation.service';
import { StixCollectionService, ImportSummary } from '../../services/stix-collection.service';

const ALL_TACTICS = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
];

const ALL_PLATFORMS = [
  'Windows', 'Linux', 'macOS', 'Cloud', 'Containers', 'Network', 'IaaS', 'SaaS',
];

@Component({
  selector: 'app-collection-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './collection-panel.component.html',
  styleUrl: './collection-panel.component.scss',
})
export class CollectionPanelComponent implements OnInit, OnDestroy {
  visible = false;
  activeTab: 'collection' | 'import' | 'techniques' = 'collection';

  // Tab 1 — My Collection
  exportName = '';
  exportDescription = '';
  customTechniqueCount = 0;
  customGroupCount = 0;
  customMitigationCount = 0;
  annotationCount = 0;
  copyMessage = '';
  shareUrl = '';

  // Share-import dialog
  showImportDialog = false;
  importDialogSummary: ImportSummary | null = null;
  importDialogBundle: Record<string, any> | null = null;

  // Tab 2 — Import
  importUrl = '';
  importPreview: ImportSummary | null = null;
  importMessage = '';
  importError = '';
  importPendingBundle: Record<string, any> | null = null;
  importFetching = false;

  // Tab 3 — Custom Techniques
  readonly allTactics = ALL_TACTICS;
  readonly allPlatforms = ALL_PLATFORMS;
  techniques: CustomTechnique[] = [];
  newTechName = '';
  newTechAttackId = '';
  newTechDescription = '';
  newTechTactics = new Set<string>();
  newTechPlatforms = new Set<string>();
  editingId: string | null = null;
  editTech: Partial<CustomTechnique> = {};
  editTactics = new Set<string>();
  editPlatforms = new Set<string>();
  deleteConfirmId: string | null = null;

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private customTechniqueService: CustomTechniqueService,
    private customGroupService: CustomGroupService,
    private customMitigationService: CustomMitigationService,
    private annotationService: AnnotationService,
    private stixCollectionService: StixCollectionService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'collection';
        if (this.visible) this.refreshCounts();
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.customTechniqueService.techniques$.subscribe(t => {
        this.techniques = t;
        this.customTechniqueCount = t.length;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.customGroupService.count$.subscribe(c => {
        this.customGroupCount = c;
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

  setTab(tab: 'collection' | 'import' | 'techniques'): void {
    this.activeTab = tab;
    this.importMessage = '';
    this.importError = '';
  }

  // ─── Tab 1: My Collection ─────────────────────────────────────────────────

  private refreshCounts(): void {
    this.customTechniqueCount = this.customTechniqueService.getAll().length;
    this.customGroupCount = this.customGroupService.getAll().length;
    this.customMitigationCount = this.customMitigationService.all.length;
    this.annotationCount = this.annotationService.all.size;
  }

  downloadBundle(): void {
    const name = this.exportName.trim() || 'My Collection';
    const desc = this.exportDescription.trim() || 'Exported from MITRE Mitigation Navigator';
    this.stixCollectionService.downloadBundle(name, desc);
  }

  copyToClipboard(): void {
    const name = this.exportName.trim() || 'My Collection';
    const desc = this.exportDescription.trim() || 'Exported from MITRE Mitigation Navigator';
    const bundle = this.stixCollectionService.exportCollection(name, desc);
    const json = JSON.stringify(bundle, null, 2);
    navigator.clipboard.writeText(json).then(() => {
      this.copyMessage = 'Copied to clipboard!';
      this.cdr.markForCheck();
      setTimeout(() => { this.copyMessage = ''; this.cdr.markForCheck(); }, 2500);
    });
  }

  shareLink(): void {
    const name = this.exportName.trim() || 'My Collection';
    const desc = this.exportDescription.trim() || 'Exported from MITRE Mitigation Navigator';
    const url = this.stixCollectionService.shareAsUrl(name, desc);
    navigator.clipboard.writeText(url).then(() => {
      this.shareUrl = url;
      this.copyMessage = 'Share link copied to clipboard!';
      this.cdr.markForCheck();
      setTimeout(() => { this.copyMessage = ''; this.shareUrl = ''; this.cdr.markForCheck(); }, 4000);
    });
  }

  /** Called from AppComponent on init to check URL for shared collection import */
  checkUrlImport(): void {
    const result = this.stixCollectionService.parseImportFromHash();
    if (!result) return;
    this.importDialogSummary = result.summary;
    this.importDialogBundle = result.bundle;
    this.showImportDialog = true;
    this.cdr.markForCheck();
  }

  confirmUrlImport(): void {
    if (!this.importDialogBundle) return;
    const summary = this.stixCollectionService.importCollection(this.importDialogBundle);
    this.stixCollectionService.clearImportHash();
    this.importMessage = `Imported: ${summary.techniques} techniques, ${summary.groups} groups, ${summary.mitigations} mitigations, ${summary.notes} notes. ${summary.skipped} skipped.`;
    this.showImportDialog = false;
    this.importDialogBundle = null;
    this.importDialogSummary = null;
    this.refreshCounts();
    this.cdr.markForCheck();
  }

  dismissUrlImport(): void {
    this.stixCollectionService.clearImportHash();
    this.showImportDialog = false;
    this.importDialogBundle = null;
    this.importDialogSummary = null;
    this.cdr.markForCheck();
  }

  // ─── Tab 2: Import ────────────────────────────────────────────────────────

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const bundle = JSON.parse(e.target?.result as string);
        this.previewBundle(bundle);
      } catch {
        this.importError = 'Invalid JSON file.';
        this.importPreview = null;
        this.importPendingBundle = null;
        this.cdr.markForCheck();
      }
    };
    reader.readAsText(file);
    input.value = '';
  }

  fetchUrl(): void {
    const url = this.importUrl.trim();
    if (!url) return;
    this.importFetching = true;
    this.importError = '';
    this.importMessage = '';
    this.cdr.markForCheck();
    this.stixCollectionService.importFromUrl(url).then(summary => {
      this.importMessage = `Imported: ${summary.techniques} techniques, ${summary.groups} groups, ${summary.mitigations} mitigations, ${summary.notes} notes. ${summary.skipped} skipped.`;
      this.importPreview = null;
      this.importPendingBundle = null;
      this.importFetching = false;
      this.refreshCounts();
      this.cdr.markForCheck();
    }).catch(err => {
      this.importError = `Failed to fetch: ${err.message || err}`;
      this.importFetching = false;
      this.cdr.markForCheck();
    });
  }

  private previewBundle(bundle: Record<string, any>): void {
    const objects: any[] = bundle['objects'] ?? [];
    const techniques = objects.filter(o => o.type === 'attack-pattern').length;
    const groups = objects.filter(o => o.type === 'intrusion-set').length;
    const mitigations = objects.filter(o => o.type === 'course-of-action').length;
    const notes = objects.filter(o => o.type === 'note').length;
    this.importPreview = { techniques, groups, mitigations, notes, skipped: 0 };
    this.importPendingBundle = bundle;
    this.importError = '';
    this.importMessage = '';
    this.cdr.markForCheck();
  }

  importBundle(): void {
    if (!this.importPendingBundle) return;
    const summary = this.stixCollectionService.importCollection(this.importPendingBundle);
    this.importMessage = `Imported: ${summary.techniques} techniques, ${summary.groups} groups, ${summary.mitigations} mitigations, ${summary.notes} notes. ${summary.skipped} skipped.`;
    this.importPreview = null;
    this.importPendingBundle = null;
    this.refreshCounts();
    this.cdr.markForCheck();
  }

  // ─── Tab 3: Custom Techniques ─────────────────────────────────────────────

  toggleNewTactic(t: string): void {
    if (this.newTechTactics.has(t)) this.newTechTactics.delete(t);
    else this.newTechTactics.add(t);
  }

  toggleNewPlatform(p: string): void {
    if (this.newTechPlatforms.has(p)) this.newTechPlatforms.delete(p);
    else this.newTechPlatforms.add(p);
  }

  createTechnique(): void {
    const name = this.newTechName.trim();
    if (!name) return;
    const attackId = this.newTechAttackId.trim() || `T${9000 + this.techniques.length + 1}`;
    this.customTechniqueService.create({
      attackId,
      name,
      description: this.newTechDescription.trim(),
      tacticShortnames: [...this.newTechTactics],
      platforms: [...this.newTechPlatforms],
      dataSources: [],
      isSubtechnique: false,
      parentId: null,
    });
    this.newTechName = '';
    this.newTechAttackId = '';
    this.newTechDescription = '';
    this.newTechTactics.clear();
    this.newTechPlatforms.clear();
    this.cdr.markForCheck();
  }

  startEdit(tech: CustomTechnique): void {
    this.editingId = tech.id;
    this.editTech = { ...tech };
    this.editTactics = new Set(tech.tacticShortnames);
    this.editPlatforms = new Set(tech.platforms);
  }

  toggleEditTactic(t: string): void {
    if (this.editTactics.has(t)) this.editTactics.delete(t);
    else this.editTactics.add(t);
  }

  toggleEditPlatform(p: string): void {
    if (this.editPlatforms.has(p)) this.editPlatforms.delete(p);
    else this.editPlatforms.add(p);
  }

  saveEdit(): void {
    if (!this.editingId || !this.editTech.name) return;
    this.customTechniqueService.update(this.editingId, {
      name: this.editTech.name,
      attackId: this.editTech.attackId,
      description: this.editTech.description,
      tacticShortnames: [...this.editTactics],
      platforms: [...this.editPlatforms],
    });
    this.editingId = null;
    this.editTech = {};
    this.cdr.markForCheck();
  }

  cancelEdit(): void {
    this.editingId = null;
    this.editTech = {};
  }

  confirmDelete(id: string): void {
    this.deleteConfirmId = id;
  }

  deleteTechnique(id: string): void {
    this.customTechniqueService.delete(id);
    this.deleteConfirmId = null;
    this.cdr.markForCheck();
  }

  cancelDelete(): void {
    this.deleteConfirmId = null;
  }

  tacticDisplay(shortnames: string[]): string {
    return shortnames.join(', ');
  }

  platformDisplay(platforms: string[]): string {
    return platforms.join(', ');
  }
}
