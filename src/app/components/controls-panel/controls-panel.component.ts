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
import { combineLatest, Subscription } from 'rxjs';
import { SecurityControl, ControlFramework, ControlStatus, FRAMEWORK_TEMPLATES, FrameworkTemplate } from '../../models/security-control';
import { ControlsService } from '../../services/controls.service';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';
import { Mitigation } from '../../models/mitigation';

interface ControlRow {
  control: SecurityControl;
  techniqueCount: number;
  mitigationCount: number;
  expanded: boolean;
  editing: boolean;
}

interface MitigationRow {
  mitigation: Mitigation;
  controlCount: number;
  controlNames: string[];
}

@Component({
  selector: 'app-controls-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './controls-panel.component.html',
  styleUrl: './controls-panel.component.scss',
})
export class ControlsPanelComponent implements OnInit, OnDestroy {
  visible = false;
  activeTab: 'my-controls' | 'by-mitigation' = 'my-controls';
  searchText = '';
  showAddForm = false;
  importStatus = '';

  domain: Domain | null = null;
  controls: SecurityControl[] = [];
  rows: ControlRow[] = [];
  filteredRows: ControlRow[] = [];
  mitRows: MitigationRow[] = [];
  filteredMitRows: MitigationRow[] = [];

  readonly frameworks = FRAMEWORK_TEMPLATES;
  readonly frameworkOptions: ControlFramework[] = ['NIST 800-53', 'CIS Controls v8', 'ISO 27001', 'Custom'];
  readonly statusOptions: ControlStatus[] = ['implemented', 'planned'];

  // Add / edit form state
  formMode: 'add' | 'edit' = 'add';
  editingId = '';
  formName = '';
  formFramework: ControlFramework = 'Custom';
  formRef = '';
  formDesc = '';
  formStatus: ControlStatus = 'implemented';
  formMitSearch = '';
  formMitSuggestions: Mitigation[] = [];
  formMitigations: Mitigation[] = [];

  private subs = new Subscription();

  get implementedCount(): number { return this.controls.filter((c) => c.status === 'implemented').length; }
  get plannedCount(): number { return this.controls.filter((c) => c.status === 'planned').length; }
  get techniqueCoverage(): number {
    if (!this.domain || !this.controls.length) return 0;
    const { coveredIds } = this.controlsService.computeCoverage(
      this.controls.filter((c) => c.status === 'implemented'),
      this.domain,
    );
    const parents = this.domain.techniques.filter((t) => !t.isSubtechnique);
    return parents.length ? Math.round((coveredIds.size / parents.length) * 100) : 0;
  }

  constructor(
    private controlsService: ControlsService,
    private filterService: FilterService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      combineLatest([this.controlsService.controls$, this.dataService.domain$]).subscribe(
        ([controls, domain]) => {
          this.controls = controls;
          this.domain = domain;
          this.rebuildRows();
          this.cdr.markForCheck();
        },
      ),
    );
    this.subs.add(
      this.filterService.activePanel$.subscribe((p) => {
        this.visible = p === 'controls';
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  private rebuildRows(): void {
    if (!this.domain) { this.rows = []; this.mitRows = []; this.applySearch(); return; }

    this.rows = this.controls.map((ctrl) => {
      const techIds = new Set<string>();
      for (const mitId of ctrl.mitigationIds) {
        const techs = this.domain!.techniquesByMitigation.get(mitId) ?? [];
        for (const t of techs) techIds.add(t.id);
      }
      const existing = this.rows.find((r) => r.control.id === ctrl.id);
      return {
        control: ctrl,
        techniqueCount: techIds.size,
        mitigationCount: ctrl.mitigationIds.length,
        expanded: existing?.expanded ?? false,
        editing: existing?.editing ?? false,
      };
    });

    // Build mitigation rows
    const controlsByMit = new Map<string, SecurityControl[]>();
    for (const ctrl of this.controls) {
      for (const mitId of ctrl.mitigationIds) {
        const list = controlsByMit.get(mitId) ?? [];
        list.push(ctrl);
        controlsByMit.set(mitId, list);
      }
    }

    this.mitRows = this.domain.mitigations.map((m) => {
      const ctrls = controlsByMit.get(m.id) ?? [];
      return { mitigation: m, controlCount: ctrls.length, controlNames: ctrls.map((c) => c.name) };
    });

    this.applySearch();
  }

  applySearch(): void {
    const q = this.searchText.trim().toLowerCase();
    if (!q) {
      this.filteredRows = this.rows;
      this.filteredMitRows = this.mitRows;
      return;
    }
    this.filteredRows = this.rows.filter(
      (r) =>
        r.control.name.toLowerCase().includes(q) ||
        r.control.controlRef.toLowerCase().includes(q) ||
        r.control.framework.toLowerCase().includes(q),
    );
    this.filteredMitRows = this.mitRows.filter(
      (r) =>
        r.mitigation.attackId.toLowerCase().includes(q) ||
        r.mitigation.name.toLowerCase().includes(q),
    );
  }

  toggleExpand(row: ControlRow): void {
    row.expanded = !row.expanded;
    this.cdr.markForCheck();
  }

  highlightControl(row: ControlRow): void {
    // Collect mitigations for this control and filter matrix
    if (!this.domain) return;
    const mits = row.control.mitigationIds
      .map((id) => this.domain!.mitigations.find((m) => m.id === id))
      .filter((m): m is import('../../models/mitigation').Mitigation => m !== undefined);
    for (const m of mits) this.filterService.addMitigationFilter(m);
  }

  filterByMitigation(row: MitigationRow): void {
    this.filterService.filterByMitigation(row.mitigation);
    this.filterService.setActivePanel(null);
  }

  // Form helpers
  openAddForm(): void {
    this.formMode = 'add';
    this.formName = '';
    this.formFramework = 'Custom';
    this.formRef = '';
    this.formDesc = '';
    this.formStatus = 'implemented';
    this.formMitigations = [];
    this.formMitSearch = '';
    this.showAddForm = true;
    this.cdr.markForCheck();
  }

  openEditForm(row: ControlRow): void {
    const ctrl = row.control;
    this.formMode = 'edit';
    this.editingId = ctrl.id;
    this.formName = ctrl.name;
    this.formFramework = ctrl.framework;
    this.formRef = ctrl.controlRef;
    this.formDesc = ctrl.description;
    this.formStatus = ctrl.status;
    this.formMitigations = ctrl.mitigationIds
      .map((id) => this.domain?.mitigations.find((m) => m.id === id))
      .filter((m): m is Mitigation => m !== undefined);
    this.formMitSearch = '';
    this.showAddForm = true;
    row.editing = true;
    this.cdr.markForCheck();
  }

  cancelForm(): void {
    this.showAddForm = false;
    this.rows.forEach((r) => r.editing = false);
    this.cdr.markForCheck();
  }

  saveForm(): void {
    if (!this.formName.trim()) return;
    const ctrl: Omit<SecurityControl, 'id'> = {
      name: this.formName.trim(),
      framework: this.formFramework,
      controlRef: this.formRef.trim(),
      description: this.formDesc.trim(),
      mitigationIds: this.formMitigations.map((m) => m.id),
      status: this.formStatus,
    };
    if (this.formMode === 'add') {
      this.controlsService.addControl(ctrl);
    } else {
      this.controlsService.updateControl(this.editingId, ctrl);
    }
    this.showAddForm = false;
    this.rows.forEach((r) => r.editing = false);
  }

  deleteControl(id: string): void {
    this.controlsService.removeControl(id);
  }

  toggleStatus(ctrl: SecurityControl): void {
    this.controlsService.updateControl(ctrl.id, {
      status: ctrl.status === 'implemented' ? 'planned' : 'implemented',
    });
  }

  onMitSearchInput(): void {
    const q = this.formMitSearch.trim().toLowerCase();
    if (!q || !this.domain) { this.formMitSuggestions = []; return; }
    const already = new Set(this.formMitigations.map((m) => m.id));
    this.formMitSuggestions = this.domain.mitigations
      .filter((m) => !already.has(m.id) && (m.attackId.toLowerCase().includes(q) || m.name.toLowerCase().includes(q)))
      .slice(0, 30);
  }

  addMitigation(m: Mitigation): void {
    if (!this.formMitigations.find((x) => x.id === m.id)) {
      this.formMitigations = [...this.formMitigations, m];
    }
    this.formMitSearch = '';
    this.formMitSuggestions = [];
    this.cdr.markForCheck();
  }

  removeMitigation(m: Mitigation): void {
    this.formMitigations = this.formMitigations.filter((x) => x.id !== m.id);
    this.cdr.markForCheck();
  }

  importTemplate(template: FrameworkTemplate, status: ControlStatus): void {
    if (!this.domain) return;
    const added = this.controlsService.importFromTemplate(template, this.domain, status);
    this.importStatus = added > 0 ? `✓ Added ${added} controls from ${template.name}` : `Already imported`;
    setTimeout(() => { this.importStatus = ''; this.cdr.markForCheck(); }, 3000);
    this.cdr.markForCheck();
  }

  exportControls(): void {
    const blob = new Blob([this.controlsService.exportJson()], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'security-controls.json';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  importControls(): void {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (ev) => {
        this.controlsService.importJson(ev.target?.result as string);
        this.cdr.markForCheck();
      };
      reader.readAsText(file);
    };
    input.click();
  }

  close(): void { this.filterService.setActivePanel(null); }

  getMitigationName(mitId: string): string {
    const m = this.domain?.mitigations.find((x) => x.id === mitId);
    return m ? `${m.attackId} ${m.name}` : mitId;
  }

  coveragePctForControl(ctrl: SecurityControl): number {
    if (!this.domain || !ctrl.mitigationIds.length) return 0;
    const { coveredIds } = this.controlsService.computeCoverage([ctrl], this.domain);
    const parents = this.domain.techniques.filter((t) => !t.isSubtechnique);
    return parents.length ? Math.round((coveredIds.size / parents.length) * 100) : 0;
  }
}
