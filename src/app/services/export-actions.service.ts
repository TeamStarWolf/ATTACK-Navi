// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { AttackDomain, DataService } from './data.service';
import { Domain } from '../models/domain';
import { FilterService, HeatmapMode } from './filter.service';
import { ImplementationService } from './implementation.service';
import { DocumentationService } from './documentation.service';
import { MatrixExportService } from './matrix-export.service';
import { HtmlReportService } from './html-report.service';
import { PdfReportService } from './pdf-report.service';
import { XlsxExportService } from './xlsx-export.service';
import { CustomMitigationService } from './custom-mitigation.service';
import { TimelineService } from './timeline.service';
import { BrowserFileService } from './browser-file.service';
import { NavigatorLayerService } from './navigator-layer.service';
import { AnnotationService } from './annotation.service';
import { UserLayerService } from './user-layer.service';

/**
 * All matrix/report export and import actions, extracted from AppComponent so
 * the toolbar, the Reports workspace's Export Hub, and the command palette can
 * invoke the same implementations. Logic is moved verbatim from the pre-router
 * AppComponent.
 */
@Injectable({ providedIn: 'root' })
export class ExportActionsService {
  private readonly dataService = inject(DataService);
  private readonly filterService = inject(FilterService);
  private readonly implService = inject(ImplementationService);
  private readonly docService = inject(DocumentationService);
  private readonly matrixExport = inject(MatrixExportService);
  private readonly htmlReportService = inject(HtmlReportService);
  private readonly pdfReportService = inject(PdfReportService);
  private readonly xlsxExport = inject(XlsxExportService);
  private readonly customMitService = inject(CustomMitigationService);
  private readonly timelineService = inject(TimelineService);
  private readonly browserFileService = inject(BrowserFileService);
  private readonly navigatorLayerService = inject(NavigatorLayerService);
  private readonly annotationService = inject(AnnotationService);
  private readonly userLayerService = inject(UserLayerService);

  private domain: Domain | null = null;
  private currentDomain: AttackDomain = 'enterprise';

  constructor() {
    this.dataService.domain$.subscribe((d) => (this.domain = d));
    this.dataService.currentDomain$.subscribe((d) => (this.currentDomain = d));
  }

  exportCsv(): void {
    if (!this.domain) return;
    const rows: string[] = ['Technique ID,Technique Name,Tactics,Platforms,Mitigation Count,Mitigation IDs,Mitigation Names'];
    for (const tech of this.domain.techniques.filter((t) => !t.isSubtechnique)) {
      const rels = this.domain.mitigationsByTechnique.get(tech.id) ?? [];
      rows.push([
        tech.attackId,
        `"${tech.name.replace(/"/g, '""')}"`,
        `"${tech.tacticShortnames.join('; ')}"`,
        `"${tech.platforms.join('; ')}"`,
        rels.length,
        `"${rels.map((r) => r.mitigation.attackId).join('; ')}"`,
        `"${rels.map((r) => r.mitigation.name.replace(/"/g, '""')).join('; ')}"`,
      ].join(','));
    }
    this.downloadCsv(rows.join('\n'), 'attack-mitigation-coverage.csv');
  }

  exportTacticCsv(): void {
    if (!this.domain) return;
    const rows: string[] = ['Tactic,Technique Count,Covered Count,Coverage %,Uncovered Technique IDs'];
    for (const col of this.domain.tacticColumns) {
      const parents = col.techniques.filter((t) => !t.isSubtechnique);
      const covered = parents.filter((t) => t.mitigationCount > 0);
      const uncoveredIds = parents.filter((t) => t.mitigationCount === 0).map((t) => t.attackId).join('; ');
      const pct = parents.length ? Math.round((covered.length / parents.length) * 100) : 0;
      rows.push([
        `"${col.tactic.name}"`,
        parents.length,
        covered.length,
        `${pct}%`,
        `"${uncoveredIds}"`,
      ].join(','));
    }
    this.downloadCsv(rows.join('\n'), 'attack-tactic-coverage.csv');
  }

  exportImplPlanCsv(): void {
    if (!this.domain) return;
    const statusMap = this.implService.getStatusMap();
    const rows: string[] = [
      'Mitigation ID,Mitigation Name,Status,Owner,Target Date,Security Controls,Evidence URL,Covered Techniques,Unique Coverage,Notes'
    ];
    const techMitCount = new Map<string, number>();
    for (const [techId, rels] of this.domain.mitigationsByTechnique.entries()) {
      techMitCount.set(techId, rels.length);
    }
    for (const mit of this.domain.mitigations) {
      const techniques = this.domain.techniquesByMitigation.get(mit.id) ?? [];
      const unique = techniques.filter((t) => (techMitCount.get(t.id) ?? 0) === 1).length;
      const doc = this.docService.getMitDoc(mit.id);
      const status = statusMap.get(mit.id) ?? 'not-tracked';
      rows.push([
        mit.attackId,
        `"${mit.name.replace(/"/g, '""')}"`,
        status,
        `"${doc.owner.replace(/"/g, '""')}"`,
        doc.dueDate,
        `"${doc.controlRefs.replace(/"/g, '""')}"`,
        `"${doc.evidenceUrl.replace(/"/g, '""')}"`,
        techniques.length,
        unique,
        `"${doc.notes.replace(/"/g, '""')}"`,
      ].join(','));
    }
    this.downloadCsv(rows.join('\n'), 'mitigation-implementation-plan.csv');
  }

  exportFullReport(): void {
    if (!this.domain) return;
    const statusMap = this.implService.getStatusMap();
    const date = new Date().toISOString().slice(0, 10);
    const rows: string[] = [
      'Technique ID,Technique Name,Tactics,Platforms,Mitigation ID,Mitigation Name,Impl Status,Owner,Due Date,Control Refs,Evidence URL,Impl Notes,Analyst Note,Total Mitigation Count,Threat Group Count'
    ];
    for (const tech of this.domain.techniques.filter((t) => !t.isSubtechnique)) {
      const rels = this.domain.mitigationsByTechnique.get(tech.id) ?? [];
      const analystNote = this.docService.getTechNote(tech.id);
      const threatGroupCount = (this.domain.groupsByTechnique.get(tech.id) ?? []).length;
      const totalMitCount = rels.length;
      const techId = tech.attackId;
      const techName = `"${tech.name.replace(/"/g, '""')}"`;
      const tactics = `"${tech.tacticShortnames.join('|')}"`;
      const platforms = `"${tech.platforms.join('|')}"`;
      const analystNoteCell = `"${analystNote.replace(/"/g, '""')}"`;
      if (rels.length === 0) {
        rows.push([
          techId, techName, tactics, platforms,
          '', '', '', '', '', '', '', '',
          analystNoteCell, totalMitCount, threatGroupCount,
        ].join(','));
      } else {
        for (const rel of rels) {
          const doc = this.docService.getMitDoc(rel.mitigation.id);
          const status = statusMap.get(rel.mitigation.id) ?? 'not-tracked';
          rows.push([
            techId, techName, tactics, platforms,
            rel.mitigation.attackId,
            `"${rel.mitigation.name.replace(/"/g, '""')}"`,
            status,
            `"${doc.owner.replace(/"/g, '""')}"`,
            doc.dueDate,
            `"${doc.controlRefs.replace(/"/g, '""')}"`,
            `"${doc.evidenceUrl.replace(/"/g, '""')}"`,
            `"${doc.notes.replace(/"/g, '""')}"`,
            analystNoteCell, totalMitCount, threatGroupCount,
          ].join(','));
        }
      }
    }
    this.downloadCsv(rows.join('\n'), `mitre-full-report-${date}.csv`);
  }

  async exportXlsxWorkbook(): Promise<void> {
    if (!this.domain) return;
    await this.xlsxExport.exportWorkbook(
      this.domain,
      this.implService.getStatusMap(),
      this.customMitService.all,
      this.timelineService.getAll(),
    );
  }

  exportHtmlCoverageReport(): void {
    if (!this.domain) return;
    this.htmlReportService.generateAndOpen(this.domain, this.implService.getStatusMap());
  }

  exportPdf(): void {
    if (!this.domain) return;
    this.pdfReportService.generateReport(this.domain, this.implService.getStatusMap());
  }

  exportMatrixPng(): void {
    if (!this.domain) return;
    const heatmapMode = (this.filterService.getStateSnapshot().heatmapMode as HeatmapMode) ?? 'coverage';
    this.matrixExport.exportPng(this.domain, this.implService.getStatusMap(), heatmapMode);
  }

  exportStateJson(): void {
    const state = {
      implementation: JSON.parse(this.implService.exportJson()),
      documentation: JSON.parse(this.docService.exportJson()),
    };
    this.browserFileService.downloadJson(state, 'mitigation-navigator-state.json');
  }

  async importStateJson(): Promise<void> {
    const json = await this.browserFileService.pickTextFile('.json');
    if (!json) return;
    try {
      const state = JSON.parse(json) as { implementation?: unknown; documentation?: unknown };
      if (state.implementation) this.implService.importJson(JSON.stringify(state.implementation));
      if (state.documentation) this.docService.importJson(JSON.stringify(state.documentation));
    } catch {
      alert('Invalid state file.');
    }
  }

  /**
   * Uploads a standard MITRE ATT&CK Navigator layer, converts it into the
   * internal {@link import('../models/user-layer').AttackNaviLayer} model
   * (preserving score/color/comment/metadata/links + layer gradient/legend/
   * filters/domain), saves it to the user's layers (IndexedDB), makes it the
   * active layer, and colors the matrix by it. Honors the layer's own domain,
   * and still applies the round-trip statuses/notes when the domain matches.
   */
  async importNavigatorLayer(): Promise<void> {
    const json = await this.browserFileService.pickTextFile('.json');
    if (!json) return;

    let converted;
    try {
      converted = this.userLayerService.convert(json);
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Failed to import Navigator layer.');
      return;
    }
    const { layer, warnings } = converted;

    // Honor the layer's declared domain — the old import silently matched
    // against whatever domain happened to be loaded.
    let domainSwitched = false;
    if (layer.domain !== this.currentDomain) {
      const switch$ = confirm(
        `This layer targets ${layer.domain.toUpperCase()} ATT&CK, but ${this.currentDomain.toUpperCase()} is loaded.\n\n` +
        `Switch to ${layer.domain.toUpperCase()} so it applies correctly?`,
      );
      if (switch$) {
        this.dataService.switchDomain(layer.domain);
        domainSwitched = true;
      } else {
        warnings.push(`Kept ${this.currentDomain.toUpperCase()} — techniques from a different domain will not match.`);
      }
    }

    try {
      await this.userLayerService.saveLayer(layer);
      this.userLayerService.applyActive(layer);
    } catch {
      this.userLayerService.applyActive(layer);
      warnings.push('Layer converted and applied, but could not be saved to this browser.');
    }
    this.filterService.setHeatmapMode('library');

    // Statuses/notes match techniqueIDs against the loaded domain, so only run
    // that when we did NOT trigger an async domain reload.
    let statusesApplied = 0;
    let notesApplied = 0;
    if (!domainSwitched && this.domain) {
      try {
        const applied = await this.navigatorLayerService.importLayer(
          json, this.domain, this.implService, this.annotationService,
        );
        statusesApplied = applied.statusesApplied;
        notesApplied = applied.notesApplied;
      } catch { /* rich layer already saved+applied; status mapping is best-effort */ }
    }

    const summary = domainSwitched
      ? `Switched to ${layer.domain.toUpperCase()} ATT&CK and colored the matrix by this layer.`
      : `${statusesApplied} statuses and ${notesApplied} notes applied; matrix colored by this layer.`;
    alert([`Layer "${layer.name}" imported and saved (${layer.techniques.length} techniques).`, summary, ...warnings].join('\n'));
  }

  /** Loads a previously saved user layer and colors the matrix by it. */
  async loadSavedLayer(id: string): Promise<void> {
    const layer = await this.userLayerService.setActive(id);
    if (!layer) {
      alert('Saved layer could not be found.');
      return;
    }
    if (layer.domain !== this.currentDomain
        && confirm(`This layer targets ${layer.domain.toUpperCase()} ATT&CK. Switch domain to view it correctly?`)) {
      this.dataService.switchDomain(layer.domain);
    }
    this.filterService.setHeatmapMode('library');
  }

  /** Permanently removes a saved user layer from this browser. */
  async deleteSavedLayer(id: string): Promise<void> {
    await this.userLayerService.deleteLayer(id);
  }

  /** Stops applying the active user layer (matrix/sidebar revert to defaults). */
  clearActiveLayer(): void {
    this.userLayerService.clearActive();
  }

  exportNavigatorLayer(): void {
    if (!this.domain) return;
    this.navigatorLayerService.downloadLayer(this.domain, this.currentDomain, this.implService.getStatusMap(), this.browserFileService, this.annotationService.all);
  }

  openInNavigator(): void {
    this.exportNavigatorLayer();
    setTimeout(() => window.open('https://mitre-attack.github.io/attack-navigator/', '_blank'), 300);
  }

  private downloadCsv(content: string, filename: string): void {
    this.browserFileService.downloadText(content, filename, 'text/csv');
  }
}
