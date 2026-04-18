// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  inject,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ValidationService, ValidationRun, ValidationStatus } from '../../services/validation.service';
import { EventLoggingService } from '../../services/event-logging.service';
import { AtomicService } from '../../services/atomic.service';
import { SigmaService } from '../../services/sigma.service';
import { SiemQueryService } from '../../services/siem-query.service';
import { LibraryService } from '../../services/library.service';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';

interface TechniqueValidationCard {
  technique: Technique;
  telemetryRequired: string[];
  telemetryConfigCount: number;
  detectionsAvailable: string[];
  atomicTestCount: number;
  latestRun: ValidationRun | null;
  libraryAssetCount: number;
}

@Component({
  selector: 'app-validation-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './validation-panel.component.html',
  styleUrls: ['./validation-panel.component.scss'],
})
export class ValidationPanelComponent implements OnInit, OnDestroy {
  visible = false;

  private filterService = inject(FilterService);
  private dataService = inject(DataService);
  private validationService = inject(ValidationService);
  private eventLogService = inject(EventLoggingService);
  private atomicService = inject(AtomicService);
  private sigmaService = inject(SigmaService);
  private siemQueryService = inject(SiemQueryService);
  private libraryService = inject(LibraryService);
  private cdr = inject(ChangeDetectorRef);

  // UI state
  currentTab: 'overview' | 'techniques' | 'runs' | 'evidence' = 'overview';
  searchText = '';
  selectedTechnique: Technique | null = null;
  domain: Domain | null = null;
  techniqueCards: TechniqueValidationCard[] = [];

  // Filter
  statusFilter: ValidationStatus | 'all' = 'all';

  // Run-recording form
  showRecordModal = false;
  formOperator = '';
  formTelemetryAvailable: Record<string, boolean> = {};
  formAtomicTestId = '';
  formAtomicCommand = '';
  formAttackResult: ValidationRun['attackResult'] = 'executed';
  formDetectionsExpected: string[] = [];
  formDetectionsFired: Record<string, boolean> = {};
  formResponsePlaybook = '';
  formResponseActions = '';
  formEvidenceLinks = '';
  formNotes = '';

  private subs = new Subscription();

  ngOnInit(): void {
    this.subs.add(this.filterService.activePanel$.subscribe(p => {
      this.visible = p === 'validation';
      if (this.visible) {
        this.loadDomain();
      }
      this.cdr.markForCheck();
    }));

    this.subs.add(this.validationService.runs$.subscribe(() => {
      if (this.visible) this.rebuildCards();
      this.cdr.markForCheck();
    }));
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  // ─── Data loading ─────────────────────────────────────────────────────────

  private loadDomain(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(d => {
      this.domain = d;
      this.rebuildCards();
      this.cdr.markForCheck();
    });
  }

  private rebuildCards(): void {
    if (!this.domain) return;
    // Keep card list small — only techniques with at least one validation input
    const cards: TechniqueValidationCard[] = [];
    for (const tech of this.domain.techniques) {
      if (tech.isSubtechnique) continue;
      const telemetry = this.eventLogService.getLoggingConfig(tech.attackId);
      const atomicCount = this.atomicService.getTestCount(tech.attackId);
      const sigmaCount = this.sigmaService.getRuleCount(tech.attackId);
      const siemCurated = this.siemQueryService.hasCuratedQueries(tech.attackId);
      const hasInputs = telemetry.length > 0 || atomicCount > 0 || sigmaCount > 0 || siemCurated;
      if (!hasInputs) continue;

      const detections: string[] = [];
      if (sigmaCount > 0) detections.push(`sigma:${sigmaCount}`);
      if (siemCurated) detections.push('siem:curated');

      cards.push({
        technique: tech,
        telemetryRequired: telemetry.map(t => `${t.source} (${t.eventId})`),
        telemetryConfigCount: telemetry.length,
        detectionsAvailable: detections,
        atomicTestCount: atomicCount,
        latestRun: this.validationService.latestFor(tech.attackId),
        libraryAssetCount: this.libraryService.getAssetsForTactic(tech.tacticShortnames?.[0] ?? '').length,
      });
    }
    this.techniqueCards = cards;
  }

  // ─── UI actions ───────────────────────────────────────────────────────────

  setTab(t: typeof this.currentTab): void {
    this.currentTab = t;
    this.cdr.markForCheck();
  }

  get filteredCards(): TechniqueValidationCard[] {
    const q = this.searchText.trim().toLowerCase();
    return this.techniqueCards.filter(c => {
      if (this.statusFilter !== 'all') {
        const s = c.latestRun?.status ?? 'untested';
        if (s !== this.statusFilter) return false;
      }
      if (!q) return true;
      return c.technique.attackId.toLowerCase().includes(q) ||
             c.technique.name.toLowerCase().includes(q);
    });
  }

  get statusCounts(): Record<ValidationStatus, number> {
    return this.validationService.statusCounts();
  }

  get totalCards(): number {
    return this.techniqueCards.length;
  }

  openRecordModal(card: TechniqueValidationCard): void {
    this.selectedTechnique = card.technique;
    this.formOperator = '';
    this.formTelemetryAvailable = {};
    card.telemetryRequired.forEach(t => (this.formTelemetryAvailable[t] = true));
    this.formAtomicTestId = '';
    this.formAtomicCommand = '';
    this.formAttackResult = 'executed';
    this.formDetectionsExpected = [...card.detectionsAvailable];
    this.formDetectionsFired = {};
    card.detectionsAvailable.forEach(d => (this.formDetectionsFired[d] = false));
    this.formResponsePlaybook = `ir-playbook:${card.technique.attackId}`;
    this.formResponseActions = '';
    this.formEvidenceLinks = '';
    this.formNotes = '';
    this.showRecordModal = true;
    this.cdr.markForCheck();
  }

  cancelRecord(): void {
    this.showRecordModal = false;
    this.selectedTechnique = null;
    this.cdr.markForCheck();
  }

  saveRun(): void {
    if (!this.selectedTechnique) return;
    const telemetryRequired = Object.keys(this.formTelemetryAvailable);
    const telemetryAvailable = telemetryRequired.filter(t => this.formTelemetryAvailable[t]);
    const detectionsExpected = this.formDetectionsExpected;
    const detectionsFired = detectionsExpected.filter(d => this.formDetectionsFired[d]);

    this.validationService.record({
      techniqueId: this.selectedTechnique.attackId,
      techniqueName: this.selectedTechnique.name,
      operator: this.formOperator,
      telemetryRequired,
      telemetryAvailable,
      atomicTestId: this.formAtomicTestId,
      atomicCommand: this.formAtomicCommand,
      attackResult: this.formAttackResult,
      detectionsExpected,
      detectionsFired,
      responsePlaybook: this.formResponsePlaybook,
      responseActions: this.formResponseActions.split('\n').map(s => s.trim()).filter(Boolean),
      evidenceLinks: this.formEvidenceLinks.split('\n').map(s => s.trim()).filter(Boolean),
      notes: this.formNotes,
    });
    this.cancelRecord();
  }

  deleteRun(id: string): void {
    this.validationService.delete(id);
  }

  exportNavigatorLayer(): void {
    if (!this.domain) return;
    const layer = this.validationService.buildNavigatorLayer(this.domain.name ?? 'enterprise-attack');
    this.downloadJson(layer, `validation-layer-${new Date().toISOString().split('T')[0]}.json`);
  }

  exportRuns(): void {
    const json = this.validationService.exportJson();
    this.downloadBlob(json, `validation-runs-${new Date().toISOString().split('T')[0]}.json`, 'application/json');
  }

  importRuns(event: Event): void {
    const file = (event.target as HTMLInputElement).files?.[0];
    if (!file) return;
    file.text().then(text => {
      const result = this.validationService.importJson(text);
      if (!result.ok) {
        alert(`Import failed: ${result.error}`);
      }
    });
  }

  private downloadJson(value: unknown, filename: string): void {
    this.downloadBlob(JSON.stringify(value, null, 2), filename, 'application/json');
  }

  private downloadBlob(content: string, filename: string, mime: string): void {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    a.click();
    URL.revokeObjectURL(url);
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  // Helpers used in template
  statusLabel(s: ValidationStatus): string {
    return { passed: 'PASS', failed: 'FAIL', partial: 'PARTIAL', 'no-telemetry': 'NO TELEMETRY', untested: 'UNTESTED' }[s];
  }

  // Detections list and runs are useful in the runs/evidence tabs
  get allRuns(): ValidationRun[] {
    return this.validationService.all.slice().sort((a, b) => b.runDate.localeCompare(a.runDate));
  }
}
