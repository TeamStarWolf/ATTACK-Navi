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
import { Subscription, filter, take } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { CisControlsService, CisControl } from '../../services/cis-controls.service';
import { CloudControlsService, CloudControl } from '../../services/cloud-controls.service';
import { NistMappingService, NistControl } from '../../services/nist-mapping.service';
import { CriProfileService, CriControl } from '../../services/cri-profile.service';
import { ComplianceMapperService, ComplianceFramework, ComplianceControl } from '../../services/compliance-mapper.service';
import { ImplementationService, ImplStatus, IMPL_STATUS_LABELS, IMPL_STATUS_COLORS } from '../../services/implementation.service';
import { CsaCcmService, CsaCcmControl } from '../../services/csa-ccm.service';
import { M365ControlsService, M365Control } from '../../services/m365-controls.service';
import { Domain } from '../../models/domain';

export interface FrameworkScore {
  key: string;            // tab id (cis, nist, soc2, etc.)
  label: string;          // display label
  total: number;          // total controls or techniques in framework
  covered: number;        // count covered / implemented
  pct: number;            // 0–100
  status: 'red' | 'amber' | 'green';
}

export interface ComplianceRow {
  id: string;
  name: string;
  attackId: string;
  tactic: string;
  cisCount: number;
  awsCount: number;
  azureCount: number;
  gcpCount: number;
  nistCount: number;
  criCount: number;
  topCisControls: CisControl[];
  topAwsControls: CloudControl[];
  topAzureControls: CloudControl[];
  topGcpControls: CloudControl[];
  topNistControls: NistControl[];
  topCriControls: CriControl[];
  csaCcmCount: number;
  topCsaCcmControls: CsaCcmControl[];
  m365CtrlCount: number;
  topM365Controls: M365Control[];
}

@Component({
  selector: 'app-compliance-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './compliance-panel.component.html',
  styleUrl: './compliance-panel.component.scss',
})
export class CompliancePanelComponent implements OnInit, OnDestroy {
  visible = false;
  activeTab: 'cis' | 'aws' | 'azure' | 'gcp' | 'nist' | 'cri' | 'csa-ccm' | 'm365-ctrl' | 'soc2' | 'iso27001' | 'pci' = 'nist';
  searchText = '';
  sortBy: 'technique' | 'coverage' = 'coverage';
  complianceRows: ComplianceRow[] = [];
  cachedDomain: Domain | null = null;

  // Tooltip state
  tooltipControl: CisControl | CloudControl | CsaCcmControl | M365Control | null = null;
  tooltipX = 0;
  tooltipY = 0;

  // Framework mapper state
  showFrameworkMapper = false;
  selectedFramework: ComplianceFramework = 'SOC 2';
  frameworkControls: { control: ComplianceControl; techniques: string[]; status: ImplStatus | null }[] = [];
  frameworkSearchText = '';
  private currentDomain: Domain | null = null;
  statusLabels = IMPL_STATUS_LABELS;
  statusColors = IMPL_STATUS_COLORS;
  copySuccess = false;

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private cisService: CisControlsService,
    private cloudService: CloudControlsService,
    private nistService: NistMappingService,
    private criService: CriProfileService,
    private complianceMapper: ComplianceMapperService,
    private implService: ImplementationService,
    private csaCcmService: CsaCcmService,
    private m365ControlsService: M365ControlsService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'compliance';
        if (this.visible && this.complianceRows.length === 0) {
          this.buildRows();
        }
        this.cdr.markForCheck();
      }),
    );

    // Refresh when CIS data finishes loading
    this.subs.add(
      this.cisService.loaded$.subscribe(loaded => {
        if (loaded && this.visible) {
          this.buildRows();
        }
        this.cdr.markForCheck();
      }),
    );

    // Refresh when any cloud data finishes loading
    this.subs.add(
      this.cloudService.loaded$.subscribe(loaded => {
        if (loaded && this.visible) {
          this.buildRows();
        }
        this.cdr.markForCheck();
      }),
    );

    // Refresh when NIST data finishes loading
    this.subs.add(
      this.nistService.loaded$.subscribe(loaded => {
        if (loaded && this.visible) {
          this.buildRows();
        }
        this.cdr.markForCheck();
      }),
    );

    // Refresh when CRI data finishes loading
    this.subs.add(
      this.criService.loaded$.subscribe(loaded => {
        if (loaded && this.visible) {
          this.buildRows();
        }
        this.cdr.markForCheck();
      }),
    );

    // Refresh when CSA CCM data finishes loading
    this.subs.add(
      this.csaCcmService.loaded$.subscribe(loaded => {
        if (loaded && this.visible) {
          this.buildRows();
        }
        this.cdr.markForCheck();
      }),
    );

    // Refresh when M365 Controls data finishes loading
    this.subs.add(
      this.m365ControlsService.loaded$.subscribe(loaded => {
        if (loaded && this.visible) {
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
      this.cachedDomain = domain;
      const rows: ComplianceRow[] = [];
      for (const tech of domain.techniques) {
        if (tech.isSubtechnique) continue;
        const cisControls = this.cisService.getControlsForTechnique(tech.attackId);
        const awsControls = this.cloudService.getControlsForTechnique(tech.attackId, 'aws');
        const azureControls = this.cloudService.getControlsForTechnique(tech.attackId, 'azure');
        const gcpControls = this.cloudService.getControlsForTechnique(tech.attackId, 'gcp');
        const nistControls = this.nistService.getControlsForTechnique(tech.attackId);
        const criControls = this.criService.getControlsForTechnique(tech.attackId);
        const csaCcmControls = this.csaCcmService.getControlsForTechnique(tech.attackId);
        const m365Ctrls = this.m365ControlsService.getControlsForTechnique(tech.attackId);
        rows.push({
          id: tech.id,
          name: tech.name,
          attackId: tech.attackId,
          tactic: tech.tacticShortnames[0] ?? '',
          cisCount: cisControls.length,
          awsCount: awsControls.length,
          azureCount: azureControls.length,
          gcpCount: gcpControls.length,
          nistCount: nistControls.length,
          criCount: criControls.length,
          topCisControls: cisControls.slice(0, 2),
          topAwsControls: awsControls.slice(0, 2),
          topAzureControls: azureControls.slice(0, 2),
          topGcpControls: gcpControls.slice(0, 2),
          topNistControls: nistControls.slice(0, 2),
          topCriControls: criControls.slice(0, 2),
          csaCcmCount: csaCcmControls.length,
          topCsaCcmControls: csaCcmControls.slice(0, 2),
          m365CtrlCount: m365Ctrls.length,
          topM365Controls: m365Ctrls.slice(0, 2),
        });
      }
      this.complianceRows = rows;
      this.computeFrameworkScores();
      this.cdr.markForCheck();
    });
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  setTab(tab: 'cis' | 'aws' | 'azure' | 'gcp' | 'nist' | 'cri' | 'csa-ccm' | 'm365-ctrl' | 'soc2' | 'iso27001' | 'pci'): void {
    this.activeTab = tab as any;
    this.searchText = '';
  }

  /** Per-framework compliance score (covered ÷ total controls). */
  frameworkScores: FrameworkScore[] = [];

  computeFrameworkScores(): void {
    if (!this.cachedDomain) return;
    const fws: FrameworkScore[] = [];

    // Mapping-based frameworks (count controls covered by ≥1 mitigated technique)
    const summarizeMapper = (fw: ComplianceFramework, key: 'soc2' | 'iso27001' | 'pci', label: string) => {
      const all = this.complianceMapper.getAllControls(fw);
      let implemented = 0;
      for (const c of all) {
        const status = this.complianceMapper.getControlStatus(c.controlId, fw, this.cachedDomain!);
        if (status === 'implemented') implemented++;
      }
      const pct = all.length > 0 ? Math.round((implemented / all.length) * 100) : 0;
      fws.push({
        key, label, total: all.length, covered: implemented, pct,
        status: pct >= 80 ? 'green' : pct >= 50 ? 'amber' : 'red',
      });
    };
    summarizeMapper('SOC 2', 'soc2', 'SOC 2 Type II');
    summarizeMapper('ISO 27001', 'iso27001', 'ISO 27001:2022');
    summarizeMapper('PCI DSS', 'pci', 'PCI DSS v4.0');

    // Technique-coverage frameworks (% techniques with at least one control mapped)
    const techCoverage = (key: any, label: string, count: (r: ComplianceRow) => number) => {
      const total = this.complianceRows.length;
      const covered = this.complianceRows.filter(r => count(r) > 0).length;
      const pct = total > 0 ? Math.round((covered / total) * 100) : 0;
      fws.push({
        key, label, total, covered, pct,
        status: pct >= 80 ? 'green' : pct >= 50 ? 'amber' : 'red',
      });
    };
    techCoverage('cis',       'CIS v8',      r => r.cisCount);
    techCoverage('nist',      'NIST 800-53', r => r.nistCount);
    techCoverage('cri',       'CRI Profile', r => r.criCount);
    techCoverage('csa-ccm',   'CSA CCM',     r => r.csaCcmCount);
    techCoverage('m365-ctrl', 'M365',        r => r.m365CtrlCount);
    techCoverage('aws',       'AWS',         r => r.awsCount);
    techCoverage('azure',     'Azure',       r => r.azureCount);
    techCoverage('gcp',       'GCP',         r => r.gcpCount);

    this.frameworkScores = fws;
    this.cdr.markForCheck();
  }

  /** XLSX export — multi-sheet workbook of all framework mappings. */
  async exportComplianceXlsx(): Promise<void> {
    if (!this.cachedDomain) return;
    try {
      const XLSX = await import('xlsx-js-style');
      const wb = XLSX.utils.book_new();

      // Summary sheet
      const sumRows: (string | number)[][] = [
        ['Compliance Framework Score Summary'],
        ['Generated', new Date().toLocaleString()],
        ['Domain', this.cachedDomain.name],
        [],
        ['Framework', 'Total controls / techniques', 'Covered', 'Coverage %', 'Status'],
      ];
      for (const fw of this.frameworkScores) {
        sumRows.push([fw.label, fw.total, fw.covered, `${fw.pct}%`, fw.status.toUpperCase()]);
      }
      const sumWs = XLSX.utils.aoa_to_sheet(sumRows);
      sumWs['!cols'] = [{ wch: 26 }, { wch: 28 }, { wch: 12 }, { wch: 14 }, { wch: 10 }];
      this.styleHeaderRow(XLSX, sumWs, 5, 4);
      this.colorScoreColumn(XLSX, sumWs, 4, this.frameworkScores.length);
      XLSX.utils.book_append_sheet(wb, sumWs, 'Summary');

      // Per-framework control sheets
      for (const fw of [
        { id: 'SOC 2' as ComplianceFramework, sheet: 'SOC 2' },
        { id: 'ISO 27001' as ComplianceFramework, sheet: 'ISO 27001' },
        { id: 'PCI DSS' as ComplianceFramework, sheet: 'PCI DSS' },
      ]) {
        const all = this.complianceMapper.getAllControls(fw.id);
        const rows: (string | number)[][] = [['Control ID', 'Description', 'Mapped techniques', 'Status']];
        for (const c of all) {
          const techs = this.complianceMapper.getTechniquesForControl(c.controlId, fw.id);
          const status = this.complianceMapper.getControlStatus(c.controlId, fw.id, this.cachedDomain) ?? 'not-started';
          rows.push([c.controlId, c.description, techs.join(', '), status]);
        }
        const ws = XLSX.utils.aoa_to_sheet(rows);
        ws['!cols'] = [{ wch: 14 }, { wch: 56 }, { wch: 36 }, { wch: 14 }];
        this.styleHeaderRow(XLSX, ws, 4, 0);
        XLSX.utils.book_append_sheet(wb, ws, fw.sheet);
      }

      const filename = `compliance-report-${new Date().toISOString().split('T')[0]}.xlsx`;
      XLSX.writeFile(wb, filename);
    } catch (err) {
      console.error('Compliance XLSX export failed', err);
      alert('Excel export failed. Try CSV instead.');
    }
  }

  private styleHeaderRow(XLSX: any, ws: any, cols: number, rowIdx: number): void {
    for (let c = 0; c < cols; c++) {
      const addr = XLSX.utils.encode_cell({ r: rowIdx, c });
      if (ws[addr]) {
        ws[addr].s = {
          font: { bold: true, color: { rgb: 'FFFFFF' } },
          fill: { fgColor: { rgb: '374151' } },
        };
      }
    }
  }

  private colorScoreColumn(XLSX: any, ws: any, col: number, rowCount: number): void {
    // Status column: GREEN/AMBER/RED background
    const colors: Record<string, string> = { GREEN: '10B981', AMBER: 'F59E0B', RED: 'EF4444' };
    for (let r = 5; r < 5 + rowCount; r++) {
      const addr = XLSX.utils.encode_cell({ r, c: col });
      if (ws[addr]) {
        const v = String(ws[addr].v ?? '').trim();
        if (colors[v]) {
          ws[addr].s = {
            font: { bold: true, color: { rgb: 'FFFFFF' } },
            fill: { fgColor: { rgb: colors[v] } },
            alignment: { horizontal: 'center' },
          };
        }
      }
    }
  }

  get cisLoaded(): boolean {
    return this.cisService.loaded$ !== undefined;
  }

  get awsLoaded(): boolean {
    return this.cloudService.isProviderLoaded('aws');
  }

  get azureLoaded(): boolean {
    return this.cloudService.isProviderLoaded('azure');
  }

  get gcpLoaded(): boolean {
    return this.cloudService.isProviderLoaded('gcp');
  }

  get cisTotal(): number {
    let t = 0;
    this.cisService.total$.subscribe(v => t = v).unsubscribe();
    return t;
  }

  get awsTotal(): number {
    return this.cloudService.getProviderTotal('aws');
  }

  get azureTotal(): number {
    return this.cloudService.getProviderTotal('azure');
  }

  get gcpTotal(): number {
    return this.cloudService.getProviderTotal('gcp');
  }

  get activeRows(): ComplianceRow[] {
    let rows = this.complianceRows;
    const q = this.searchText.trim().toLowerCase();
    if (q) {
      rows = rows.filter(r =>
        r.name.toLowerCase().includes(q) ||
        r.attackId.toLowerCase().includes(q) ||
        r.tactic.toLowerCase().includes(q),
      );
    }
    return this.sortRows(rows);
  }

  get cisRows(): ComplianceRow[] {
    return this.activeRows.filter(r => r.cisCount > 0 || this.sortBy === 'technique');
  }

  get awsRows(): ComplianceRow[] {
    return this.activeRows.filter(r => r.awsCount > 0 || this.sortBy === 'technique');
  }

  get azureRows(): ComplianceRow[] {
    return this.activeRows.filter(r => r.azureCount > 0 || this.sortBy === 'technique');
  }

  get gcpRows(): ComplianceRow[] {
    return this.activeRows.filter(r => r.gcpCount > 0 || this.sortBy === 'technique');
  }

  get nistRows(): ComplianceRow[] {
    return this.activeRows.filter(r => r.nistCount > 0 || this.sortBy === 'technique');
  }

  get criRows(): ComplianceRow[] {
    return this.activeRows.filter(r => r.criCount > 0 || this.sortBy === 'technique');
  }

  get csaCcmRows(): ComplianceRow[] {
    return this.activeRows.filter(r => r.csaCcmCount > 0 || this.sortBy === 'technique');
  }

  get m365CtrlRows(): ComplianceRow[] {
    return this.activeRows.filter(r => r.m365CtrlCount > 0 || this.sortBy === 'technique');
  }

  get displayRows(): ComplianceRow[] {
    switch (this.activeTab) {
      case 'cis':      return this.cisRows;
      case 'aws':      return this.awsRows;
      case 'azure':    return this.azureRows;
      case 'gcp':      return this.gcpRows;
      case 'nist':     return this.nistRows;
      case 'cri':      return this.criRows;
      case 'csa-ccm':  return this.csaCcmRows;
      case 'm365-ctrl': return this.m365CtrlRows;
      case 'soc2':
      case 'iso27001':
      case 'pci':
      default:         return [];   // mapper-frameworks render via dashboard cards, not row tables
    }
  }

  get activeTabCount(): number {
    switch (this.activeTab) {
      case 'cis':      return this.complianceRows.filter(r => r.cisCount > 0).length;
      case 'aws':      return this.complianceRows.filter(r => r.awsCount > 0).length;
      case 'azure':    return this.complianceRows.filter(r => r.azureCount > 0).length;
      case 'gcp':      return this.complianceRows.filter(r => r.gcpCount > 0).length;
      case 'nist':     return this.complianceRows.filter(r => r.nistCount > 0).length;
      case 'cri':      return this.complianceRows.filter(r => r.criCount > 0).length;
      case 'csa-ccm':  return this.complianceRows.filter(r => r.csaCcmCount > 0).length;
      case 'm365-ctrl': return this.complianceRows.filter(r => r.m365CtrlCount > 0).length;
      case 'soc2':
      case 'iso27001':
      case 'pci':
      default:         return this.frameworkScores.find(f => f.key === this.activeTab)?.covered ?? 0;
    }
  }

  activeCount(row: ComplianceRow): number {
    switch (this.activeTab) {
      case 'cis':      return row.cisCount;
      case 'aws':      return row.awsCount;
      case 'azure':    return row.azureCount;
      case 'gcp':      return row.gcpCount;
      case 'nist':     return row.nistCount;
      case 'cri':      return row.criCount;
      case 'csa-ccm':  return row.csaCcmCount;
      case 'm365-ctrl': return row.m365CtrlCount;
      default:         return 0;
    }
  }

  topControls(row: ComplianceRow): (CisControl | CloudControl | NistControl | CriControl | CsaCcmControl | M365Control)[] {
    switch (this.activeTab) {
      case 'cis':      return row.topCisControls;
      case 'aws':      return row.topAwsControls;
      case 'azure':    return row.topAzureControls;
      case 'gcp':      return row.topGcpControls;
      case 'nist':     return row.topNistControls;
      case 'cri':      return row.topCriControls;
      case 'csa-ccm':  return row.topCsaCcmControls;
      case 'm365-ctrl': return row.topM365Controls;
      default:         return [];
    }
  }

  get nistTotal(): number {
    let t = 0;
    this.nistService.total$.subscribe(v => t = v).unsubscribe();
    return t;
  }

  get criTotal(): number {
    let t = 0;
    this.criService.total$.subscribe(v => t = v).unsubscribe();
    return t;
  }

  get nistLoaded(): boolean {
    let loaded = false;
    this.nistService.loaded$.subscribe(v => loaded = v).unsubscribe();
    return loaded;
  }

  get criLoaded(): boolean {
    let loaded = false;
    this.criService.loaded$.subscribe(v => loaded = v).unsubscribe();
    return loaded;
  }

  get csaCcmTotal(): number {
    let t = 0;
    this.csaCcmService.total$.subscribe(v => t = v).unsubscribe();
    return t;
  }

  get csaCcmLoaded(): boolean {
    let loaded = false;
    this.csaCcmService.loaded$.subscribe(v => loaded = v).unsubscribe();
    return loaded;
  }

  get m365CtrlTotal(): number {
    let t = 0;
    this.m365ControlsService.total$.subscribe(v => t = v).unsubscribe();
    return t;
  }

  get m365CtrlLoaded(): boolean {
    let loaded = false;
    this.m365ControlsService.loaded$.subscribe(v => loaded = v).unsubscribe();
    return loaded;
  }

  attackUrl(attackId: string): string {
    return `https://attack.mitre.org/techniques/${attackId.replace('.', '/')}/`;
  }

  showTooltip(event: MouseEvent, ctrl: CisControl | CloudControl | NistControl | CriControl | CsaCcmControl | M365Control): void {
    this.tooltipControl = ctrl as CisControl | CloudControl;
    this.tooltipX = event.clientX + 12;
    this.tooltipY = event.clientY - 8;
    this.cdr.markForCheck();
  }

  hideTooltip(): void {
    this.tooltipControl = null;
    this.cdr.markForCheck();
  }

  // --- Framework Mapper Methods ---
  get availableFrameworks(): ComplianceFramework[] {
    return this.complianceMapper.getFrameworks();
  }

  toggleFrameworkMapper(): void {
    this.showFrameworkMapper = !this.showFrameworkMapper;
    if (this.showFrameworkMapper) {
      this.buildFrameworkControls();
    }
  }

  setFramework(fw: ComplianceFramework): void {
    this.selectedFramework = fw;
    this.frameworkSearchText = '';
    this.buildFrameworkControls();
  }

  buildFrameworkControls(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      this.currentDomain = domain;
      const controls = this.complianceMapper.getAllControls(this.selectedFramework);
      this.frameworkControls = controls.map(c => ({
        control: c,
        techniques: this.complianceMapper.getTechniquesForControl(c.controlId, this.selectedFramework),
        status: this.complianceMapper.getControlStatus(c.controlId, this.selectedFramework, domain),
      }));
      this.cdr.markForCheck();
    });
  }

  get filteredFrameworkControls() {
    const q = this.frameworkSearchText.trim().toLowerCase();
    if (!q) return this.frameworkControls;
    return this.frameworkControls.filter(c =>
      c.control.controlId.toLowerCase().includes(q) ||
      c.control.description.toLowerCase().includes(q) ||
      c.techniques.some(t => t.toLowerCase().includes(q)),
    );
  }

  getStatusColor(status: ImplStatus | null): string {
    if (!status) return '#3a5a74';
    return this.statusColors[status] ?? '#3a5a74';
  }

  getStatusLabel(status: ImplStatus | null): string {
    if (!status) return 'Unknown';
    return this.statusLabels[status] ?? status;
  }

  exportEvidenceReport(): void {
    if (!this.currentDomain) {
      this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
        this.currentDomain = domain;
        this.doExport();
      });
    } else {
      this.doExport();
    }
  }

  private doExport(): void {
    const csv = this.complianceMapper.exportComplianceReport(this.selectedFramework, this.currentDomain!);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${this.selectedFramework.replace(/\s+/g, '_')}_compliance_report.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  private sortRows(rows: ComplianceRow[]): ComplianceRow[] {
    if (this.sortBy === 'technique') {
      return [...rows].sort((a, b) => a.name.localeCompare(b.name));
    }
    // coverage: sort by active tab count descending
    switch (this.activeTab) {
      case 'cis':   return [...rows].sort((a, b) => b.cisCount - a.cisCount);
      case 'aws':   return [...rows].sort((a, b) => b.awsCount - a.awsCount);
      case 'azure': return [...rows].sort((a, b) => b.azureCount - a.azureCount);
      case 'gcp':   return [...rows].sort((a, b) => b.gcpCount - a.gcpCount);
      case 'nist':     return [...rows].sort((a, b) => b.nistCount - a.nistCount);
      case 'cri':      return [...rows].sort((a, b) => b.criCount - a.criCount);
      case 'csa-ccm':  return [...rows].sort((a, b) => b.csaCcmCount - a.csaCcmCount);
      case 'm365-ctrl': return [...rows].sort((a, b) => b.m365CtrlCount - a.m365CtrlCount);
      default: return rows;
    }
  }
}
