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
import { Domain } from '../../models/domain';

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
  activeTab: 'cis' | 'aws' | 'azure' | 'gcp' | 'nist' | 'cri' = 'nist';
  searchText = '';
  sortBy: 'technique' | 'coverage' = 'coverage';
  complianceRows: ComplianceRow[] = [];

  // Tooltip state
  tooltipControl: CisControl | CloudControl | null = null;
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
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  buildRows(): void {
    this.dataService.domain$.pipe(filter(Boolean), take(1)).subscribe(domain => {
      const rows: ComplianceRow[] = [];
      for (const tech of domain.techniques) {
        if (tech.isSubtechnique) continue;
        const cisControls = this.cisService.getControlsForTechnique(tech.attackId);
        const awsControls = this.cloudService.getControlsForTechnique(tech.attackId, 'aws');
        const azureControls = this.cloudService.getControlsForTechnique(tech.attackId, 'azure');
        const gcpControls = this.cloudService.getControlsForTechnique(tech.attackId, 'gcp');
        const nistControls = this.nistService.getControlsForTechnique(tech.attackId);
        const criControls = this.criService.getControlsForTechnique(tech.attackId);
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
        });
      }
      this.complianceRows = rows;
      this.cdr.markForCheck();
    });
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  setTab(tab: 'cis' | 'aws' | 'azure' | 'gcp' | 'nist' | 'cri'): void {
    this.activeTab = tab;
    this.searchText = '';
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

  get displayRows(): ComplianceRow[] {
    switch (this.activeTab) {
      case 'cis':   return this.cisRows;
      case 'aws':   return this.awsRows;
      case 'azure': return this.azureRows;
      case 'gcp':   return this.gcpRows;
      case 'nist':  return this.nistRows;
      case 'cri':   return this.criRows;
    }
  }

  get activeTabCount(): number {
    switch (this.activeTab) {
      case 'cis':   return this.complianceRows.filter(r => r.cisCount > 0).length;
      case 'aws':   return this.complianceRows.filter(r => r.awsCount > 0).length;
      case 'azure': return this.complianceRows.filter(r => r.azureCount > 0).length;
      case 'gcp':   return this.complianceRows.filter(r => r.gcpCount > 0).length;
      case 'nist':  return this.complianceRows.filter(r => r.nistCount > 0).length;
      case 'cri':   return this.complianceRows.filter(r => r.criCount > 0).length;
    }
  }

  activeCount(row: ComplianceRow): number {
    switch (this.activeTab) {
      case 'cis':   return row.cisCount;
      case 'aws':   return row.awsCount;
      case 'azure': return row.azureCount;
      case 'gcp':   return row.gcpCount;
      case 'nist':  return row.nistCount;
      case 'cri':   return row.criCount;
    }
  }

  topControls(row: ComplianceRow): (CisControl | CloudControl | NistControl | CriControl)[] {
    switch (this.activeTab) {
      case 'cis':   return row.topCisControls;
      case 'aws':   return row.topAwsControls;
      case 'azure': return row.topAzureControls;
      case 'gcp':   return row.topGcpControls;
      case 'nist':  return row.topNistControls;
      case 'cri':   return row.topCriControls;
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

  attackUrl(attackId: string): string {
    return `https://attack.mitre.org/techniques/${attackId.replace('.', '/')}/`;
  }

  showTooltip(event: MouseEvent, ctrl: CisControl | CloudControl | NistControl | CriControl): void {
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
      case 'nist':  return [...rows].sort((a, b) => b.nistCount - a.nistCount);
      case 'cri':   return [...rows].sort((a, b) => b.criCount - a.criCount);
    }
  }
}
