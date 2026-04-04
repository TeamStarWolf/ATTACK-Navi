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
import { SettingsService, AppSettings, DEFAULT_SETTINGS } from '../../services/settings.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { TimelineService } from '../../services/timeline.service';
import { OpenCtiService } from '../../services/opencti.service';
import { MispService } from '../../services/misp.service';

@Component({
  selector: 'app-settings-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './settings-panel.component.html',
  styleUrl: './settings-panel.component.scss',
})
export class SettingsPanelComponent implements OnInit, OnDestroy {
  visible = false;
  settings: AppSettings = { ...DEFAULT_SETTINGS, scoringWeights: { ...DEFAULT_SETTINGS.scoringWeights } };
  activeTab: 'scoring' | 'display' | 'organization' | 'data' | 'integrations' = 'scoring';

  readonly themes = [
    { id: 'default',     label: 'Default',       colors: ['#d32f2f', '#e65100', '#f9a825', '#558b2f', '#1b5e20'] },
    { id: 'redgreen',    label: 'Vivid',          colors: ['#dc2626', '#f97316', '#eab308', '#16a34a', '#15803d'] },
    { id: 'blueorange',  label: 'Blue/Orange',    colors: ['#1d4ed8', '#0ea5e9', '#f59e0b', '#d97706', '#92400e'] },
    { id: 'monochrome',  label: 'Monochrome',     colors: ['#111827', '#374151', '#6b7280', '#9ca3af', '#e5e7eb'] },
    { id: 'accessible',  label: 'High Contrast',  colors: ['#cc0000', '#ff6600', '#ffcc00', '#006600', '#003300'] },
  ];

  // Data tab info
  attackVersion = '';
  cacheStatus = 'Not cached';
  snapshotCount = 0;
  snapshotSizeKb = 0;
  mitigationCount = 0;
  isRefreshing = false;

  // Integrations tab state
  nvdApiKey = '';
  openCtiUrl = '';
  openCtiToken = '';
  openCtiMode: 'direct' | 'proxy' = 'direct';
  openCtiProxyUrl = '';
  openCtiTesting = false;
  openCtiConnected = false;
  openCtiError = '';

  // MISP integration state
  mispUrl = '';
  mispApiKey = '';
  mispOrgId = '';
  mispMode: 'direct' | 'proxy' = 'direct';
  mispProxyUrl = '';
  mispTesting = false;
  mispConnected = false;
  mispError = '';

  private subs = new Subscription();
  private savedSettings: AppSettings = { ...DEFAULT_SETTINGS, scoringWeights: { ...DEFAULT_SETTINGS.scoringWeights } };

  constructor(
    private filterService: FilterService,
    readonly settingsService: SettingsService,
    private dataService: DataService,
    private implService: ImplementationService,
    private timelineService: TimelineService,
    private openCtiService: OpenCtiService,
    private mispService: MispService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'settings';
        if (this.visible) {
          this.reloadSettings();
          this.refreshDataInfo();
          this.loadIntegrationsState();
        }
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.settingsService.settings$.subscribe(s => {
        this.savedSettings = { ...s, scoringWeights: { ...s.scoringWeights } };
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.timelineService.snapshots$.subscribe(snaps => {
        this.snapshotCount = snaps.length;
        const raw = localStorage.getItem('mitre-nav-timeline-v1') ?? '';
        this.snapshotSizeKb = Math.round(raw.length / 1024);
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.dataService.domain$.subscribe(domain => {
        if (domain) {
          this.attackVersion = domain.attackVersion || 'Unknown';
          this.mitigationCount = domain.mitigations.length;
          this.settingsService.update({ attackVersion: this.attackVersion });
          this.cdr.markForCheck();
        }
      }),
    );

    this.subs.add(
      this.openCtiService.connected$.subscribe(connected => {
        this.openCtiConnected = connected;
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.openCtiService.error$.subscribe(err => {
        this.openCtiError = err ?? '';
        if (err) this.openCtiTesting = false;
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.openCtiService.loading$.subscribe(loading => {
        if (!loading) this.openCtiTesting = false;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.mispService.connected$.subscribe(connected => {
        this.mispConnected = connected;
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.mispService.serverError$.subscribe(err => {
        this.mispError = err ?? '';
        if (err) this.mispTesting = false;
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.mispService.serverLoading$.subscribe(loading => {
        if (!loading) this.mispTesting = false;
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  private reloadSettings(): void {
    const s = this.settingsService.current;
    this.settings = { ...s, scoringWeights: { ...s.scoringWeights } };
  }

  private refreshDataInfo(): void {
    this.checkCacheStatus();
  }

  private checkCacheStatus(): void {
    const cacheKeyByDomain = {
      enterprise: 'enterprise-attack-v2',
      ics: 'ics-attack-v1',
      mobile: 'mobile-attack-v1',
    } as const;
    const cacheKey = cacheKeyByDomain[this.dataService.getCurrentAttackDomain()];
    const req = indexedDB.open('mitre-navigator-cache', 1);
    req.onsuccess = () => {
      const db = req.result;
      try {
        const tx = db.transaction('stix-bundles', 'readonly');
        const store = tx.objectStore('stix-bundles');
        const getReq = store.get(cacheKey);
        getReq.onsuccess = () => {
          const entry = getReq.result as { bundle: any; ts: number } | undefined;
          if (entry?.ts) {
            const d = new Date(entry.ts);
            this.cacheStatus = `Cached at ${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
          } else {
            this.cacheStatus = 'Not cached';
          }
          this.cdr.markForCheck();
        };
        getReq.onerror = () => {
          this.cacheStatus = 'Cache unavailable';
          this.cdr.markForCheck();
        };
      } catch {
        this.cacheStatus = 'Cache unavailable';
        this.cdr.markForCheck();
      }
    };
    req.onerror = () => {
      this.cacheStatus = 'Cache unavailable';
      this.cdr.markForCheck();
    };
  }

  get weightsTotal(): number {
    const w = this.settings.scoringWeights;
    return w.mitigations + w.car + w.atomic + w.d3fend + w.nist;
  }

  get isDirty(): boolean {
    const s = this.settings;
    const saved = this.savedSettings;
    return (
      s.scoringWeights.mitigations !== saved.scoringWeights.mitigations ||
      s.scoringWeights.car !== saved.scoringWeights.car ||
      s.scoringWeights.atomic !== saved.scoringWeights.atomic ||
      s.scoringWeights.d3fend !== saved.scoringWeights.d3fend ||
      s.scoringWeights.nist !== saved.scoringWeights.nist ||
      s.matrixCellSize !== saved.matrixCellSize ||
      s.showTechniqueIds !== saved.showTechniqueIds ||
      s.showMitigationCount !== saved.showMitigationCount ||
      s.showSubtechniqueCount !== saved.showSubtechniqueCount ||
      s.heatmapColorTheme !== saved.heatmapColorTheme ||
      s.orgName !== saved.orgName
    );
  }

  get sampleCoverageScore(): number {
    const w = this.settings.scoringWeights;
    const total = w.mitigations + w.car + w.atomic + w.d3fend + w.nist;
    if (total === 0) return 0;
    // Sample: 3 mitigations, has CAR, has Atomic, no D3FEND, has NIST
    const mitScore = Math.min(w.mitigations, (3 / 5) * w.mitigations);
    const carScore = w.car;
    const atomicScore = w.atomic;
    const d3fendScore = 0;
    const nistScore = w.nist;
    const raw = mitScore + carScore + atomicScore + d3fendScore + nistScore;
    return Math.min(100, Math.round((raw / total) * 100));
  }

  applySettings(): void {
    this.settingsService.update(this.settings);
  }

  resetToDefaults(): void {
    this.settingsService.reset();
    this.reloadSettings();
    this.cdr.markForCheck();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  onWeightChange(): void {
    // Clamp each weight to valid range
    const w = this.settings.scoringWeights;
    w.mitigations = Math.max(0, Math.min(60, w.mitigations));
    w.car         = Math.max(0, Math.min(40, w.car));
    w.atomic      = Math.max(0, Math.min(30, w.atomic));
    w.d3fend      = Math.max(0, Math.min(30, w.d3fend));
    w.nist        = Math.max(0, Math.min(20, w.nist));
    this.applySettings();
    this.cdr.markForCheck();
  }

  autoNormalize(): void {
    const total = this.weightsTotal;
    if (total === 0) return;
    const w = this.settings.scoringWeights;
    const factor = 100 / total;
    // Distribute rounding to mitigations
    const car     = Math.round(w.car * factor);
    const atomic  = Math.round(w.atomic * factor);
    const d3fend  = Math.round(w.d3fend * factor);
    const nist    = Math.round(w.nist * factor);
    const mitigations = 100 - car - atomic - d3fend - nist;
    this.settings = {
      ...this.settings,
      scoringWeights: { mitigations, car, atomic, d3fend, nist },
    };
    this.applySettings();
    this.cdr.markForCheck();
  }

  setColorTheme(themeId: string): void {
    this.settings = { ...this.settings, heatmapColorTheme: themeId as AppSettings['heatmapColorTheme'] };
    this.applySettings();
    this.cdr.markForCheck();
  }

  onDisplayChange(): void {
    this.applySettings();
  }

  onOrgChange(): void {
    this.applySettings();
  }

  async refreshData(): Promise<void> {
    this.isRefreshing = true;
    this.cdr.markForCheck();
    await this.dataService.forceRefresh();
    this.isRefreshing = false;
    this.cacheStatus = 'Refreshing…';
    setTimeout(() => {
      this.checkCacheStatus();
    }, 1500);
    this.cdr.markForCheck();
  }

  clearCache(): void {
    const req = indexedDB.open('mitre-navigator-cache', 1);
    req.onsuccess = () => {
      const db = req.result;
      try {
        const tx = db.transaction('stix-bundles', 'readwrite');
        tx.objectStore('stix-bundles').clear();
        tx.oncomplete = () => {
          this.cacheStatus = 'Not cached';
          this.cdr.markForCheck();
        };
      } catch {
        this.cdr.markForCheck();
      }
    };
  }

  clearAllSnapshots(): void {
    const snapshots = this.timelineService.getAll();
    for (const snap of [...snapshots]) {
      this.timelineService.deleteSnapshot(snap.id);
    }
    this.cdr.markForCheck();
  }

  exportImplCsv(): void {
    const domain = this.dataService.getCurrentDomain();
    if (!domain) return;
    const statusMap = this.implService.getStatusMap();
    const rows: string[] = ['Mitigation ID,Mitigation Name,Status,Covered Techniques'];
    for (const mit of domain.mitigations) {
      const techniques = domain.techniquesByMitigation.get(mit.id) ?? [];
      const status = statusMap.get(mit.id) ?? 'not-tracked';
      rows.push([
        mit.attackId,
        `"${mit.name.replace(/"/g, '""')}"`,
        status,
        techniques.length,
      ].join(','));
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'implementation-status.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  get today(): string {
    return new Date().toLocaleDateString();
  }

  setTab(tab: 'scoring' | 'display' | 'organization' | 'data' | 'integrations'): void {
    this.activeTab = tab;
    this.cdr.markForCheck();
  }

  // ─── Integrations tab ────────────────────────────────────────────────────

  private loadIntegrationsState(): void {
    this.nvdApiKey = this.settingsService.current.nvdApiKey ?? '';
    const ctiConfig = this.openCtiService.getConfig();
    this.openCtiUrl = ctiConfig.url;
    this.openCtiToken = ctiConfig.token;
    this.openCtiMode = ctiConfig.mode;
    this.openCtiProxyUrl = ctiConfig.proxyUrl;
    this.openCtiConnected = ctiConfig.connected;
    this.openCtiError = '';

    const mispConfig = this.mispService.getConfig();
    this.mispUrl = mispConfig.url;
    this.mispApiKey = mispConfig.apiKey;
    this.mispOrgId = mispConfig.orgId;
    this.mispMode = mispConfig.mode;
    this.mispProxyUrl = mispConfig.proxyUrl;
    this.mispConnected = mispConfig.connected;
    this.mispError = '';
    this.cdr.markForCheck();
  }

  saveNvdApiKey(): void {
    this.settingsService.setNvdApiKey(this.nvdApiKey);
  }

  testOpenCti(): void {
    if (this.openCtiTesting) return;
    this.openCtiTesting = true;
    this.openCtiError = '';
    this.openCtiConnected = false;
    this.cdr.markForCheck();
    this.openCtiService.saveConfig({
      url: this.openCtiUrl,
      token: this.openCtiToken,
      mode: this.openCtiMode,
      proxyUrl: this.openCtiProxyUrl,
    });
  }

  saveOpenCti(): void {
    this.openCtiService.saveConfig({
      url: this.openCtiUrl,
      token: this.openCtiToken,
      mode: this.openCtiMode,
      proxyUrl: this.openCtiProxyUrl,
    });
  }

  clearOpenCti(): void {
    this.openCtiService.clearConfig();
    this.openCtiUrl = '';
    this.openCtiToken = '';
    this.openCtiMode = 'direct';
    this.openCtiProxyUrl = '';
    this.openCtiConnected = false;
    this.openCtiError = '';
    this.cdr.markForCheck();
  }

  // ─── MISP integration ───────────────────────────────────────────────────

  saveMispConfig(): void {
    this.mispService.saveConfig({
      url: this.mispUrl,
      apiKey: this.mispApiKey,
      orgId: this.mispOrgId,
      connected: false,
      mode: this.mispMode,
      proxyUrl: this.mispProxyUrl,
    });
  }

  testMispConnection(): void {
    if (this.mispTesting) return;
    this.mispTesting = true;
    this.mispError = '';
    this.mispConnected = false;
    this.cdr.markForCheck();

    this.mispService.saveConfig({
      url: this.mispUrl,
      apiKey: this.mispApiKey,
      orgId: this.mispOrgId,
      connected: false,
      mode: this.mispMode,
      proxyUrl: this.mispProxyUrl,
    });
  }

  disconnectMisp(): void {
    this.mispService.clearConfig();
    this.mispUrl = '';
    this.mispApiKey = '';
    this.mispOrgId = '';
    this.mispMode = 'direct';
    this.mispProxyUrl = '';
    this.mispConnected = false;
    this.mispError = '';
    this.cdr.markForCheck();
  }
}
