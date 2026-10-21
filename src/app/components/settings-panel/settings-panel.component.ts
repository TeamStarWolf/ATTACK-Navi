// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Signal,
  computed,
  inject,
} from '@angular/core';

import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { SettingsService, AppSettings, DEFAULT_SETTINGS, POSTURE_LIMITS, PostureSettings } from '../../services/settings.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { CsvPreview } from '../../models/impl-csv';
import { TimelineService } from '../../services/timeline.service';
import { OpenCtiService } from '../../services/opencti.service';
import { MispService } from '../../services/misp.service';
import { TaxiiService, TaxiiServerConfig, TaxiiCollection } from '../../services/taxii.service';
import { ImportSummary } from '../../services/stix-collection.service';
import { csvRow } from '../../utils/csv';
import { HEATMAP_MODES } from '../../models/heatmap-modes';
import { isPostureCellLens, lensNameVisible } from '../../models/lens-registry';
import { PostureService } from '../../services/posture.service';

@Component({
  selector: 'app-settings-panel',
  standalone: true,
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './settings-panel.component.html',
  styleUrl: './settings-panel.component.scss',
})
export class SettingsPanelComponent implements OnInit, OnDestroy {
  settings: AppSettings = { ...DEFAULT_SETTINGS, cellDisplay: { ...DEFAULT_SETTINGS.cellDisplay } };
  // E1.5 retired the 'scoring' tab (Scoring Weights); Display is the first tab.
  activeTab: 'display' | 'organization' | 'data' | 'integrations' = 'display';

  // Swatch labels only; the colours come from the one place the matrix reads
  // them (SettingsService.COLOR_THEMES), so the preview always matches the ramp
  // the matrix applies for each theme and cannot drift from a second copy.
  private readonly themeLabels: ReadonlyArray<{ id: string; label: string }> = [
    { id: 'default',    label: 'Default' },
    { id: 'redgreen',   label: 'Vivid' },
    { id: 'blueorange', label: 'Blue/Orange' },
    { id: 'monochrome', label: 'Monochrome' },
    { id: 'accessible', label: 'High Contrast' },
  ];

  private readonly postureService = inject(PostureService);

  // The lenses the Colorblind-safe toggle leaves alone: the registry-hosted
  // lenses with a posture cell, whose ramps are CVD-safe by design (P2-14).
  // Reference depth is registry-hosted too (P2-15) but turns to viridis under
  // the toggle, so it is not named (isPostureCellLens). Read from the lens
  // registry with the menu labels, so the description names each lens the way
  // the lens picker does. The Proven and Covered lenses are named only once
  // owner data exists (lensNameVisible over PostureService.ownerWords, §10.4
  // item 14): an empty user never sees a rung word here.
  readonly cvdOwnRampLenses: Signal<string> = computed(() => {
    const ownerWords = this.postureService.ownerWords();
    return HEATMAP_MODES.filter(m => isPostureCellLens(m) && lensNameVisible(m, ownerWords)).map(m => m.label).join(', ');
  });

  get themes(): { id: string; label: string; colors: string[] }[] {
    return this.themeLabels.map(t => ({ ...t, colors: this.settingsService.COLOR_THEMES[t.id] ?? [] }));
  }

  // Data tab info
  attackVersion = '';
  cacheStatus = 'Not cached';
  snapshotCount = 0;
  snapshotSizeKb = 0;
  mitigationCount = 0;
  isRefreshing = false;

  // Integrations tab state
  nvdApiKey = '';
  proxyToken = '';
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

  // TAXII integration state
  taxiiServers: TaxiiServerConfig[] = [];
  taxiiNewName = '';
  taxiiNewUrl = '';
  taxiiNewUsername = '';
  taxiiNewPassword = '';
  taxiiTestingId: string | null = null;
  taxiiTestResults = new Map<string, boolean>();
  taxiiFetchingId: string | null = null;
  taxiiApiRoots = new Map<string, string[]>();
  taxiiSelectedApiRoot = new Map<string, string>();
  taxiiCollections = new Map<string, TaxiiCollection[]>();
  taxiiImportingCollection: string | null = null;
  taxiiImportResult: ImportSummary | null = null;
  taxiiError = '';

  // Posture rules (P2-05; design §6, §7): edited in place, saved on change.
  readonly postureLimits = POSTURE_LIMITS;
  readonly postureWindows: ReadonlyArray<{ scope: keyof PostureSettings['decayDays']; label: string }> = [
    { scope: 'range', label: 'Range proof window (days)' },
    { scope: 'production', label: 'Production proof window (days)' },
    { scope: 'own-run', label: 'Own-run proof window (days)' },
  ];

  // Bulk CSV import state
  csvPreview: CsvPreview | null = null;
  csvImportApplied: number | null = null;
  csvImportError = '';
  /** Two-step confirm for the destructive "reset all implementation statuses" action. */
  confirmingResetImpl = false;

  private subs = new Subscription();
  private savedSettings: AppSettings = { ...DEFAULT_SETTINGS, cellDisplay: { ...DEFAULT_SETTINGS.cellDisplay } };

  constructor(
    readonly settingsService: SettingsService,
    private dataService: DataService,
    private implService: ImplementationService,
    private timelineService: TimelineService,
    private openCtiService: OpenCtiService,
    private mispService: MispService,
    private taxiiService: TaxiiService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.reloadSettings();
    this.refreshDataInfo();
    this.loadIntegrationsState();

    this.subs.add(
      this.settingsService.settings$.subscribe(s => {
        this.savedSettings = { ...s, cellDisplay: { ...s.cellDisplay }, posture: this.copyPosture(s.posture) };
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.timelineService.snapshots$.subscribe(snaps => {
        this.snapshotCount = snaps.length;
        this.snapshotSizeKb = this.timelineService.getStorageSizeKb();
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

    this.subs.add(
      this.taxiiService.servers$.subscribe(servers => {
        this.taxiiServers = servers;
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  private reloadSettings(): void {
    const s = this.settingsService.current;
    this.settings = { ...s, cellDisplay: { ...s.cellDisplay }, posture: this.copyPosture(s.posture) };
  }

  private copyPosture(p: PostureSettings): PostureSettings {
    return { ...p, decayDays: { ...p.decayDays } };
  }

  /** The stored posture rules (the block shows what PostureService uses). */
  get posture(): PostureSettings {
    return this.settingsService.current.posture;
  }

  /** An integer in [min, max] from a number input, or null. */
  private intFrom(event: Event, min: number, max: number): number | null {
    const input = event.target as HTMLInputElement;
    const v = Number(input.value);
    if (input.value.trim() === '' || !Number.isInteger(v) || v < min || v > max) return null;
    return v;
  }

  /** Save the D16 threshold; an out-of-range or non-integer entry is refused and the stored value shown again. */
  setPostureThreshold(event: Event): void {
    const { min, max } = POSTURE_LIMITS.threshold;
    const v = this.intFrom(event, min, max);
    if (v === null) {
      (event.target as HTMLInputElement).value = String(this.posture.mitigationBreadthThreshold);
      return;
    }
    this.savePosture({ ...this.copyPosture(this.posture), mitigationBreadthThreshold: v });
  }

  /** Save one D10 proof window (days). */
  setPostureWindow(scope: keyof PostureSettings['decayDays'], event: Event): void {
    const { min, max } = POSTURE_LIMITS.decayDays;
    const v = this.intFrom(event, min, max);
    if (v === null) {
      (event.target as HTMLInputElement).value = String(this.posture.decayDays[scope]);
      return;
    }
    const next = this.copyPosture(this.posture);
    next.decayDays[scope] = v;
    this.savePosture(next);
  }

  private savePosture(posture: PostureSettings): void {
    this.settingsService.update({ posture });
    this.settings = { ...this.settings, posture: this.copyPosture(posture) };
    this.cdr.markForCheck();
  }

  private refreshDataInfo(): void {
    this.checkCacheStatus();
  }

  private checkCacheStatus(): void {
    const cacheKeyByDomain = {
      enterprise: 'enterprise-attack-v2',
      ics: 'ics-attack-v1',
      mobile: 'mobile-attack-v1',
      f3: 'f3-attack-v1',
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

  get isDirty(): boolean {
    const s = this.settings;
    const saved = this.savedSettings;
    return (
      s.matrixCellSize !== saved.matrixCellSize ||
      s.showTechniqueIds !== saved.showTechniqueIds ||
      s.showMitigationCount !== saved.showMitigationCount ||
      s.showSubtechniqueCount !== saved.showSubtechniqueCount ||
      s.cellDisplay.exposureBadge !== saved.cellDisplay.exposureBadge ||
      s.cellDisplay.softwareBadge !== saved.cellDisplay.softwareBadge ||
      s.cellDisplay.campaignBadge !== saved.cellDisplay.campaignBadge ||
      s.cellDisplay.metricBadge !== saved.cellDisplay.metricBadge ||
      s.cellDisplay.noteDot !== saved.cellDisplay.noteDot ||
      s.cellDisplay.annotationDot !== saved.cellDisplay.annotationDot ||
      s.cellDisplay.watchIndicator !== saved.cellDisplay.watchIndicator ||
      s.cellDisplay.myMarks !== saved.cellDisplay.myMarks ||
      s.heatmapColorTheme !== saved.heatmapColorTheme ||
      s.orgName !== saved.orgName
    );
  }

  applySettings(): void {
    this.settingsService.update(this.settings);
  }

  resetToDefaults(): void {
    this.settingsService.reset();
    this.reloadSettings();
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
    const rows: string[] = ['Mitigation ID,Mitigation Name,Status,Mapped Techniques'];
    for (const mit of domain.mitigations) {
      const techniques = domain.techniquesByMitigation.get(mit.id) ?? [];
      const status = statusMap.get(mit.id) ?? 'not-tracked';
      rows.push(csvRow([
        mit.attackId,
        mit.name,
        status,
        techniques.length,
      ]));
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

  setTab(tab: SettingsPanelComponent['activeTab']): void {
    this.activeTab = tab;
    this.cdr.markForCheck();
  }

  // ─── Integrations tab ────────────────────────────────────────────────────

  private loadIntegrationsState(): void {
    this.nvdApiKey = this.settingsService.current.nvdApiKey ?? '';
    this.proxyToken = this.settingsService.current.proxyToken ?? '';
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

  /** Proxy access token: sent as X-Proxy-Key on proxy-mode OpenCTI/MISP calls. */
  saveProxyToken(): void {
    this.settingsService.setProxyToken(this.proxyToken);
    this.proxyToken = this.settingsService.current.proxyToken;
    this.cdr.markForCheck();
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

  // ─── TAXII integration ──────────────────────────────────────────────────

  addTaxiiServer(): void {
    if (!this.taxiiNewName || !this.taxiiNewUrl) return;
    this.taxiiService.addServer({
      name: this.taxiiNewName,
      url: this.taxiiNewUrl,
      username: this.taxiiNewUsername,
      password: this.taxiiNewPassword,
      enabled: true,
    });
    this.taxiiNewName = '';
    this.taxiiNewUrl = '';
    this.taxiiNewUsername = '';
    this.taxiiNewPassword = '';
    this.taxiiError = '';
    this.cdr.markForCheck();
  }

  removeTaxiiServer(id: string): void {
    this.taxiiService.removeServer(id);
    this.taxiiTestResults.delete(id);
    this.taxiiApiRoots.delete(id);
    this.taxiiCollections.delete(id);
    this.taxiiSelectedApiRoot.delete(id);
    this.cdr.markForCheck();
  }

  testTaxiiServer(server: TaxiiServerConfig): void {
    this.taxiiTestingId = server.id;
    this.taxiiTestResults.delete(server.id);
    this.taxiiError = '';
    this.cdr.markForCheck();

    this.taxiiService.testConnection(server).subscribe({
      next: ok => {
        this.taxiiTestResults.set(server.id, ok);
        this.taxiiTestingId = null;
        if (!ok) this.taxiiError = 'Connection failed. Check URL and credentials.';
        this.cdr.markForCheck();
      },
      error: () => {
        this.taxiiTestResults.set(server.id, false);
        this.taxiiTestingId = null;
        this.taxiiError = 'Connection error.';
        this.cdr.markForCheck();
      },
    });
  }

  fetchTaxiiCollections(server: TaxiiServerConfig): void {
    this.taxiiFetchingId = server.id;
    this.taxiiError = '';
    this.taxiiCollections.delete(server.id);
    this.cdr.markForCheck();

    this.taxiiService.discoverApiRoots(server).subscribe({
      next: roots => {
        this.taxiiApiRoots.set(server.id, roots);
        if (roots.length > 0) {
          const selectedRoot = roots[0];
          this.taxiiSelectedApiRoot.set(server.id, selectedRoot);
          this.loadTaxiiCollectionsForRoot(server, selectedRoot);
        } else {
          this.taxiiFetchingId = null;
          this.taxiiError = 'No API roots found on this server.';
          this.cdr.markForCheck();
        }
      },
      error: () => {
        this.taxiiFetchingId = null;
        this.taxiiError = 'Failed to discover API roots.';
        this.cdr.markForCheck();
      },
    });
  }

  onTaxiiApiRootChange(server: TaxiiServerConfig, apiRoot: string): void {
    this.taxiiSelectedApiRoot.set(server.id, apiRoot);
    this.taxiiCollections.delete(server.id);
    this.taxiiFetchingId = server.id;
    this.cdr.markForCheck();
    this.loadTaxiiCollectionsForRoot(server, apiRoot);
  }

  private loadTaxiiCollectionsForRoot(server: TaxiiServerConfig, apiRoot: string): void {
    this.taxiiService.getCollections(server, apiRoot).subscribe({
      next: cols => {
        this.taxiiCollections.set(server.id, cols);
        this.taxiiFetchingId = null;
        this.cdr.markForCheck();
      },
      error: () => {
        this.taxiiFetchingId = null;
        this.taxiiError = 'Failed to load collections.';
        this.cdr.markForCheck();
      },
    });
  }

  importTaxiiCollection(server: TaxiiServerConfig, collection: TaxiiCollection): void {
    const apiRoot = this.taxiiSelectedApiRoot.get(server.id);
    if (!apiRoot) return;
    this.taxiiImportingCollection = collection.id;
    this.taxiiImportResult = null;
    this.taxiiError = '';
    this.cdr.markForCheck();

    this.taxiiService.fetchCollection(server, apiRoot, collection.id).subscribe({
      next: bundle => {
        const result = this.taxiiService.importCollection(bundle);
        this.taxiiImportResult = result;
        this.taxiiImportingCollection = null;
        this.cdr.markForCheck();
      },
      error: () => {
        this.taxiiImportingCollection = null;
        this.taxiiError = 'Failed to fetch collection objects.';
        this.cdr.markForCheck();
      },
    });
  }

  // ─── Bulk CSV Import ────────────────────────────────────────────────────

  onCsvFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    this.csvPreview = null;
    this.csvImportApplied = null;
    this.csvImportError = '';
    this.cdr.markForCheck();

    const domain = this.dataService.getCurrentDomain();
    if (!domain) {
      this.csvImportError = 'Load a domain before importing.';
      this.cdr.markForCheck();
      input.value = '';
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const text = reader.result as string;
        this.csvPreview = this.implService.previewStatusCsv(text, domain);
        this.cdr.markForCheck();
      } catch (e: any) {
        this.csvImportError = e?.message ?? 'Failed to parse CSV file';
        this.cdr.markForCheck();
      }
    };
    reader.onerror = () => {
      this.csvImportError = 'Failed to read file';
      this.cdr.markForCheck();
    };
    reader.readAsText(file);

    // Reset file input so the same file can be re-selected
    input.value = '';
  }

  /** Commit the previewed import: writes only the matched mitigations' statuses. */
  applyCsvPreview(): void {
    if (!this.csvPreview) return;
    this.csvImportApplied = this.implService.applyStatusCsv(this.csvPreview);
    this.csvPreview = null;
    this.cdr.markForCheck();
  }

  /** First click arms the confirm; the second clears every saved implementation status. */
  resetImplementationStatuses(): void {
    if (!this.confirmingResetImpl) {
      this.confirmingResetImpl = true;
      this.cdr.markForCheck();
      return;
    }
    this.implService.resetAll();
    this.confirmingResetImpl = false;
    this.csvImportApplied = null;
    this.cdr.markForCheck();
  }

  cancelResetImpl(): void {
    this.confirmingResetImpl = false;
    this.cdr.markForCheck();
  }
}
