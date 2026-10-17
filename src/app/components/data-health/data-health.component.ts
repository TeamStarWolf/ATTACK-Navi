// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';

import { Observable, Subscription, combineLatest, distinctUntilChanged, map, merge } from 'rxjs';
import { AtomicService } from '../../services/atomic.service';
import { SigmaService } from '../../services/sigma.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { CapecService } from '../../services/capec.service';
import { MispService } from '../../services/misp.service';
import { NistMappingService } from '../../services/nist-mapping.service';
import { CriProfileService } from '../../services/cri-profile.service';
import { CloudControlsService } from '../../services/cloud-controls.service';
import { VerisService } from '../../services/veris.service';
import { D3fendService } from '../../services/d3fend.service';
import { CARService } from '../../services/car.service';
import { ElasticService } from '../../services/elastic.service';
import { SplunkContentService } from '../../services/splunk-content.service';
import { ExploitdbService } from '../../services/exploitdb.service';
import { NucleiService } from '../../services/nuclei.service';
import { DataService } from '../../services/data.service';
import { EpssService } from '../../services/epss.service';
import { CveService } from '../../services/cve.service';
import { NvdBulkService } from '../../services/nvd-bulk.service';
import { Cve2CapecService } from '../../services/cve2capec.service';
import { PocExploitService } from '../../services/poc-exploit.service';
import { EvtxSamplesService } from '../../services/evtx-samples.service';
import { SentinelRulesService } from '../../services/sentinel-rules.service';
import { AnthropicSkillsService } from '../../services/anthropic-skills.service';
import { ThreatHunterPlaybookService } from '../../services/threathunter-playbook.service';
import { SourceRegistryService } from '../../services/source-registry.service';

interface HealthEntry { name: string; status: 'loading' | 'loaded' | 'failed' | 'empty'; detail?: string; }

/** What the source registry says about a ribbon entry: failed or empty with a reason, or nothing. */
interface RegistryVerdict { status: 'failed' | 'empty'; detail: string; }

const LAST_REFRESHED_KEY = 'data-health-last-refreshed';

@Component({
  selector: 'app-data-health',
  standalone: true,
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="data-health-ribbon">
      @for (entry of entries; track entry.name) {
        <span
          class="health-dot"
          [class.dot-loaded]="entry.status === 'loaded'"
          [class.dot-loading]="entry.status === 'loading'"
          [class.dot-failed]="entry.status === 'failed'"
          [class.dot-empty]="entry.status === 'empty'"
          [title]="entry.name + ': ' + entry.status + (entry.detail ? ' - ' + entry.detail : '')"
        ></span>
      }
      @if (lastRefreshedLabel) {
        <span class="last-refreshed">{{ lastRefreshedLabel }}</span>
      }
      <button class="refresh-btn" title="Reload page" (click)="refreshAll()">&#x21bb;</button>
    </div>
  `,
  styles: [`
    .data-health-ribbon {
      display: flex; align-items: center; gap: 4px; padding: 0 8px;
    }
    .health-dot {
      width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
      transition: background 0.3s;
    }
    .dot-loaded { background: #22c55e; }
    .dot-loading { background: #eab308; animation: pulse-dot 1.2s infinite; }
    .dot-failed { background: #ef4444; }
    .dot-empty { background: #94a3b8; }
    @keyframes pulse-dot {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.4; }
    }
    .last-refreshed {
      font-size: 0.7rem;
      color: #94a3b8;
      white-space: nowrap;
      margin-left: 4px;
    }
    .refresh-btn {
      background: none; border: none; color: #94a3b8; cursor: pointer;
      font-size: 0.85rem; padding: 0 2px; line-height: 1;
      transition: color 0.2s;
    }
    .refresh-btn:hover { color: #e2e8f0; }

    :host-context(body.light-mode) .health-dot {
      width: 10px;
      height: 10px;
      border: 1px solid rgba(0, 0, 0, 0.1);
    }
    :host-context(body.light-mode) .dot-loaded { background: #16a34a; }
    :host-context(body.light-mode) .dot-loading { background: #d97706; }
    :host-context(body.light-mode) .dot-failed { background: #dc2626; }
    :host-context(body.light-mode) .dot-empty { background: #64748b; }
    :host-context(body.light-mode) .last-refreshed { color: #475569; }
    :host-context(body.light-mode) .refresh-btn { color: #64748b; }
    :host-context(body.light-mode) .refresh-btn:hover { color: #1e293b; }
  `],
})
export class DataHealthComponent implements OnInit, OnDestroy {
  entries: HealthEntry[] = [];
  lastRefreshedLabel = '';
  private lastRefreshedDate: Date | null = null;
  private labelTimer: ReturnType<typeof setInterval> | null = null;
  private subs = new Subscription();

  constructor(
    private atomicService: AtomicService,
    private sigmaService: SigmaService,
    private attackCveService: AttackCveService,
    private capecService: CapecService,
    private mispService: MispService,
    private nistMappingService: NistMappingService,
    private criProfileService: CriProfileService,
    private cloudControlsService: CloudControlsService,
    private verisService: VerisService,
    private d3fendService: D3fendService,
    private carService: CARService,
    private elasticService: ElasticService,
    private splunkContentService: SplunkContentService,
    private exploitdbService: ExploitdbService,
    private nucleiService: NucleiService,
    private dataService: DataService,
    private epssService: EpssService,
    private cveService: CveService,
    private nvdBulkService: NvdBulkService,
    private cve2capecService: Cve2CapecService,
    private pocExploitService: PocExploitService,
    private evtxSamplesService: EvtxSamplesService,
    private sentinelRulesService: SentinelRulesService,
    private anthropicSkillsService: AnthropicSkillsService,
    private threatHunterPlaybookService: ThreatHunterPlaybookService,
    private cdr: ChangeDetectorRef,
    private sources: SourceRegistryService,
  ) {}

  /**
   * The registry's verdict for a ribbon entry backed by one or more sources: 'failed'
   * (or 'empty') only when every one of them failed (or returned nothing), so an entry
   * that still has some data is not painted red.
   */
  private registryVerdict$(ids: string[]): Observable<RegistryVerdict | null> {
    return this.sources.records$.pipe(
      map(records => {
        const mine = records.filter(r => ids.includes(r.id));
        if (!mine.length) return null;
        if (mine.every(r => r.status === 'failed' || r.status === 'empty')) {
          const failed = mine.filter(r => r.status === 'failed');
          if (failed.length) {
            return { status: 'failed' as const, detail: failed.map(r => r.lastError ?? 'failed').join('; ') };
          }
          return { status: 'empty' as const, detail: 'the source returned no usable rows' };
        }
        return null;
      }),
      distinctUntilChanged((a, b) => a?.status === b?.status && a?.detail === b?.detail),
    );
  }

  ngOnInit(): void {
    // Restore persisted timestamp
    const stored = localStorage.getItem(LAST_REFRESHED_KEY);
    if (stored) {
      this.lastRefreshedDate = new Date(stored);
      this.updateLabel();
    }

    // `failed$` (optional) emits a reason when a fetch has definitively failed; the dot
    // turns red rather than pulsing "loading" forever.
    // `ids` name the SourceRegistry records behind an entry (E1.3): a loader that fails
    // no longer reports loaded, so the registry is what turns its dot red (or grey when
    // the source answered with nothing) instead of leaving it pulsing "loading".
    const sources: { name: string; loaded$: any; failed$?: Observable<string | null>; ids?: string[] }[] = [
      { name: 'Atomic Red Team', loaded$: this.atomicService.loaded$, ids: ['atomic-layer'] },
      { name: 'Sigma Rules', loaded$: this.sigmaService.loaded$, ids: ['sigmahq-coverage'] },
      { name: 'ATT&CK CVE', loaded$: this.attackCveService.loaded$, ids: ['ctid-attack-to-cve', 'ctid-kev'] },
      { name: 'CAPEC', loaded$: this.capecService.loaded$, ids: ['capec'] },
      { name: 'MISP Galaxy', loaded$: this.mispService.loaded$, ids: ['misp-galaxy'] },
      { name: 'NIST 800-53', loaded$: this.nistMappingService.loaded$, ids: ['ctid-nist-800-53'] },
      { name: 'CRI Profile', loaded$: this.criProfileService.loaded$, ids: ['ctid-cri-profile'] },
      { name: 'Cloud Controls', loaded$: this.cloudControlsService.loaded$, ids: ['ctid-aws', 'ctid-azure', 'ctid-gcp'] },
      { name: 'VERIS', loaded$: this.verisService.loaded$, ids: ['ctid-veris'] },
      { name: 'D3FEND', loaded$: this.d3fendService.loaded$, ids: ['d3fend-ontology'] },
      { name: 'CAR Analytics', loaded$: this.carService.loaded$, ids: ['car-layer'] },
      { name: 'Elastic Rules', loaded$: this.elasticService.loaded$, ids: ['elastic-tree'] },
      { name: 'Splunk Content', loaded$: this.splunkContentService.loaded$, ids: ['splunk-tree'] },
      { name: 'ExploitDB', loaded$: this.exploitdbService.loaded$, ids: ['exploitdb'] },
      { name: 'Nuclei Templates', loaded$: this.nucleiService.loaded$, ids: ['nuclei-tree'] },
      // A real availability check (E1.3), recorded on the 'epss' source; no longer a hard-coded true.
      // The check emits once and completes, so the dot also follows the registry record: a Retry
      // that succeeds on the data-health table turns it green instead of leaving it 'loading'.
      {
        name: 'EPSS',
        loaded$: merge(
          this.epssService.checkAvailability(),
          this.sources.record$('epss').pipe(map(() => this.sources.hasData('epss')), distinctUntilChanged()),
        ),
        ids: ['epss'],
      },
      // Green only for the live feed. While the dated KEV snapshot stands in for it (E1.3),
      // the dot stays red and its title names the snapshot date.
      {
        name: 'CISA KEV',
        loaded$: combineLatest([this.cveService.kevLoaded$, this.cveService.kevSnapshotDate$]).pipe(
          map(([loaded, snapshotDate]) => loaded && !snapshotDate),
        ),
        failed$: combineLatest([this.cveService.kevError$, this.cveService.kevSnapshotDate$]).pipe(
          map(([error, snapshotDate]) => (error && snapshotDate ? `${error}; using the bundled KEV snapshot of ${snapshotDate}` : error)),
        ),
      },
      { name: 'NVD Bulk', loaded$: this.nvdBulkService.loaded$, ids: ['cve-technique-map'] },
      { name: 'CVE2CAPEC', loaded$: this.cve2capecService.loaded$, ids: ['cve2capec-runtime'] },
      { name: 'PoC Exploits', loaded$: this.pocExploitService.loaded$, ids: ['trickest-poc-tree'] },
      { name: 'EVTX Samples', loaded$: this.evtxSamplesService.loaded$, ids: ['evtx-samples-tree'] },
      { name: 'Sentinel Rules', loaded$: this.sentinelRulesService.loaded$, ids: ['sentinel-attack-tree'] },
      { name: 'Anthropic Skills', loaded$: this.anthropicSkillsService.loaded$, ids: ['anthropic-skills-layer'] },
      { name: 'ThreatHunter Playbook', loaded$: this.threatHunterPlaybookService.loaded$, ids: ['threathunter-playbook'] },
    ];

    this.entries = sources.map(s => ({ name: s.name, status: 'loading' as const }));

    sources.forEach((src, i) => {
      this.subs.add(
        src.loaded$.subscribe((loaded: boolean) => {
          // A failed or empty source keeps its colour until its own verdict clears (a retry started).
          if (!loaded && (this.entries[i].status === 'failed' || this.entries[i].status === 'empty')) return;
          this.entries[i] = { name: src.name, status: loaded ? 'loaded' : 'loading' };
          if (loaded) this.markRefreshed();
          this.cdr.markForCheck();
        }),
      );
      if (src.failed$) {
        this.subs.add(
          src.failed$.subscribe(reason => {
            if (this.entries[i].status === 'loaded') return;
            this.entries[i] = reason
              ? { name: src.name, status: 'failed', detail: reason }
              : { name: src.name, status: 'loading' };
            this.cdr.markForCheck();
          }),
        );
      }
      if (src.ids) {
        this.subs.add(
          this.registryVerdict$(src.ids).subscribe(verdict => {
            if (this.entries[i].status === 'loaded') return;
            this.entries[i] = verdict
              ? { name: src.name, status: verdict.status, detail: verdict.detail }
              : { name: src.name, status: 'loading' };
            this.cdr.markForCheck();
          }),
        );
      }
    });

    // Also listen to DataService domain fetches
    this.subs.add(
      this.dataService.lastFetched$.subscribe((iso) => {
        if (iso) this.markRefreshed();
      }),
    );

    // Update relative label every 30 seconds
    this.labelTimer = setInterval(() => {
      this.updateLabel();
      this.cdr.markForCheck();
    }, 30_000);
  }

  refreshAll(): void {
    if (!confirm('This will reload the page and clear unsaved state. Continue?')) return;
    window.location.reload();
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
    if (this.labelTimer) clearInterval(this.labelTimer);
  }

  private markRefreshed(): void {
    this.lastRefreshedDate = new Date();
    localStorage.setItem(LAST_REFRESHED_KEY, this.lastRefreshedDate.toISOString());
    this.updateLabel();
  }

  private updateLabel(): void {
    if (!this.lastRefreshedDate) {
      this.lastRefreshedLabel = '';
      return;
    }
    const diffMs = Date.now() - this.lastRefreshedDate.getTime();
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHr = Math.floor(diffMin / 60);

    if (diffMin < 1) {
      this.lastRefreshedLabel = 'Last refreshed: just now';
    } else if (diffMin < 60) {
      this.lastRefreshedLabel = `Last refreshed: ${diffMin} min ago`;
    } else if (diffHr < 24) {
      const time = this.lastRefreshedDate.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
      this.lastRefreshedLabel = `Last refreshed: ${time}`;
    } else {
      const date = this.lastRefreshedDate.toLocaleDateString([], { month: 'short', day: 'numeric' });
      this.lastRefreshedLabel = `Last refreshed: ${date}`;
    }
  }
}
