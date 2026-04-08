// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
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

interface HealthEntry { name: string; status: 'loading' | 'loaded' | 'failed'; }

const LAST_REFRESHED_KEY = 'data-health-last-refreshed';

@Component({
  selector: 'app-data-health',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="data-health-ribbon">
      @for (entry of entries; track entry.name) {
        <span
          class="health-dot"
          [class.dot-loaded]="entry.status === 'loaded'"
          [class.dot-loading]="entry.status === 'loading'"
          [class.dot-failed]="entry.status === 'failed'"
          [title]="entry.name + ': ' + entry.status"
        ></span>
      }
      <span class="last-refreshed" *ngIf="lastRefreshedLabel">{{ lastRefreshedLabel }}</span>
      <button class="refresh-btn" title="Refresh All" (click)="refreshAll()">&#x21bb;</button>
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
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Restore persisted timestamp
    const stored = localStorage.getItem(LAST_REFRESHED_KEY);
    if (stored) {
      this.lastRefreshedDate = new Date(stored);
      this.updateLabel();
    }

    const sources: { name: string; loaded$: any }[] = [
      { name: 'Atomic Red Team', loaded$: this.atomicService.loaded$ },
      { name: 'Sigma Rules', loaded$: this.sigmaService.loaded$ },
      { name: 'ATT&CK CVE', loaded$: this.attackCveService.loaded$ },
      { name: 'CAPEC', loaded$: this.capecService.loaded$ },
      { name: 'MISP Galaxy', loaded$: this.mispService.loaded$ },
      { name: 'NIST 800-53', loaded$: this.nistMappingService.loaded$ },
      { name: 'CRI Profile', loaded$: this.criProfileService.loaded$ },
      { name: 'Cloud Controls', loaded$: this.cloudControlsService.loaded$ },
      { name: 'VERIS', loaded$: this.verisService.loaded$ },
      { name: 'D3FEND', loaded$: this.d3fendService.loaded$ },
      { name: 'CAR Analytics', loaded$: this.carService.loaded$ },
      { name: 'Elastic Rules', loaded$: this.elasticService.loaded$ },
      { name: 'Splunk Content', loaded$: this.splunkContentService.loaded$ },
      { name: 'ExploitDB', loaded$: this.exploitdbService.loaded$ },
      { name: 'Nuclei Templates', loaded$: this.nucleiService.loaded$ },
    ];

    this.entries = sources.map(s => ({ name: s.name, status: 'loading' as const }));

    sources.forEach((src, i) => {
      this.subs.add(
        src.loaded$.subscribe((loaded: boolean) => {
          this.entries[i] = { name: src.name, status: loaded ? 'loaded' : 'loading' };
          if (loaded) this.markRefreshed();
          this.cdr.markForCheck();
        }),
      );
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
