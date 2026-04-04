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

interface HealthEntry { name: string; status: 'loading' | 'loaded' | 'failed'; }

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
  `],
})
export class DataHealthComponent implements OnInit, OnDestroy {
  entries: HealthEntry[] = [];
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
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
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
          this.cdr.markForCheck();
        }),
      );
    });
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }
}
